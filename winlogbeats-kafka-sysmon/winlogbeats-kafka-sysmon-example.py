# Databricks notebook source
# MAGIC %md
# MAGIC # Databricks Winlogbeats -> Kafka -> Sysmon Example
# MAGIC 
# MAGIC | Detail | Information |
# MAGIC |--------|-------------|
# MAGIC |**Created By** | Derek King (cybersecurity@databricks.com)|
# MAGIC |**Ingest Connector**|Kafka|
# MAGIC |**Kafka Topic**|winlogbeat|
# MAGIC |**Input(s)**|Winlogbeats<ul><li>WinEventLog:Application</li><li>WinEventLog:System</li><li>WinEventLog:Security</li><li>Microsoft-Windows-WMI-Activity/Operational</li><li>Microsoft-Windows-Sysmon/Operational</li><li>Windows Powershell</li></ul>|
# MAGIC |**Extracts**| Microsoft-Windows-Sysmon/Operational<br><br>Others left for the interested reader|
# MAGIC |**Sample Records Link**|<a><href="#">No Link</a>|
# MAGIC 
# MAGIC ## History
# MAGIC | Date | Version | Developed By | Reason |
# MAGIC |------|---------|--------------|--------|
# MAGIC |30-Jan-2022|v0.1 - DRAFT| Derek King|Sample extraction of Windows Event Logs|

# COMMAND ----------

# MAGIC %md ### Setup Notebook Vars

# COMMAND ----------

optimizeInline = False  # Used for example purposes - Probably want to schedule hours jobs for optimization tasks
streamMode = 'batch' # batch OR streaming
bootstrapServerAddr = "10.0.253.218"

# COMMAND ----------

# MAGIC %md ### Functions & Modules

# COMMAND ----------

from pyspark.sql.types import *
from pyspark.sql.functions import expr, col, from_json, lit, current_timestamp, array_remove
from pyspark.sql.functions import *
from pyspark.sql import DataFrame
import json, re
from pyspark.sql import functions as F

def read_kafka_topic(bootstrapServers: str, port: int, topic: str, startOffset: str="earliest", endingOffset: str="latest", corruptRecords: bool=False):
    bootstrapServers = bootstrapServers
    port = port
    topic = topic
    startOffset = startOffset
    endingOffset = endingOffset
    corruptRecords = corruptRecords
    
    try:
        raw = (spark.read
          .format("kafka")
          .option("kafka.bootstrap.servers", bootstrapServers+':'+port)
          .option("subscribe", topic)
          .option("startingOffsets", startOffset)
          .option("failOnDataLoss", "false")
          .load()
          # filter out empty values
          .withColumn("value", expr("string(value)"))
          .filter(col("value").isNotNull())
          )
        
        raw_df = raw.withColumn("_raw", col("value"))
        raw_df = spark.read.json(raw_df.rdd.map(lambda x: x.value), multiLine=True)
        
        # Drop Corrupt Records
        if corruptRecords:
            raw_df = drop_corrupt_kafka_records(raw_df)
    
        # Schema as StructType
        topic_schema = read_kafka_topic_schema(raw_df)
        
        return raw_df, topic_schema
    
    except Exception as e:
        return('read_kafka_topic Error: ', e)
    
def drop_corrupt_kafka_records(df: DataFrame) -> DataFrame:
    df = df
    if "_corrupt_record" in df.columns:
        df = (df
          .filter(col("_corrupt_record").isNotNull())
          .drop("_corrupt_record"))
    return df

def read_kafka_topic_schema(df:DataFrame) -> DataFrame:
    df = df
    json_schema = df.schema.json()
    obj = json.loads(json_schema)
    schema = StructType.fromJson(obj)
    return schema

def add_ingest_meta(df: DataFrame) -> DataFrame:
    return(df.select(
      current_timestamp().alias("_ingest_time"),
      "*")
    )

# Compliments of https://stackoverflow.com/questions/38753898/how-to-flatten-a-struct-in-a-spark-dataframe
def flatten_df(nested_df):
    stack = [((), nested_df)]
    columns = []

    while len(stack) > 0:
        parents, df = stack.pop()

        flat_cols = [
            col(".".join(parents + (c[0],))).alias(":".join(parents + (c[0],)))
            for c in df.dtypes
            if c[1][:6] != "struct"
        ]

        nested_cols = [
            c[0]
            for c in df.dtypes
            if c[1][:6] == "struct"
        ]

        columns.extend(flat_cols)

        for nested_col in nested_cols:
            projected_df = df.select(nested_col + ".*")
            stack.append((parents + (nested_col,), projected_df))

    return nested_df.select(columns)

def write_table(df: DataFrame, tableName, table: str, partitions: list, streamType:str='batch') -> bool:
        tableName = tableName
        table = table
        dataFrame = df
        streamType = streamType
        partitions = partitions

        if table not in ('bronze','silver', 'gold'):
            return("Incorrect Args passed to write_table function")
        
        # Bronze Behaviours
        if table == 'bronze':
            spark.sql("SET delta.dataSkippingNumIndexedCols=5")

        if streamType == 'batch':
            return(dataFrame.write.format("delta")
                       .option("mergeSchema", "true")
                       .mode("append")
                       .partitionBy(*partitions)
                       .saveAsTable(tableName)
            )

        if streamType == 'streaming':
            return(dataFrame.writeStream.format("delta")
                        .option("mergeSchema", "true")
                        .outputMode("append")
                        .option("checkpointLocation", '/tmp/events/_checkpoints/kafka1')
                        .partitionBy(*partitions)
                        .toTable(tableName)
                        .start()
            )
        
def read_table(tableName: str) -> DataFrame:
    return(spark.read.table(tableName))

def parser_kafka_winlogbeat(df: DataFrame, stage: str=None) -> DataFrame:
    df = df
    if stage == 'raw':
        df = df.select(col("winlog.channel").alias("_sourcetype"), col("`@timestamp`").alias("_event_time"), col("`@timestamp`").cast("date").alias("_event_date"), col("agent.hostname").alias("dvc_hostname"), "*")
        return df
    else:
        # Parser behaviours
        _df2 = df.select("*", split(df.message, "\n").alias("message_split")).drop("message").withColumnRenamed("message_split", "message")
        # Flatten entire DataFrame maintaining parent col name
        return(flatten_df(_df2))

def cim_cols(df: DataFrame, columns: list, action: str) -> DataFrame:
    df = df
    columns = columns
    cols = []
    for column in columns:
        if action == 'rename':
            df = df.withColumnRenamed(column[0],column[1])
            cols.append(column[1])
        if action == 'new_literals':
            df = df.withColumn(column[0], lit(column[1]))
            cols.append(column[0])
        if action == 'new_expressions':
            cols.append(column[0])
    if action == 'new_expressions':
        df = df.select("*", *[F.expr(x[1]).alias(x[0]) for x in columns])
    return df,cols

def create_missing_cols(df: DataFrame, columns: list) -> DataFrame:
    df = df
    columns = columns
    for col in columns:
        if not col[0] in df.columns:
            df = df.withColumn(col[0], lit('null'))
    
    return df
  
def cim_dataframe(df: DataFrame, transforms: list) -> DataFrame:
    df = df
    transform_cols = transforms
    
    new_expressions,new_literals, renames = [],[],[]
    for transform in transform_cols:
        x = transform.items()
        for k, v in x:
            column, value = v[0], v[1]
            if k == 'new':
                if re.search("^EXPR(\s)?=", value):
                    new_expressions.append([column,value[5:]])
                elif re.search("^LITERAL(\s)?=", value):
                    new_literals.append([column,value[8:]])
            if k == 'rename':
                renames.append([column,value])
            
    df = create_missing_cols(df, renames) 
    
    df, cols = cim_cols(df, new_literals, 'new_literals')
    
    df, renamed_cols = cim_cols(df, renames, 'rename')
    cols.extend(renamed_cols)
    
    df, derived_cols = cim_cols(df, new_expressions, 'new_expressions')
    cols.extend(derived_cols)
    cols.sort()
    
    return(df.select(*cols))
  
def create_bloom_filter(tableName:str, columns:list):
    cols = ",".join(columns)
    query = f"CREATE BLOOMFILTER INDEX ON TABLE {tableName} FOR COLUMNS({cols} OPTIONS (fpp=0.1, numItems=500000000))"
    spark.sql(query)
    return
    
def optimize_table(tableName:str, columns: list):
    cols = ",".join(columns)
    query = f"OPTIMIZE {tableName} ZORDER BY {cols}"
    spark.sql(query)
    return

# COMMAND ----------

# MAGIC %md ### Sample Config Files

# COMMAND ----------

# MAGIC %md
# MAGIC ** Winlogbeat Configuration file **
# MAGIC 
# MAGIC Sample winlogbeat.yml file
# MAGIC 
# MAGIC Reference(s): https://www.elastic.co/guide/en/beats/winlogbeat/master/kafka-output.html
# MAGIC 
# MAGIC     #-------------------------- Windows Logs To Collect -----------------------------
# MAGIC     winlogbeat.event_logs:
# MAGIC       - name: Application
# MAGIC       - name: Security
# MAGIC       - name: System
# MAGIC       - name: Microsoft-windows-sysmon/operational
# MAGIC       - name: Microsoft-windows-PowerShell/Operational 
# MAGIC         event_id: 4103, 4104
# MAGIC       - name: Windows PowerShell
# MAGIC         event_id: 400,600
# MAGIC       - name: Microsoft-Windows-WMI-Activity/Operational
# MAGIC         event_id: 5857,5858,5859,5860,5861
# MAGIC 
# MAGIC     #----------------------------- Kafka output --------------------------------
# MAGIC     output.kafka:
# MAGIC       hosts: [34.215.129.45:9094"]
# MAGIC       topic: "winlogbeat"
# MAGIC       partition.random:
# MAGIC         reachable_only: false
# MAGIC       max_message_bytes: 1000000
# MAGIC       max_retries: 3
# MAGIC       required_acks: 1

# COMMAND ----------

# MAGIC %md
# MAGIC #### Kafka Server Creation
# MAGIC If you do not have a kafka server, you can spin one up on using <a href="https://github.com/DerekKing001/kafka-in-docker" target="_blank">this repository</a>.
# MAGIC 
# MAGIC **Notes**
# MAGIC 
# MAGIC * This should be used ONLY for testing purposes. It is configured to run well in AWS (uses metadata service for hostname configuration etc), but can be adapted to your environment.
# MAGIC * It will create the winlogbeat topic and listen externally on port 9094 for incoming messages. 
# MAGIC * Remember to configure your security groups if you bring this up in the cloud.
# MAGIC * This notebook should have access to the internal IP to retrieve messages. 

# COMMAND ----------

# MAGIC %md ## Extract 
# MAGIC |Actions|Detail|
# MAGIC |-------|------|
# MAGIC |Read from Kafka|Topic winlogbeat|
# MAGIC |Add meta| Includes meta data|
# MAGIC |Write|Bronze table - Partitioned By<ul><li>_event_date</li><li>_sourcetype</li></ul>|

# COMMAND ----------

winlogbeatDF, winlogbeatSchema = read_kafka_topic(bootstrapServers=bootstrapServerAddr, port="9094", topic="winlogbeat")
if type(winlogbeatDF) == DataFrame:
    winlogbeatDF = add_ingest_meta(winlogbeatDF)
    winlogbeatDF = parser_kafka_winlogbeat(winlogbeatDF, stage='raw')
    display(winlogbeatDF)
else:
    print(winlogbeatDF, winlogbeatSchema)

# COMMAND ----------

# MAGIC %md ### Write to Bronze

# COMMAND ----------

partitions = ["_event_date", "_sourcetype"]
write_table(df=winlogbeatDF, tableName='winlogbeat_kafka_bronze', table='bronze', partitions=partitions, streamType=streamMode)

# COMMAND ----------

display(spark.sql("SHOW PARTITIONS winlogbeat_kafka_bronze"))

# COMMAND ----------

# MAGIC %md ### Read Bronze back, and Cache

# COMMAND ----------

bronzeWinlogbeatDF = read_table('winlogbeat_kafka_bronze').cache()
display(bronzeWinlogbeatDF)

# COMMAND ----------

# MAGIC %md ## Transforms
# MAGIC |Transforms|EventId|DataFrame|Delta TableName|
# MAGIC |----------|-------|---------|---------------|
# MAGIC |Processes|1,5,18|sysmonProcess|default.Process|
# MAGIC |Registry|12,13,14|sysmonRegistry|default.Registry|
# MAGIC |Service|4|sysmonService|default.Service|
# MAGIC |File|11,23|sysmonFile|default.File|
# MAGIC |Network|3|sysmonNetwork|default.Network|
# MAGIC |WMI|19,20,21|sysmonWMI|default.WMI|

# COMMAND ----------

# MAGIC %md ### Extract & Flatten Bronze/Raw Dataframe

# COMMAND ----------

bronzeWinlogbeatDF = parser_kafka_winlogbeat(bronzeWinlogbeatDF)
display(bronzeWinlogbeatDF)

# COMMAND ----------

# MAGIC %md ### Sysmon Process Events

# COMMAND ----------

sysmonProcessDF = bronzeWinlogbeatDF.filter((bronzeWinlogbeatDF._sourcetype == 'Microsoft-Windows-Sysmon/Operational') 
                  & ( (col("winlog:event_id") == '1') 
                  | (col("winlog:event_id") == '5') 
                  | (col("winlog:event_id") == '18') ))

# COMMAND ----------

transform_cols = [
    {"new":["event_message","EXPR=case when (event_id = 1) then 'Process Started' when (event_id = 5) then 'Process Terminated' when (event_id = 18) then 'Pipe Connected' end"]},
    {"new":["event_message_result","LITERAL=success"]},
    {"new":["event_schema_version","LITERAL=1.0"]},
    {"new":["event_schema_file","LITERAL=winlogbeat-sysmon"]},
    {"new":["event_result","LITERAL=success"]},
    {"rename":["_sourcetype","_sourcetype"]},
    {"rename":["_event_time","_event_time"]},
    {"rename":["_event_date","_event_date"]},
    {"rename":["dvc_hostname","dvc_hostname"]},
    {"rename":["winlog:event_id","event_id"]},
    {"rename":["winlog:task","event_category_type"]},
    {"rename":["log:level","event_severity"]},
    {"rename":["event:action","event_status"]},
    {"rename":["winlog:event_data:CommandLine","process_command_line"]},
    {"rename":["winlog:event_data:Company","file_company"]},
    {"rename":["winlog:event_data:CurrentDirectory","process_file_directory"]},
    {"rename":["winlog:event_data:Description","file_description"]},
    {"rename":["winlog:event_data:Image","process_file_path"]},
    {"rename":["winlog:event_data:IntegrityLevel","process_integrity_level"]},
    {"rename":["winlog:event_data:LogonGuid","user_logon_guid"]},
    {"rename":["winlog:event_data:LogonId","user_logon_id"]},
    {"rename":["winlog:event_data:OriginalFileName","file_name_original"]},
    {"rename":["winlog:event_data:ParentCommandLine","process_parent_command_line"]},
    {"rename":["winlog:event_data:ParentImage","process_parent_file_path"]},
    {"rename":["winlog:event_data:ParentProcessGuid","process_parent_guid"]},
    {"rename":["winlog:event_data:ParentProcessId","process_parent_id"]},
    {"rename":["winlog:event_data:ParentUser","acting_user_name"]},
    {"rename":["winlog:event_data:ProcessId","process_id"]},
    {"rename":["winlog:event_data:ProcessName","process_name"]},
    {"rename":["winlog:event_data:Product","file_product"]},
    {"rename":["winlog:event_data:TerminalSessionId","user_session_id"]},
    {"rename":["winlog:event_data:User","user_name"]},
    {"rename":["winlog:event_data:FileVersion","file_version"]},
    {"rename":["winlog:event_data:ProcessGuid","process_guid"]},
    {"rename":["winlog:event_data:Hashes","file_hashes"]},
    {"rename":["winlog:event_data:PipeName","pipe_name"]}
]

bloom_cols = ["user_name"]
z_order_cols = ["process_name", "event_id"]
partition_cols = ["_event_date"]
   
try:
    sysmonProcess = cim_dataframe(sysmonProcessDF, transform_cols)
except NameError:
    raise
    
write_table(df=sysmonProcess,partitions=partition_cols, tableName='Process', table='silver', streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='Process', columns=bloom_cols)
    optimize_table(tableName='Process', columns=z_order_cols)

display(sysmonProcess)

# COMMAND ----------

# MAGIC %md ### Sysmon Registry Events

# COMMAND ----------

sysmonRegistryDF = bronzeWinlogbeatDF.filter((bronzeWinlogbeatDF._sourcetype == 'Microsoft-Windows-Sysmon/Operational') 
                                             & ( (col("winlog:event_id") == '12') | (col("winlog:event_id") == '13') | (col("winlog:event_id") == '14')    ) )

# COMMAND ----------

transform_cols = [
{"new":["event_schema_version","LITERAL=1.0"]},
{"new":["event_schema_file","LITERAL=winlogbeat-sysmon"]},
{"new":["event_message","EXPR=case when (event_id = 12) then 'RegistryKey Create/Delete' when (event_id = 13) then 'Registry Value Set' when (event_id = 14) then 'Registry Key and Value Rename' end"]},
{"new":["event_result","LITERAL=success"]},
{"rename":["_sourcetype","_sourcetype"]},
{"rename":["_event_time","_event_time"]},
{"rename":["_event_date","_event_date"]},
{"rename":["dvc_hostname","dvc_hostname"]},
{"rename":["winlog:event_id","event_id"]},
{"rename":["winlog:task","event_category_type"]},
{"rename":["log:level","event_severity"]},
{"rename":["event:action","event_status"]},
{"rename":["winlog:event_data:EventType","event_type"]},
{"rename":["winlog:event_data:ProcessGuid","process_guid"]},
{"rename":["winlog:event_data:ProcessId","process_id"]},
{"rename":["winlog:event_data:Image","process_file_path"]},
{"rename":["winlog:event_data:TargetObject","registry_path"]},
{"rename":["winlog:event_data:Details","registry_value"]},
{"rename":["winlog:event_data:NewName","registry_key_new_name"]}
]

bloom_cols = ["registry_path"]
z_order_cols = ["dvc_hostname", "event_id"]
partition_cols = ["_event_date"]

try:
    sysmonRegistry = cim_dataframe(sysmonRegistryDF, transform_cols)
except NameError:
    pass
  
write_table(df=sysmonRegistry,partitions=partition_cols, tableName='Registry', table='silver', streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='Registry', columns=bloom_cols)
    optimize_table(tableName='Registry', columns=z_order_cols)


display(sysmonRegistry)

# COMMAND ----------

# MAGIC %md ### Sysmon Service Events

# COMMAND ----------

sysmonServiceDF = bronzeWinlogbeatDF.filter((bronzeWinlogbeatDF._sourcetype == 'Microsoft-Windows-Sysmon/Operational') 
                                            & ( (col("winlog:event_id") == '4')  ) )

# COMMAND ----------

transform_cols = [
{"new":["event_schema_version","LITERAL=1.0"]},
{"new":["event_schema_file","LITERAL=winlogbeat-sysmon"]},
{"new":["event_message","LITERAL=Service State Changed"]},
{"new":["event_result","LITERAL=success"]},
{"rename":["_sourcetype","_sourcetype"]},
{"rename":["_event_time","_event_time"]},
{"rename":["_event_date","_event_date"]},
{"rename":["dvc_hostname","dvc_hostname"]},
{"rename":["winlog:event_id","event_id"]},
{"rename":["winlog:task","event_category_type"]},
{"rename":["log:level","event_severity"]},
{"rename":["event:action","event_status"]},
{"rename":["winlog:event_data:State","service_state"]},
{"rename":["winlog:event_data:Version","file_version"]},
{"rename":["winlog:process:pid","process_pid"]},   
]

bloom_cols = ["_sourcetype", "service_state"]
z_order_cols = ["dvc_hostname", "event_id"]
partition_cols = ["_event_date"]
try:
    sysmonService = cim_dataframe(sysmonServiceDF, transform_cols)
except NameError:
    pass
  
write_table(df=sysmonService,partitions=partition_cols, tableName='Service', table='silver',streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='Service', columns=bloom_cols)
    optimize_table(tableName='Service', columns=z_order_cols)

display(sysmonService)

# COMMAND ----------

# MAGIC %md ### Sysmon File Events

# COMMAND ----------

sysmonFileDF = bronzeWinlogbeatDF.filter((bronzeWinlogbeatDF._sourcetype == 'Microsoft-Windows-Sysmon/Operational') 
                                         & ( (col("winlog:event_id") == '11') | (col("winlog:event_id") == '23') ) )

# COMMAND ----------

transform_cols = [
{"new":["event_schema_version","LITERAL=1.0"]},
{"new":["event_schema_file","LITERAL=winlogbeat-sysmon"]},
{"new":["event_message","LITERAL="]},
{"new":["event_result","LITERAL=success"]},
{"rename":["_sourcetype","_sourcetype"]},
{"rename":["_event_time","_event_time"]},
{"rename":["_event_date","_event_date"]},
{"rename":["dvc_hostname","dvc_hostname"]},
{"rename":["winlog:event_id","event_id"]},
{"rename":["winlog:task","event_category_type"]},
{"rename":["log:level","event_severity"]},
{"rename":["event:action","event_status"]},
{"rename":["winlog:event_data:ProcessGuid","process_guid"]},
{"rename":["winlog:event_data:ProcessId","process_id"]},
{"rename":["winlog:event_data:Image","process_file_path"]},
{"rename":["winlog:event_data:TargetFilename","file_name"]},
{"rename":["winlog:event_data:CreationUtcTime","file_creation_time"]},
{"rename":["winlog:event_data:User","user_name"]},
{"rename":["winlog:event_data:Hashes","file_hashes"]},
{"rename":["winlog:event_data:IsExecutable","file_is_exe"]},
{"rename":["winlog:event_data:Archived","file_archived"]}
]

bloom_cols = ["_sourcetype", "file_name"]
z_order_cols = ["dvc_hostname", "event_id"]
partition_cols = ["_event_date"]

try:
    sysmonFile = cim_dataframe(sysmonFileDF, transform_cols)
except NameError:
    pass
  
write_table(df=sysmonFile,partitions=partition_cols, tableName='File', table='silver', streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='File', columns=bloom_cols)
    optimize_table(tableName='File', columns=z_order_cols)
    
display(sysmonFile)

# COMMAND ----------

# MAGIC %md ### Sysmon Network Connection Events

# COMMAND ----------

sysmonNetworkDF = bronzeWinlogbeatDF.filter((bronzeWinlogbeatDF._sourcetype == 'Microsoft-Windows-Sysmon/Operational') 
                                            & ( (col("winlog:event_id") == '3')  ) )

# COMMAND ----------

transform_cols = [
{"new":["event_schema_version","LITERAL=1.0"]},
{"new":["event_schema_file","LITERAL=winlogbeat-sysmon"]},
{"new":["event_message","Network Connection"]},
{"new":["event_result","LITERAL=success"]},
{"rename":["_sourcetype","_sourcetype"]},
{"rename":["_event_time","_event_time"]},
{"rename":["_event_date","_event_date"]},
{"rename":["dvc_hostname","dvc_hostname"]},
{"rename":["winlog:event_id","event_id"]},
{"rename":["winlog:task","event_category_type"]},
{"rename":["log:level","event_severity"]},
{"rename":["event:action","event_status"]},
{"rename":["winlog:event_data:ProcessGuid","process_guid"]},
{"rename":["winlog:event_data:ProcessId","process_id"]},
{"rename":["winlog:event_data:Image","process_file_path"]},
{"rename":["winlog:event_data:User","user_name"]},
{"rename":["winlog:event_data:Protocol","network_protocol"]},
{"rename":["winlog:event_data:Initiated","network_initiated"]},
{"rename":["winlog:event_data:SourceIsIpv6","src_ip_is_ipv6"]},
{"rename":["winlog:event_data:SourceIp","src_ip_addr"]},
{"rename":["winlog:event_data:SourceHostname","src_dvc_hostname"]},
{"rename":["winlog:event_data:SourcePort","src_port_number"]},
{"rename":["winlog:event_data:DestinationIsIpv6","dst_ip_is_ipv6"]},
{"rename":["winlog:event_data:DestinationIp","dst_ip_addr"]},
{"rename":["winlog:event_data:DestinationHostname","dst_dvc_hostname"]},
{"rename":["winlog:event_data:DestinationPort","dst_port_number"]},
{"rename":["winlog:event_data:DestinationPortName","dst_port_name"]}
]

bloom_cols = ["_sourcetype", "dst_ip_addr", "src_ip_addr"]
z_order_cols = ["dvc_hostname", "event_id"]
partition_cols = ["_event_date"]

try:
    sysmonNetwork = cim_dataframe(sysmonNetworkDF, transform_cols)
except NameError:
    pass

write_table(df=sysmonNetwork,partitions=partition_cols, tableName='Network', table='silver', streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='Network', columns=bloom_cols)
    optimize_table(tableName='Network', columns=z_order_cols)

display(sysmonNetwork)

# COMMAND ----------

# MAGIC %md ### Sysmon DNS Events

# COMMAND ----------

sysmonDNSDF = bronzeWinlogbeatDF.filter((bronzeWinlogbeatDF._sourcetype == 'Microsoft-Windows-Sysmon/Operational') 
                                        & ( (col("winlog:event_id") == '22')  ) )

# COMMAND ----------

transform_cols = [
{"new":["event_schema_version","LITERAL=1.0"]},
{"new":["event_schema_file","LITERAL=winlogbeat-sysmon"]},
{"new":["event_message","LITERAL=DNS"]},
{"new":["event_result","LITERAL=success"]},
{"rename":["_sourcetype","_sourcetype"]},
{"rename":["_event_time","_event_time"]},
{"rename":["_event_date","_event_date"]},
{"rename":["dvc_hostname","dvc_hostname"]},
{"rename":["winlog:event_id","event_id"]},
{"rename":["winlog:task","event_category_type"]},
{"rename":["log:level","event_severity"]},
{"rename":["event:action","event_status"]},
{"rename":["winlog:event_data:ProcessGuid","process_guid"]},
{"rename":["winlog:event_data:ProcessId","process_id"]},
{"rename":["winlog:event_data:QueryName","dst_host_name"]},
{"rename":["winlog:event_data:QueryStatus","dns_response_code"]},
{"rename":["winlog:event_data:QueryResults","dns_response_name"]},
{"rename":["winlog:event_data:Image","process_file_path"]}
]

bloom_cols = ["_sourcetype", "dst_host_name", "dns_response_name"]
z_order_cols = ["dvc_hostname", "event_id"]
partition_cols = ["_event_date"]

try:
    sysmonDNS = cim_dataframe(sysmonDNSDF, transform_cols)
except NameError:
    pass

write_table(df=sysmonDNS,partitions=partition_cols, tableName='DNS', table='silver', streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='DNS', columns=bloom_cols)
    optimize_table(tableName='DNS', columns=z_order_cols)

display(sysmonDNS)

# COMMAND ----------

# MAGIC %md ### Sysmon WMI Events

# COMMAND ----------

sysmonWMIDF = bronzeWinlogbeatDF.filter((bronzeWinlogbeatDF._sourcetype == 'Microsoft-Windows-Sysmon/Operational') 
                                        & ( (col("winlog:event_id") == '19') | (col("winlog:event_id") == '20') | (col("winlog:event_id") == '21')  ) )

# COMMAND ----------

transform_cols = [
{"new":["event_schema_version","LITERAL=1.0"]},
{"new":["event_schema_file","LITERAL=winlogbeat-sysmon"]},
{"new":["event_message","EXPR=case when (event_id = 19) then 'WmiEventFilter activity detected' when (event_id = 20) then 'WmiEventConsumer activity detected' when (event_id = 21) then 'WmiEventConsumerToFilter activity detected' end"]},
{"new":["event_result","LITERAL=success"]},
{"rename":["_sourcetype","_sourcetype"]},
{"rename":["_event_time","_event_time"]},
{"rename":["_event_date","_event_date"]},
{"rename":["dvc_hostname","dvc_hostname"]},
{"rename":["winlog:event_id","event_id"]},
{"rename":["winlog:task","event_category_type"]},
{"rename":["log:level","event_severity"]},
{"rename":["event:action","event_status"]},
{"rename":["winlog:event_data:Operation","wmi_operation"]},
{"rename":["winlog:event_data:User","user_name"]},
{"rename":["winlog:event_data:EventNamespace","wmi_namespace"]},
{"rename":["winlog:event_data:Name","wmi_filter_name"]},
{"rename":["winlog:event_data:Query","wmi_query"]},
{"rename":["winlog:event_data:ConsumerName","wmi_consumer_name"]},
{"rename":["winlog:event_data:Type","wmi_consumer_type"]},
{"rename":["winlog:event_data:Destination","wmi_consumer_destination"]},
{"rename":["winlog:event_data:Consumer","wmi_consumer_path"]},
{"rename":["winlog:event_data:Filter","wmi_filter_path"]}
]

bloom_cols = ["_sourcetype", "wmi_operation"]
z_order_cols = ["dvc_hostname", "event_id"]
partition_cols = ["_event_date"]

try:
    sysmonWMI = cim_dataframe(sysmonWMIDF,transform_cols)
except (NameError):
    pass

write_table(df=sysmonWMI,partitions=partition_cols, tableName='WMI', table='silver', streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='WMI', columns=bloom_cols)
    optimize_table(tableName='WMI', columns=z_order_cols)

display(sysmonWMI)

# COMMAND ----------

# MAGIC %md ### Entire Silver Table

# COMMAND ----------

partitions_cols = ["_event_date"]
bloom_cols = ["_sourcetype"]
z_order_cols = ["event_id"]

sysmonSilver = bronzeWinlogbeatDF.withColumnRenamed('dvc:hostname', 'dvc_hostname').withColumnRenamed('winlog:event_id', 'event_id')

write_table(df=sysmonSilver,partitions=partition_cols, tableName='winlogbeat_kafka_all_silver', table='silver', streamType=streamMode)
if optimizeInline:
    create_bloom_filter(tableName='winlogbeat_kafka_all_silver', columns=bloom_cols)
    optimize_table(tableName='winlogbeat_kafka_all_silver', columns=z_order_cols)

display(read_table('winlogbeat_kafka_all_silver'))

# COMMAND ----------


