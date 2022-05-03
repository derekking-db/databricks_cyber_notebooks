# Databricks notebook source
# MAGIC %md
# MAGIC ### This is a companion notebook to Blog 
# MAGIC #### 'Hunting Anomalous Connections and Infrastructure With TLS Certificates'.
# MAGIC We Invite your feedback and ideas at cybersecurity@databricks.com
# MAGIC 
# MAGIC version: 1.0 (21/12/21)

# COMMAND ----------

# MAGIC %md
# MAGIC ### How to run this notebook.
# MAGIC - Go to the clusters pull down at the top of the notebook, towards the top left corner
# MAGIC - Click on the cluster
# MAGIC - Either from the notebook menu click 'Run All', or run each cell sequentially to follow sloooowly..
# MAGIC - If you are not running the community edition, set the below flag to false.

# COMMAND ----------

# Set to False if you are NOT running the community edition
community_edition = False
if community_edition == True:
    default_dbfs_path = '/databricks/driver/data'
else:
    default_dbfs_path = 'dbfs:/FileStore/x509/datasets'

# COMMAND ----------

# MAGIC %md
# MAGIC ### Setup paths, functions and global variables.
# MAGIC - Using %run magic command allows you to abstract away details and keep notebook code tidy and easier to read. 
# MAGIC - Passing arguments makes code more generic and reusable across multiple notebooks
# MAGIC - The configuration notebook sets up paths to the raw x509.json file, sslblacklist and alexa_top1m

# COMMAND ----------

# Global Variables
databaseName = 'x509Certs'
datasource = 'x509_certs'

x509_file = default_dbfs_path + "/x509.json.gz"
blacklist_file = default_dbfs_path + "/sslblacklist.csv.gz"
top1m_file = default_dbfs_path + "/top-1m.csv.gz"


# Modules
from pyspark.sql import DataFrame, DataFrameWriter
from pyspark.sql.session import SparkSession
from pyspark.sql.functions import collect_set, countDistinct, from_json, explode, col, length, lit, current_timestamp
from pyspark.sql.types import StructType, StructField, StringType, IntegerType
import math

# Schemas
alexa_schema = StructType() \
    .add("RecordNumber",IntegerType(),True) \
    .add("alexa_top_host",StringType(),True)

# Functions
def read_batch(spark: SparkSession, rawPath: str, format: str='delta', schema: str=None) -> DataFrame:
  
  if format == 'json':
    return((spark.read.json(rawPath)))
  
  if format == 'csv':
    if schema == None:
      return((spark.read.format('csv').options(header='true', inferSchema='true').load(rawPath)))
    else:
      return((spark.read.format('csv').options(header='false').schema(schema).load(rawPath)))

def add_meta(spark: SparkSession, df: DataFrame, datasource: str) -> DataFrame:
  return (
    df.select(
      lit(datasource).alias("datasource"),
      current_timestamp().alias("ingest_time"),
      "*",
      current_timestamp().cast("date").alias("p_ingest_date")
    )
  )

def create_batch_writer(spark: SparkSession, df: DataFrame, partition_column: str=None, mode: str='append') -> DataFrameWriter:
  batch_writer = (
        df.write
        .format("delta")
        .mode(mode)

  )
  if partition_column is not None:
      return batch_writer.partitionBy(partition_column)
  else:   
      return batch_writer


# COMMAND ----------

spark.sql(f"CREATE DATABASE IF NOT EXISTS {databaseName}")
spark.sql(f"USE {databaseName}")  


# COMMAND ----------

# MAGIC %sh
# MAGIC 
# MAGIC mkdir data
# MAGIC curl -o data/sslblacklist.csv.gz https://raw.githubusercontent.com/derekking001/huntingtlscertificates/master/datasets/sslblacklist.csv.gz
# MAGIC curl -o data/top-1m.csv.gz https://raw.githubusercontent.com/derekking001/huntingtlscertificates/master/datasets/top-1m.csv.gz
# MAGIC curl -o data/x509.json.gz https://raw.githubusercontent.com/derekking001/huntingtlscertificates/master/datasets/x509.json.gz

# COMMAND ----------

dbutils.fs.cp("file:///databricks/driver/data","dbfs:/FileStore/x509/datasets/",True)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Preflight Checks
# MAGIC - Check we can see both the rawBatchPath, lookupPaths and that we see files. 

# COMMAND ----------

try:
  assert len(dbutils.fs.ls(default_dbfs_path)) > 0, "Please check dataset files have downloaded and copied to dbfs"
except AssertionError as e:
  print(e)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Build the lookup tables
# MAGIC - Alexa Top 1m Websites (used as a mechanism to filter dataset sizes down)
# MAGIC - sslblacklist - Our threat intel for certificates known to be participating in hosting malware. 

# COMMAND ----------

# Alexa-Top1m
rawTop1mDF = read_batch(spark, top1m_file, format='csv', schema=alexa_schema)
display(rawTop1mDF)

# COMMAND ----------

# Write to Bronze Table
alexaTop1mBronzeWriter = create_batch_writer(spark=spark, df=rawTop1mDF, mode='overwrite')
alexaTop1mBronzeWriter.saveAsTable(databaseName + ".alexaTop1m_bronze")

# COMMAND ----------

# Make Transformations to Top1m
bronzeTop1mDF = spark.table(databaseName + ".alexaTop1m_bronze")
bronzeTop1mDF = bronzeTop1mDF.filter(~bronzeTop1mDF.alexa_top_host.rlike('localhost')).drop("RecordNumber")
display(bronzeTop1mDF)

# COMMAND ----------

# Write to Silver Table
alexaTop1mSilverWriter = create_batch_writer(spark=spark, df=bronzeTop1mDF, mode='overwrite')
alexaTop1mSilverWriter.saveAsTable(databaseName + ".alexaTop1m_silver")

# COMMAND ----------

# SSLBlacklist
rawBlackListDF = read_batch(spark, blacklist_file, format='csv')
rawBlackListDF = rawBlackListDF.withColumnRenamed("# Listingdate",'listingDate')
display(rawBlackListDF)

# COMMAND ----------

# Write to Bronze Table
sslBlBronzeWriter = create_batch_writer(spark=spark, df=rawBlackListDF, mode='overwrite')
sslBlBronzeWriter.saveAsTable(databaseName + ".sslBlacklist_bronze")

# COMMAND ----------

# Make Transformations to the SSLBlacklist
bronzeBlackListDF = spark.table(databaseName + ".sslBlackList_bronze")
bronzeBlackListDF = bronzeBlackListDF.select(*(col(x).alias('sslbl_' + x) for x in bronzeBlackListDF.columns))
display(bronzeBlackListDF)

# COMMAND ----------

# Write to Silver Table
BlackListSilverWriter = create_batch_writer(spark=spark, df=bronzeBlackListDF, mode='overwrite')
BlackListSilverWriter.saveAsTable(databaseName + ".sslBlackList_silver")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Ingest the X.509 Certificates

# COMMAND ----------

rawX509DF = read_batch(spark=spark, rawPath=x509_file, format='json')
rawX509DF = add_meta(spark=spark, df=rawX509DF, datasource=datasource)
display(rawX509DF)

# COMMAND ----------

# Write to Bronze Table
x509BronzeWriter = create_batch_writer(spark=spark, df=rawX509DF, mode='overwrite')
x509BronzeWriter.saveAsTable(databaseName + ".x509_bronze")

# COMMAND ----------

# Make Transformations to the X509 Table
bronzeX509DF = spark.table(databaseName + ".x509_bronze")
display(bronzeX509DF.select( "subject", "issuer", "dest_ip", "not_valid_before", "sha1_fingerprint"  ))

# COMMAND ----------

# MAGIC %md
# MAGIC ### Enrich the x509 certificate data with the SSLblacklist table

# COMMAND ----------

# Read Blacklist
silverBlackListDF = spark.table(databaseName + ".sslBlackList_silver")

# COMMAND ----------

silverX509DF = bronzeX509DF.join(silverBlackListDF, bronzeX509DF.sha1_fingerprint == silverBlackListDF.sslbl_SHA1, how='left')
display(silverX509DF)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Enrich the x509 certificate data with AlexaTop1m table

# COMMAND ----------

# Read Alexa Table
silverAlexaTop1mDF = spark.table(databaseName + ".alexaTop1m_silver")

# COMMAND ----------

x509Table = silverX509DF.alias('x509Table')
alexaTable = silverAlexaTop1mDF.alias('alexaTable')
silverX509DF = x509Table.join(alexaTable, x509Table.common_name == alexaTable.alexa_top_host, how='left')
display(silverX509DF)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Remove any certs in the alexaTop1m
# MAGIC - drop the alexa fields

# COMMAND ----------

silverX509DF = silverX509DF.filter(silverX509DF.alexa_top_host.isNull()).drop('alexa_top_host')
display(silverX509DF)

# COMMAND ----------

# MAGIC %md 
# MAGIC ### Transforms and write to silver table

# COMMAND ----------

# Write to Silver Table
x509SilverWriter = create_batch_writer(spark=spark, df=silverX509DF, mode='overwrite')
x509SilverWriter.saveAsTable(databaseName + ".x509_silver")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Look for certificates that may be of interest
# MAGIC - Unique values in common_name and issuer fields
# MAGIC - Hits against SSLBlacklist
# MAGIC - Entropy

# COMMAND ----------

# Unique Entries
silverX509DF = spark.table(databaseName + ".x509_silver")

uniqueNameDF = silverX509DF.groupby('issuer').agg(collect_set('subject').alias('subject'), 
            collect_set('common_name').alias('common_name'), collect_set('rdns').alias('rdns'), 
            collect_set('sha1_fingerprint').alias('sha1_fingerprint'), collect_set('src_ip').alias('src_ip'), 
            collect_set('dest_ip').alias('dest_ip'), 
            countDistinct('issuer').alias('count')).orderBy('count').where(col('count') == 1)

display(uniqueNameDF)

# COMMAND ----------

# MAGIC %md 
# MAGIC ### Certificates with short issuer fields
# MAGIC - Top hit on subject (unique string - and its the shortest)

# COMMAND ----------

shortSubjectDF = silverX509DF.select("common_name","subject","issuer","subject_alternative_names","sha1_fingerprint") \
    .withColumn('length',length(col("issuer"))).orderBy('length') \
    .where((length(col("issuer")) < 15) & (col('issuer') != '<Name()>') & (col('common_name') != 'apiserver'))
      
display(shortSubjectDF)

# COMMAND ----------

# SSLBlacklist
isSSLBlackListedDF = silverX509DF.select(
      "sslbl_Listingreason","common_name", "country", "dest_ip","rdns","issuer", 
      "sha1_fingerprint", "not_valid_before", "not_valid_after" 
      ).filter(silverX509DF.sslbl_SHA1 != 'null')
display(isSSLBlackListedDF)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Lets try looking at shannon entropy on the common_name

# COMMAND ----------


def entropy(string):
        "Calculates the Shannon entropy of a string"
        try:
          # get probability of chars in string
          prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

          # calculate the entropy
          entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
        except Exception as e:
          print(e)
          entropy = -1

        return entropy

entropy_udf = udf(entropy, StringType())

entropyDF = silverX509DF.where(length(col("subject")) < 15).select(
    "common_name","subject","issuer","subject_alternative_names","sha1_fingerprint"
    ).withColumn("entropy_score", entropy_udf(col('common_name'))).orderBy(col("entropy_score").desc()).where(col('entropy_score') > 1.5)

display(entropyDF)
