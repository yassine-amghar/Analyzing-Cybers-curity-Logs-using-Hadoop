"""
Spark Analysis Script #3: Web Server Log Analysis & SQL Injection Detection
Analyzes web server logs to identify SQL injection and web attacks

Author: [Your Name]
Date: December 2025
"""

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, regexp_extract, when, lower
from pyspark.sql.types import *

# Initialize Spark Session
spark = SparkSession.builder \
    .appName("WebAttackDetection") \
    .config("spark.sql.shuffle.partitions", "4") \
    .getOrCreate()

print("="*60)
print("WEB SERVER LOG ANALYSIS & SQL INJECTION DETECTION")
print("="*60)

# Read web server logs from HDFS
print("\n[1] Reading web server logs from HDFS...")
web_logs_path = "hdfs://hadoop-master:9000/data/logs/web/web_logs.log"
raw_logs = spark.read.text(web_logs_path)

print(f"Total web requests: {raw_logs.count():,}")

# Parse web server logs (Apache/Nginx format)
print("\n[2] Parsing web server log entries...")
parsed_logs = raw_logs.select(
    regexp_extract(col("value"), r"^([\d.]+)", 1).alias("ip_address"),
    regexp_extract(col("value"), r"\[([^\]]+)\]", 1).alias("timestamp"),
    regexp_extract(col("value"), r'"(GET|POST|PUT|DELETE)', 1).alias("method"),
    regexp_extract(col("value"), r'"(?:GET|POST|PUT|DELETE) ([^\s]+)', 1).alias("path"),
    regexp_extract(col("value"), r'" (\d{3}) ', 1).alias("status_code"),
    regexp_extract(col("value"), r'" \d{3} (\d+)', 1).alias("response_size"),
    regexp_extract(col("value"), r'"([^"]*)"$', 1).alias("user_agent")
).filter(col("method") != "")

parsed_logs.cache()
print(f"Parsed entries: {parsed_logs.count():,}")

# Show sample
print("\n[3] Sample parsed web logs:")
parsed_logs.show(5, truncate=False)

# Analysis 1: Detect SQL injection attempts
print("\n[4] SQL INJECTION DETECTION")
print("Identifying requests with SQL injection patterns...")

sql_injection_logs = parsed_logs.withColumn(
    "is_sql_injection",
    when(
        lower(col("path")).contains("'") |
        lower(col("path")).contains("or 1=1") |
        lower(col("path")).contains("union") |
        lower(col("path")).contains("select") |
        lower(col("path")).contains("drop") |
        lower(col("path")).contains("--"),
        True
    ).otherwise(False)
)

sql_injections = sql_injection_logs.filter(col("is_sql_injection") == True)
sql_injection_count = sql_injections.count()
total_requests = parsed_logs.count()

print(f"SQL injection attempts: {sql_injection_count:,} ({sql_injection_count/total_requests*100:.2f}%)")

# Top IPs performing SQL injection
print("\n[5] Top IPs performing SQL injection:")
sql_attackers = sql_injections.groupBy("ip_address") \
    .agg(count("*").alias("injection_attempts")) \
    .orderBy(col("injection_attempts").desc())

sql_attackers.show(15, truncate=False)

# Analysis 2: HTTP status code distribution
print("\n[6] ANALYSIS: HTTP status code distribution")
status_dist = parsed_logs.groupBy("status_code") \
    .agg(count("*").alias("count")) \
    .orderBy(col("count").desc())

status_dist.show()

# Interpret status codes
print("\nStatus code interpretation:")
status_meanings = {
    "200": "OK (Success)",
    "304": "Not Modified",
    "403": "Forbidden (Access Denied)",
    "404": "Not Found",
    "500": "Internal Server Error"
}

for code, meaning in status_meanings.items():
    code_count = parsed_logs.filter(col("status_code") == code).count()
    if code_count > 0:
        print(f"  {code} ({meaning}): {code_count:,} ({code_count/total_requests*100:.2f}%)")

# Analysis 3: Most requested paths
print("\n[7] ANALYSIS: Most requested paths")
top_paths = parsed_logs.groupBy("path") \
    .agg(count("*").alias("request_count")) \
    .orderBy(col("request_count").desc())

# Extract base path (remove query parameters)
parsed_logs_with_base = parsed_logs.withColumn(
    "base_path",
    regexp_extract(col("path"), r"^([^?]+)", 1)
)

top_base_paths = parsed_logs_with_base.groupBy("base_path") \
    .agg(count("*").alias("request_count")) \
    .orderBy(col("request_count").desc())

print("Top 15 requested paths:")
top_base_paths.show(15, truncate=False)

# Analysis 4: Attack patterns from suspicious user agents
print("\n[8] ANALYSIS: Suspicious user agents")
suspicious_agents = parsed_logs.filter(
    lower(col("user_agent")).contains("sqlmap") |
    lower(col("user_agent")).contains("nikto") |
    lower(col("user_agent")).contains("nmap") |
    lower(col("user_agent")).contains("masscan")
)

print(f"Requests from attack tools: {suspicious_agents.count():,}")
if suspicious_agents.count() > 0:
    suspicious_agents.groupBy("user_agent") \
        .agg(count("*").alias("count")) \
        .orderBy(col("count").desc()) \
        .show(10, truncate=False)

# Analysis 5: HTTP method distribution
print("\n[9] ANALYSIS: HTTP method distribution")
method_dist = parsed_logs.groupBy("method") \
    .agg(count("*").alias("count")) \
    .orderBy(col("count").desc())

method_dist.show()

# Analysis 6: Top requesting IPs (potential bots/scrapers)
print("\n[10] ANALYSIS: Top requesting IPs")
top_ips = parsed_logs.groupBy("ip_address") \
    .agg(count("*").alias("request_count")) \
    .orderBy(col("request_count").desc())

print("Top 20 most active IPs:")
top_ips.show(20, truncate=False)

# Analysis 7: Failed requests (4xx and 5xx errors)
print("\n[11] ANALYSIS: Failed requests")
failed_requests = parsed_logs.filter(
    col("status_code").startswith("4") | col("status_code").startswith("5")
)

failed_count = failed_requests.count()
print(f"Failed requests (4xx/5xx): {failed_count:,} ({failed_count/total_requests*100:.2f}%)")

# Save results to HDFS
print("\n[12] Saving results to HDFS...")

# Save SQL injection attempts
sql_injection_output = "hdfs://hadoop-master:9000/data/results/sql_injection_attempts"
sql_injections.select("ip_address", "timestamp", "path", "status_code") \
    .coalesce(1).write.mode("overwrite").csv(sql_injection_output, header=True)
print(f"✓ Saved SQL injection attempts to: {sql_injection_output}")

# Save SQL attackers
sql_attackers_output = "hdfs://hadoop-master:9000/data/results/sql_attackers"
sql_attackers.coalesce(1).write.mode("overwrite").csv(sql_attackers_output, header=True)
print(f"✓ Saved SQL attackers to: {sql_attackers_output}")

# Save top paths
paths_output = "hdfs://hadoop-master:9000/data/results/top_paths"
top_base_paths.coalesce(1).write.mode("overwrite").csv(paths_output, header=True)
print(f"✓ Saved top paths to: {paths_output}")

# Save status distribution
status_output = "hdfs://hadoop-master:9000/data/results/status_distribution"
status_dist.coalesce(1).write.mode("overwrite").csv(status_output, header=True)
print(f"✓ Saved status distribution to: {status_output}")

print("\n" + "="*60)
print("WEB ATTACK ANALYSIS COMPLETE!")
print("="*60)
print("\nKey Findings:")
print(f"  • {sql_injection_count:,} SQL injection attempts detected")
print(f"  • {sql_attackers.count()} unique attacking IPs")
print(f"  • {failed_count:,} failed requests (4xx/5xx errors)")
print(f"  • Most requested path: {top_base_paths.first()['base_path']}")
print("="*60)

# Stop Spark
spark.stop()