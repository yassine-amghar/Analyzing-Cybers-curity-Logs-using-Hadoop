"""
Spark Analysis Script #1: Brute Force Attack Detection
Analyzes authentication logs to identify brute force attacks

Author: [Your Name]
Date: December 2025
"""

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, regexp_extract, to_timestamp, hour, dayofweek
from pyspark.sql.types import *
import sys

# Initialize Spark Session
spark = SparkSession.builder \
    .appName("BruteForceDetection") \
    .config("spark.sql.shuffle.partitions", "4") \
    .getOrCreate()

print("="*60)
print("BRUTE FORCE ATTACK DETECTION")
print("="*60)

# Read authentication logs from HDFS
print("\n[1] Reading authentication logs from HDFS...")
auth_logs_path = "hdfs://hadoop-master:9000/data/logs/auth/auth_logs.log"
raw_logs = spark.read.text(auth_logs_path)

print(f"Total log entries: {raw_logs.count():,}")

# Parse log lines
print("\n[2] Parsing log entries...")
parsed_logs = raw_logs.select(
    regexp_extract(col("value"), r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", 1).alias("timestamp"),
    regexp_extract(col("value"), r"(Failed|Accepted)", 1).alias("status"),
    regexp_extract(col("value"), r"for (\w+[\w.]*)", 1).alias("username"),
    regexp_extract(col("value"), r"from ([\d.]+)", 1).alias("ip_address"),
    regexp_extract(col("value"), r"port (\d+)", 1).alias("port")
).filter(col("status") != "")

# Convert timestamp to proper format
parsed_logs = parsed_logs.withColumn(
    "timestamp", 
    to_timestamp(col("timestamp"), "yyyy-MM-dd HH:mm:ss")
)

parsed_logs.cache()
print(f"Parsed entries: {parsed_logs.count():,}")

# Show sample
print("\n[3] Sample parsed logs:")
parsed_logs.show(5, truncate=False)

# Analysis 1: Failed login attempts per IP
print("\n[4] ANALYSIS: Failed login attempts per IP")
failed_logins = parsed_logs.filter(col("status") == "Failed") \
    .groupBy("ip_address") \
    .agg(count("*").alias("failed_attempts")) \
    .orderBy(col("failed_attempts").desc())

print("Top 20 IPs with most failed attempts:")
failed_logins.show(20, truncate=False)

# Identify brute force attacks (>50 failed attempts)
print("\n[5] BRUTE FORCE DETECTION (>50 failed attempts):")
brute_force_ips = failed_logins.filter(col("failed_attempts") > 50)
print(f"Total brute force sources detected: {brute_force_ips.count()}")
brute_force_ips.show(10, truncate=False)

# Analysis 2: Most targeted usernames
print("\n[6] ANALYSIS: Most targeted usernames")
targeted_users = parsed_logs.filter(col("status") == "Failed") \
    .groupBy("username") \
    .agg(count("*").alias("attack_count")) \
    .orderBy(col("attack_count").desc())

print("Top 10 targeted usernames:")
targeted_users.show(10, truncate=False)

# Analysis 3: Attack patterns by hour
print("\n[7] ANALYSIS: Attack patterns by hour of day")
attacks_by_hour = parsed_logs.filter(col("status") == "Failed") \
    .withColumn("hour_of_day", hour(col("timestamp"))) \
    .groupBy("hour_of_day") \
    .agg(count("*").alias("attack_count")) \
    .orderBy("hour_of_day")

print("Failed login attempts by hour:")
attacks_by_hour.show(24, truncate=False)

# Analysis 4: Success rate statistics
print("\n[8] ANALYSIS: Login success vs failure statistics")
status_summary = parsed_logs.groupBy("status") \
    .agg(count("*").alias("count"))

status_summary.show()

total = parsed_logs.count()
failed = parsed_logs.filter(col("status") == "Failed").count()
success = parsed_logs.filter(col("status") == "Accepted").count()

print(f"\nSummary:")
print(f"  Total attempts: {total:,}")
print(f"  Failed: {failed:,} ({failed/total*100:.2f}%)")
print(f"  Success: {success:,} ({success/total*100:.2f}%)")

# Analysis 5: Attacks by day of week
print("\n[9] ANALYSIS: Attack patterns by day of week")
attacks_by_day = parsed_logs.filter(col("status") == "Failed") \
    .withColumn("day_of_week", dayofweek(col("timestamp"))) \
    .groupBy("day_of_week") \
    .agg(count("*").alias("attack_count")) \
    .orderBy("day_of_week")

print("Failed logins by day (1=Sunday, 7=Saturday):")
attacks_by_day.show(7, truncate=False)

# Save results to HDFS
print("\n[10] Saving results to HDFS...")

# Save brute force IPs
brute_force_output = "hdfs://hadoop-master:9000/data/results/brute_force_ips"
brute_force_ips.coalesce(1).write.mode("overwrite").csv(brute_force_output, header=True)
print(f"✓ Saved brute force IPs to: {brute_force_output}")

# Save targeted users
targeted_users_output = "hdfs://hadoop-master:9000/data/results/targeted_users"
targeted_users.coalesce(1).write.mode("overwrite").csv(targeted_users_output, header=True)
print(f"✓ Saved targeted users to: {targeted_users_output}")

# Save hourly patterns
hourly_output = "hdfs://hadoop-master:9000/data/results/attacks_by_hour"
attacks_by_hour.coalesce(1).write.mode("overwrite").csv(hourly_output, header=True)
print(f"✓ Saved hourly patterns to: {hourly_output}")

print("\n" + "="*60)
print("ANALYSIS COMPLETE!")
print("="*60)
print("\nKey Findings:")
print(f"  • {brute_force_ips.count()} brute force attack sources detected")
print(f"  • {failed:,} total failed login attempts")
print(f"  • Most targeted username: {targeted_users.first()['username']}")
print(f"  • Attack success rate: {(success/total*100):.2f}%")
print("="*60)

# Stop Spark
spark.stop()