"""
Spark Analysis Script #2: Firewall Log Analysis & Port Scan Detection
Analyzes firewall logs to identify port scanning and attack patterns

Author: [Your Name]
Date: December 2025
"""

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, regexp_extract, countDistinct
from pyspark.sql.types import *

# Initialize Spark Session
spark = SparkSession.builder \
    .appName("FirewallAnalysis") \
    .config("spark.sql.shuffle.partitions", "4") \
    .getOrCreate()

print("="*60)
print("FIREWALL LOG ANALYSIS & PORT SCAN DETECTION")
print("="*60)

# Read firewall logs from HDFS
print("\n[1] Reading firewall logs from HDFS...")
firewall_logs_path = "hdfs://hadoop-master:9000/data/logs/firewall/firewall_logs.log"
raw_logs = spark.read.text(firewall_logs_path)

print(f"Total firewall events: {raw_logs.count():,}")

# Parse firewall logs
print("\n[2] Parsing firewall log entries...")
parsed_logs = raw_logs.select(
    regexp_extract(col("value"), r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", 1).alias("timestamp"),
    regexp_extract(col("value"), r"FIREWALL (\w+)", 1).alias("action"),
    regexp_extract(col("value"), r"(TCP|UDP)", 1).alias("protocol"),
    regexp_extract(col("value"), r"([\d.]+):\d+ ->", 1).alias("src_ip"),
    regexp_extract(col("value"), r":\d+ -> ([\d.]+)", 1).alias("dst_ip"),
    regexp_extract(col("value"), r"-> [\d.]+:(\d+)", 1).alias("dst_port")
).filter(col("action") != "")

parsed_logs.cache()
print(f"Parsed entries: {parsed_logs.count():,}")

# Show sample
print("\n[3] Sample parsed firewall logs:")
parsed_logs.show(5, truncate=False)

# Analysis 1: Top attacking source IPs
print("\n[4] ANALYSIS: Top attacking source IPs")
top_attackers = parsed_logs.groupBy("src_ip") \
    .agg(count("*").alias("blocked_attempts")) \
    .orderBy(col("blocked_attempts").desc())

print("Top 20 attacking IPs:")
top_attackers.show(20, truncate=False)

# Analysis 2: Most targeted internal IPs
print("\n[5] ANALYSIS: Most targeted internal IPs")
top_targets = parsed_logs.groupBy("dst_ip") \
    .agg(count("*").alias("times_targeted")) \
    .orderBy(col("times_targeted").desc())

print("Top 10 targeted internal IPs:")
top_targets.show(10, truncate=False)

# Analysis 3: Port scan detection
print("\n[6] PORT SCAN DETECTION")
print("Identifying IPs scanning multiple ports...")

port_scans = parsed_logs.groupBy("src_ip") \
    .agg(
        countDistinct("dst_port").alias("unique_ports_scanned"),
        count("*").alias("total_attempts")
    ) \
    .filter(col("unique_ports_scanned") > 50) \
    .orderBy(col("unique_ports_scanned").desc())

print(f"Port scanners detected (scanned >50 different ports): {port_scans.count()}")
port_scans.show(10, truncate=False)

# Analysis 4: Most targeted ports
print("\n[7] ANALYSIS: Most targeted ports")
top_ports = parsed_logs.groupBy("dst_port") \
    .agg(count("*").alias("attack_count")) \
    .orderBy(col("attack_count").desc())

print("Top 15 targeted ports:")
top_ports.show(15, truncate=False)

# Add port descriptions
port_names = {
    "22": "SSH",
    "80": "HTTP",
    "443": "HTTPS",
    "3306": "MySQL",
    "8080": "HTTP-ALT",
    "3389": "RDP",
    "21": "FTP",
    "25": "SMTP",
    "53": "DNS",
    "110": "POP3",
    "143": "IMAP",
    "445": "SMB"
}

print("\nCommon port interpretations:")
for port, name in port_names.items():
    port_count = parsed_logs.filter(col("dst_port") == port).count()
    if port_count > 0:
        print(f"  Port {port} ({name}): {port_count:,} attacks")

# Analysis 5: Protocol distribution
print("\n[8] ANALYSIS: Protocol distribution")
protocol_stats = parsed_logs.groupBy("protocol") \
    .agg(count("*").alias("count"))

protocol_stats.show()

# Analysis 6: Coordinated attacks (same target, multiple sources)
print("\n[9] ANALYSIS: Coordinated/Distributed attacks")
coordinated = parsed_logs.groupBy("dst_ip") \
    .agg(
        countDistinct("src_ip").alias("unique_attackers"),
        count("*").alias("total_attacks")
    ) \
    .filter(col("unique_attackers") > 10) \
    .orderBy(col("unique_attackers").desc())

print("Targets under coordinated attack (>10 unique sources):")
coordinated.show(10, truncate=False)

# Save results to HDFS
print("\n[10] Saving results to HDFS...")

# Save top attackers
attackers_output = "hdfs://hadoop-master:9000/data/results/top_attackers"
top_attackers.coalesce(1).write.mode("overwrite").csv(attackers_output, header=True)
print(f"✓ Saved top attackers to: {attackers_output}")

# Save port scanners
port_scan_output = "hdfs://hadoop-master:9000/data/results/port_scanners"
port_scans.coalesce(1).write.mode("overwrite").csv(port_scan_output, header=True)
print(f"✓ Saved port scanners to: {port_scan_output}")

# Save targeted ports
ports_output = "hdfs://hadoop-master:9000/data/results/targeted_ports"
top_ports.coalesce(1).write.mode("overwrite").csv(ports_output, header=True)
print(f"✓ Saved targeted ports to: {ports_output}")

print("\n" + "="*60)
print("FIREWALL ANALYSIS COMPLETE!")
print("="*60)
print("\nKey Findings:")
print(f"  • {top_attackers.count():,} unique attacking IPs")
print(f"  • {port_scans.count()} port scanning sources detected")
print(f"  • Most attacked port: {top_ports.first()['dst_port']}")
print(f"  • {coordinated.count()} targets under coordinated attack")
print("="*60)

# Stop Spark
spark.stop()