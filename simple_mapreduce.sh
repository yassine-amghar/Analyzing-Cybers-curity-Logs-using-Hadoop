#!/bin/bash
# ============================================================
# Simple MapReduce Demo - Local Processing (No YARN needed)
# Demonstrates MapReduce concepts using basic shell commands
# ============================================================

echo "============================================================"
echo "MAPREDUCE DEMO: Log Analysis with MapReduce Concepts"
echo "============================================================"

# Create temporary directory
TEMP_DIR="/tmp/mapreduce_demo_$$"
mkdir -p $TEMP_DIR

echo ""
echo "[1] Extracting logs from HDFS to local temp directory..."
hdfs dfs -cat /data/logs/auth/auth_logs.log > $TEMP_DIR/auth_logs.txt
echo "    ✓ Downloaded $(wc -l < $TEMP_DIR/auth_logs.txt) lines"

# ============================================================
# ANALYSIS 1: Count Failed vs Successful Logins (MapReduce Style)
# ============================================================
echo ""
echo "============================================================"
echo "ANALYSIS 1: Failed vs Successful Login Counts"
echo "============================================================"
echo ""
echo "[MAP PHASE] Extracting status from each line..."

# Map: Extract status (Failed/Accepted)
grep -o "Failed\|Accepted" $TEMP_DIR/auth_logs.txt > $TEMP_DIR/mapped_status.txt
echo "    ✓ Mapped $(wc -l < $TEMP_DIR/mapped_status.txt) status values"

echo ""
echo "[SHUFFLE & SORT PHASE] Sorting status values..."
sort $TEMP_DIR/mapped_status.txt > $TEMP_DIR/sorted_status.txt
echo "    ✓ Sorted"

echo ""
echo "[REDUCE PHASE] Counting occurrences..."
uniq -c $TEMP_DIR/sorted_status.txt > $TEMP_DIR/status_counts.txt

echo ""
echo "Results:"
cat $TEMP_DIR/status_counts.txt
FAILED=$(grep "Failed" $TEMP_DIR/status_counts.txt | awk '{print $1}')
ACCEPTED=$(grep "Accepted" $TEMP_DIR/status_counts.txt | awk '{print $1}')
TOTAL=$((FAILED + ACCEPTED))
echo ""
echo "Summary:"
echo "  Total Login Attempts: $TOTAL"
echo "  Failed: $FAILED ($(awk "BEGIN {printf \"%.1f\", ($FAILED/$TOTAL)*100}")%)"
echo "  Successful: $ACCEPTED ($(awk "BEGIN {printf \"%.1f\", ($ACCEPTED/$TOTAL)*100}")%)"

# ============================================================
# ANALYSIS 2: Count Unique IP Addresses (MapReduce Style)
# ============================================================
echo ""
echo "============================================================"
echo "ANALYSIS 2: Unique IP Address Count"
echo "============================================================"
echo ""
echo "[MAP PHASE] Extracting IP addresses from each line..."

# Map: Extract IPs using regex
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' $TEMP_DIR/auth_logs.txt > $TEMP_DIR/mapped_ips.txt
echo "    ✓ Mapped $(wc -l < $TEMP_DIR/mapped_ips.txt) IP addresses"

echo ""
echo "[SHUFFLE & SORT PHASE] Sorting IP addresses..."
sort $TEMP_DIR/mapped_ips.txt > $TEMP_DIR/sorted_ips.txt
echo "    ✓ Sorted"

echo ""
echo "[REDUCE PHASE] Counting unique IPs and their frequencies..."
uniq -c $TEMP_DIR/sorted_ips.txt | sort -rn > $TEMP_DIR/ip_counts.txt

UNIQUE_IPS=$(wc -l < $TEMP_DIR/ip_counts.txt)
echo ""
echo "Results:"
echo "  Total unique IP addresses: $UNIQUE_IPS"
echo ""
echo "  Top 10 most active IPs:"
head -10 $TEMP_DIR/ip_counts.txt | awk '{printf "    %s: %s attempts\n", $2, $1}'

# ============================================================
# ANALYSIS 3: Count Most Targeted Usernames (MapReduce Style)
# ============================================================
echo ""
echo "============================================================"
echo "ANALYSIS 3: Most Targeted Usernames"
echo "============================================================"
echo ""
echo "[MAP PHASE] Extracting usernames from each line..."

# Map: Extract usernames
grep -oP 'for \K\w+' $TEMP_DIR/auth_logs.txt > $TEMP_DIR/mapped_usernames.txt
echo "    ✓ Mapped $(wc -l < $TEMP_DIR/mapped_usernames.txt) usernames"

echo ""
echo "[SHUFFLE & SORT PHASE] Sorting usernames..."
sort $TEMP_DIR/mapped_usernames.txt > $TEMP_DIR/sorted_usernames.txt
echo "    ✓ Sorted"

echo ""
echo "[REDUCE PHASE] Counting username frequencies..."
uniq -c $TEMP_DIR/sorted_usernames.txt | sort -rn > $TEMP_DIR/username_counts.txt

echo ""
echo "Results - Top 15 targeted usernames:"
head -15 $TEMP_DIR/username_counts.txt | awk '{printf "    %s: %s attempts\n", $2, $1}'

# ============================================================
# ANALYSIS 4: Count Attacks by Port (MapReduce Style)
# ============================================================
echo ""
echo "============================================================"
echo "ANALYSIS 4: Attacks by Port"
echo "============================================================"
echo ""
echo "[MAP PHASE] Extracting port numbers from each line..."

# Map: Extract ports
grep -oP 'port \K\d+' $TEMP_DIR/auth_logs.txt > $TEMP_DIR/mapped_ports.txt
echo "    ✓ Mapped $(wc -l < $TEMP_DIR/mapped_ports.txt) port numbers"

echo ""
echo "[SHUFFLE & SORT PHASE] Sorting port numbers..."
sort $TEMP_DIR/mapped_ports.txt > $TEMP_DIR/sorted_ports.txt
echo "    ✓ Sorted"

echo ""
echo "[REDUCE PHASE] Counting port frequencies..."
uniq -c $TEMP_DIR/sorted_ports.txt | sort -rn > $TEMP_DIR/port_counts.txt

echo ""
echo "Results - Attacks by port:"
cat $TEMP_DIR/port_counts.txt | awk '{
    port=$2
    count=$1
    service=""
    if (port==22) service="SSH"
    else if (port==80) service="HTTP"
    else if (port==443) service="HTTPS"
    else if (port==3389) service="RDP"
    else service="Other"
    printf "    Port %s (%s): %s attempts\n", port, service, count
}'

# ============================================================
# Save Results to HDFS
# ============================================================
echo ""
echo "============================================================"
echo "SAVING RESULTS TO HDFS"
echo "============================================================"

OUTPUT_BASE="/data/mapreduce_results"
hdfs dfs -mkdir -p $OUTPUT_BASE

echo ""
echo "Uploading results to HDFS..."
hdfs dfs -put -f $TEMP_DIR/status_counts.txt $OUTPUT_BASE/
hdfs dfs -put -f $TEMP_DIR/ip_counts.txt $OUTPUT_BASE/
hdfs dfs -put -f $TEMP_DIR/username_counts.txt $OUTPUT_BASE/
hdfs dfs -put -f $TEMP_DIR/port_counts.txt $OUTPUT_BASE/

echo "    ✓ Results saved to: $OUTPUT_BASE/"

# ============================================================
# Cleanup
# ============================================================
echo ""
echo "Cleaning up temporary files..."
rm -rf $TEMP_DIR
echo "    ✓ Cleaned up"

# ============================================================
# Summary
# ============================================================
echo ""
echo "============================================================"
echo "MAPREDUCE DEMO COMPLETE!"
echo "============================================================"
echo ""
echo "This demo demonstrated MapReduce concepts:"
echo "  • MAP: Extract relevant data from each log line"
echo "  • SHUFFLE & SORT: Organize data by key"
echo "  • REDUCE: Aggregate and count occurrences"
echo ""
echo "Results saved to HDFS at: $OUTPUT_BASE/"
echo ""
echo "View results with:"
echo "  hdfs dfs -cat $OUTPUT_BASE/status_counts.txt"
echo "  hdfs dfs -cat $OUTPUT_BASE/ip_counts.txt"
echo "  hdfs dfs -cat $OUTPUT_BASE/username_counts.txt"
echo "  hdfs dfs -cat $OUTPUT_BASE/port_counts.txt"
echo ""
echo "Key Findings:"
echo "  • Total Login Attempts: $TOTAL"
echo "  • Failed Logins: $FAILED"
echo "  • Unique IP Addresses: $UNIQUE_IPS"
echo "============================================================"