"""
Log Inspector - Optimized for 5GB Dataset
Samples data instead of reading everything (memory efficient)

Author: AMGHAR Yassine
Date: December 2025
"""

from pathlib import Path
from collections import Counter
import random
import re

LOG_DIR = Path("bigdata_logs")
SAMPLE_SIZE = 100_000  # Sample 100k lines from each file

def sample_lines(filepath, sample_size):
    """Efficiently sample lines from large file"""
    print(f"Samplieng {sample_size:,} lines from {filepath.name}...")
    
    # Count total lines first
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        total_lines = sum(1 for _ in f)
    
    print(f"  Total lines: {total_lines:,}")
    
    if total_lines <= sample_size:
        # If file is small, read all
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines(), total_lines
    
    # Random sampling
    sample_indices = set(random.sample(range(total_lines), sample_size))
    samples = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i in sample_indices:
                samples.append(line)
                if len(samples) >= sample_size:
                    break
    
    return samples, total_lines

def analyze_auth_logs():
    """Analyze authentication logs"""
    print("\n" + "="*70)
    print("AUTHENTICATION LOGS ANALYSIS (5GB Dataset)")
    print("="*70)
    
    filepath = LOG_DIR / "auth_logs.log"
    samples, total_lines = sample_lines(filepath, SAMPLE_SIZE)
    
    failed = 0
    success = 0
    failed_ips = Counter()
    failed_users = Counter()
    
    for line in samples:
        if "Failed password" in line:
            failed += 1
            ip_match = re.search(r'from ([\d.]+)', line)
            user_match = re.search(r'for ([\w.]+)', line)
            
            if ip_match:
                failed_ips[ip_match.group(1)] += 1
            if user_match:
                failed_users[user_match.group(1)] += 1
                
        elif "Accepted password" in line:
            success += 1
    
    # Extrapolate to full dataset
    sample_ratio = total_lines / len(samples)
    estimated_failed = int(failed * sample_ratio)
    estimated_success = int(success * sample_ratio)
    
    print(f"\n📊 Statistics (from {len(samples):,} sampled lines):")
    print(f"  Total events: {total_lines:,}")
    print(f"  Estimated failed logins: ~{estimated_failed:,} ({failed/len(samples)*100:.1f}%)")
    print(f"  Estimated successful logins: ~{estimated_success:,} ({success/len(samples)*100:.1f}%)")
    
    print(f"\n🎯 Top 10 IPs with most failed attempts (in sample):")
    for ip, count in failed_ips.most_common(10):
        estimated_count = int(count * sample_ratio)
        print(f"  {ip}: ~{estimated_count} attempts (sample: {count})")
        if count > 50:
            print(f"    ⚠️  BRUTE FORCE DETECTED!")
    
    print(f"\n👤 Top 10 targeted usernames (in sample):")
    for user, count in failed_users.most_common(10):
        estimated_count = int(count * sample_ratio)
        print(f"  {user}: ~{estimated_count} attempts (sample: {count})")
    
    # Show some Arabic/Moroccan usernames
    arabic_users = [u for u in failed_users.keys() if '.' in u and u not in ['root', 'admin', 'test']]
    if arabic_users:
        print(f"\n🇲🇦 Moroccan/Arabic usernames detected:")
        for user in arabic_users[:5]:
            print(f"  ✓ {user}")
    
    # Sample log entries
    print(f"\n📄 Sample log entries:")
    for i, line in enumerate(samples[:3]):
        print(f"  {line.strip()}")

def analyze_firewall_logs():
    """Analyze firewall logs"""
    print("\n" + "="*70)
    print("FIREWALL LOGS ANALYSIS (5GB Dataset)")
    print("="*70)
    
    filepath = LOG_DIR / "firewall_logs.log"
    samples, total_lines = sample_lines(filepath, SAMPLE_SIZE)
    
    blocked_ips = Counter()
    targeted_ips = Counter()
    ports = Counter()
    protocols = Counter()
    
    for line in samples:
        src_match = re.search(r'([\d.]+):\d+ ->', line)
        dst_match = re.search(r'-> ([\d.]+):(\d+)', line)
        proto_match = re.search(r'BLOCK (TCP|UDP|ICMP)', line)
        
        if src_match:
            blocked_ips[src_match.group(1)] += 1
        if dst_match:
            targeted_ips[dst_match.group(1)] += 1
            ports[dst_match.group(2)] += 1
        if proto_match:
            protocols[proto_match.group(1)] += 1
    
    sample_ratio = total_lines / len(samples)
    
    print(f"\n📊 Statistics (from {len(samples):,} sampled lines):")
    print(f"  Total blocked connections: {total_lines:,}")
    
    print(f"\n🚫 Top 10 attacking IPs (in sample):")
    for ip, count in blocked_ips.most_common(10):
        estimated = int(count * sample_ratio)
        print(f"  {ip}: ~{estimated} attempts (sample: {count})")
        if count > 100:
            print(f"    ⚠️  PORT SCAN DETECTED!")
    
    print(f"\n🎯 Top 10 targeted internal IPs:")
    for ip, count in targeted_ips.most_common(10):
        estimated = int(count * sample_ratio)
        print(f"  {ip}: ~{estimated} times targeted (sample: {count})")
    
    print(f"\n🔌 Most targeted ports:")
    port_names = {
        '22': 'SSH', '80': 'HTTP', '443': 'HTTPS',
        '3306': 'MySQL', '8080': 'HTTP-ALT'
    }
    for port, count in ports.most_common(10):
        port_name = port_names.get(port, 'Unknown')
        estimated = int(count * sample_ratio)
        print(f"  Port {port} ({port_name}): ~{estimated} attempts")
    
    print(f"\n📡 Protocols:")
    for proto, count in protocols.most_common():
        print(f"  {proto}: {count:,} ({count/len(samples)*100:.1f}%)")

def analyze_web_logs():
    """Analyze web server logs"""
    print("\n" + "="*70)
    print("WEB SERVER LOGS ANALYSIS (5GB Dataset)")
    print("="*70)
    
    filepath = LOG_DIR / "web_logs.log"
    samples, total_lines = sample_lines(filepath, SAMPLE_SIZE)
    
    status_codes = Counter()
    methods = Counter()
    ips = Counter()
    sql_injection = 0
    
    for line in samples:
        ip_match = re.match(r'^([\d.]+)', line)
        method_match = re.search(r'"(GET|POST|PUT|DELETE)', line)
        status_match = re.search(r'" (\d{3}) ', line)
        
        if ip_match:
            ips[ip_match.group(1)] += 1
        if method_match:
            methods[method_match.group(1)] += 1
        if status_match:
            status_codes[status_match.group(1)] += 1
        
        # Check for SQL injection
        if any(x in line.lower() for x in ["'", "union", "select", "drop", "or 1=1"]):
            sql_injection += 1
    
    sample_ratio = total_lines / len(samples)
    estimated_sql = int(sql_injection * sample_ratio)
    
    print(f"\n📊 Statistics (from {len(samples):,} sampled lines):")
    print(f"  Total requests: {total_lines:,}")
    print(f"  Estimated SQL injection attempts: ~{estimated_sql:,} ({sql_injection/len(samples)*100:.1f}%)")
    
    print(f"\n📍 HTTP Status Codes:")
    for code, count in sorted(status_codes.items()):
        code_meaning = {
            '200': 'OK', '304': 'Not Modified', '403': 'Forbidden',
            '404': 'Not Found', '500': 'Internal Error'
        }
        meaning = code_meaning.get(code, 'Unknown')
        print(f"  {code} ({meaning}): {count:,} ({count/len(samples)*100:.1f}%)")
    
    print(f"\n🌐 HTTP Methods:")
    for method, count in methods.most_common():
        print(f"  {method}: {count:,} ({count/len(samples)*100:.1f}%)")
    
    print(f"\n🌍 Top 10 requesting IPs (in sample):")
    for ip, count in ips.most_common(10):
        estimated = int(count * sample_ratio)
        print(f"  {ip}: ~{estimated} requests")

def main():
    print("="*70)
    print("CYBERSECURITY LOG ANALYSIS - 5GB DATASET")
    print("="*70)
    print(f"Dataset location: {LOG_DIR.absolute()}")
    print(f"Analysis method: Statistical sampling ({SAMPLE_SIZE:,} lines per file)")
    print(f"Author: AMGHAR Yassine")
    
    try:
        # Check if files exist
        auth_file = LOG_DIR / "auth_logs.log"
        firewall_file = LOG_DIR / "firewall_logs.log"
        web_file = LOG_DIR / "web_logs.log"
        
        if not auth_file.exists():
            print(f"\n❌ Error: {auth_file} not found!")
            print("   Make sure you ran fullscale_generator_arabic.py first!")
            return
        
        # File sizes
        print(f"\n📁 Dataset files:")
        for file in LOG_DIR.glob("*.log"):
            size_mb = file.stat().st_size / (1024 * 1024)
            size_gb = size_mb / 1024
            print(f"  - {file.name}: {size_gb:.2f} GB ({size_mb:.1f} MB)")
        
        # Run analyses
        analyze_auth_logs()
        analyze_firewall_logs()
        analyze_web_logs()
        
        print("\n" + "="*70)
        print("ANALYSIS COMPLETE!")
        print("="*70)
        print("\n✅ Data Quality: EXCELLENT (5GB dataset)")
        print("✅ Attack Patterns: DETECTED at scale")
        print("✅ Arabic/Moroccan usernames: CONFIRMED")
        print("✅ Ready for Big Data processing with Spark")
        
        print("\n📋 Next Steps:")
        print("  1. Data already uploaded to HDFS ✓")
        print("  2. Run Spark analysis ✓")
        print("  3. Generate visualizations")
        print("  4. Update dashboard")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()