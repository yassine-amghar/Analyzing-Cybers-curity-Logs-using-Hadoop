"""
Cybersecurity Analysis Visualizations - 5GB Dataset
Generates charts and graphs from Spark analysis results (5.8GB data)

Author: AMGHAR Yassine
Date: January 2026

Requirements:
  pip install matplotlib seaborn pandas
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from pathlib import Path
import subprocess
import sys

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 8)
plt.rcParams['font.size'] = 11

# Output directory for 5GB visualizations
OUTPUT_DIR = Path("visualizations_5gb")
OUTPUT_DIR.mkdir(exist_ok=True)

print("="*70)
print("GENERATING VISUALIZATIONS FROM 5GB DATASET SPARK RESULTS")
print("="*70)
print("Author: AMGHAR Yassine")
print("Dataset: 5.8GB (50M logs)")
print("Output: visualizations_5gb/")
print("="*70)

# ============================================================
# HELPER: Download CSV from HDFS via Docker
# ============================================================
def download_from_hdfs(hdfs_path, local_path):
    """Download CSV file from HDFS via docker exec"""
    print(f"\n[Downloading] {hdfs_path}...")
    
    # Use docker exec to cat the file
    cmd = f'docker exec hadoop-master hdfs dfs -cat {hdfs_path}/*.csv'
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0 and result.stdout.strip():
            with open(local_path, 'w', encoding='utf-8') as f:
                f.write(result.stdout)
            print(f"✓ Downloaded: {hdfs_path} → {local_path}")
            
            # Verify file has content
            file_size = Path(local_path).stat().st_size
            if file_size < 100:
                print(f"  ⚠️  Warning: File is very small ({file_size} bytes)")
            
            return True
        else:
            print(f"✗ Failed to download: {hdfs_path}")
            if result.stderr:
                print(f"  Error: {result.stderr[:200]}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"✗ Timeout downloading: {hdfs_path}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

# ============================================================
# DOWNLOAD ALL RESULTS FROM HDFS (5GB Analysis)
# ============================================================
print("\n[1] Downloading Spark results from HDFS...")
print("    (This downloads analysis results, not raw 5GB logs)")

downloads = {
    '/data/results/brute_force_ips': 'brute_force_ips.csv',
    '/data/results/targeted_users': 'targeted_users.csv',
    '/data/results/attacks_by_hour': 'attacks_by_hour.csv',
    '/data/results/top_attackers': 'top_attackers.csv',
    '/data/results/targeted_ports': 'targeted_ports.csv',
    '/data/results/sql_attackers': 'sql_attackers.csv',
    '/data/results/status_distribution': 'status_distribution.csv'
}

data_files = {}
success_count = 0

for hdfs_path, filename in downloads.items():
    local_path = OUTPUT_DIR / filename
    if download_from_hdfs(hdfs_path, local_path):
        data_files[filename] = local_path
        success_count += 1

if success_count == 0:
    print("\n❌ ERROR: No files downloaded!")
    print("\nPossible causes:")
    print("  1. Spark analysis didn't run successfully")
    print("  2. Hadoop container not running")
    print("  3. Results not saved to /data/results/")
    print("\nSolution:")
    print("  Run Spark analysis again:")
    print("  docker exec -it hadoop-master bash")
    print("  spark-submit --master local[*] /tmp/spark_bruteforce_analysis.py")
    sys.exit(1)

print(f"\n✓ Downloaded {success_count}/{len(downloads)} files")

# ============================================================
# VISUALIZATION 1: Top Brute Force Attackers (5GB Data)
# ============================================================
print("\n[2] Creating Visualization 1: Top Brute Force Attackers (5GB)...")

try:
    df_brute = pd.read_csv(data_files['brute_force_ips.csv'])
    
    if df_brute.empty:
        print("⚠️  Warning: brute_force_ips.csv is empty!")
    else:
        plt.figure(figsize=(16, 10))
        top_20 = df_brute.head(20)
        
        colors = ['#d32f2f' if x > 1000 else '#f57c00' for x in top_20['failed_attempts']]
        
        plt.barh(range(len(top_20)), top_20['failed_attempts'], color=colors)
        plt.yticks(range(len(top_20)), top_20['ip_address'], fontsize=10)
        plt.xlabel('Failed Login Attempts', fontsize=13, fontweight='bold')
        plt.ylabel('IP Address', fontsize=13, fontweight='bold')
        plt.title('Top 20 Brute Force Attack Sources (5.8GB Dataset - 25M Auth Logs)', 
                  fontsize=15, fontweight='bold', pad=20)
        plt.gca().invert_yaxis()
        
        for i, v in enumerate(top_20['failed_attempts']):
            plt.text(v + (v*0.02), i, f'{v:,}', va='center', fontweight='bold', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'brute_force_attacks.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: brute_force_attacks.png")
        plt.close()
        
except Exception as e:
    print(f"✗ Error creating brute force chart: {e}")

# ============================================================
# VISUALIZATION 2: Most Targeted Usernames (Arabic Names)
# ============================================================
print("\n[3] Creating Visualization 2: Most Targeted Usernames (5GB)...")

try:
    df_users = pd.read_csv(data_files['targeted_users.csv'])
    
    if not df_users.empty:
        plt.figure(figsize=(14, 10))
        top_15 = df_users.head(15)
        
        plt.bar(range(len(top_15)), top_15['attack_count'], color='#1976d2', alpha=0.8)
        plt.xticks(range(len(top_15)), top_15['username'], rotation=45, ha='right', fontsize=10)
        plt.ylabel('Number of Attack Attempts', fontsize=13, fontweight='bold')
        plt.xlabel('Username', fontsize=13, fontweight='bold')
        plt.title('Most Targeted Usernames (5.8GB Dataset - Moroccan Names)', 
                  fontsize=15, fontweight='bold', pad=20)
        plt.grid(axis='y', alpha=0.3)
        
        for i, v in enumerate(top_15['attack_count']):
            plt.text(i, v + (v*0.02), f'{v:,}', ha='center', fontweight='bold', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'targeted_usernames.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: targeted_usernames.png")
        plt.close()
        
except Exception as e:
    print(f"✗ Error creating targeted users chart: {e}")

# ============================================================
# VISUALIZATION 3: Attack Patterns by Hour (5GB Data)
# ============================================================
print("\n[4] Creating Visualization 3: Attack Patterns by Hour (5GB)...")

try:
    df_hours = pd.read_csv(data_files['attacks_by_hour.csv'])
    
    if not df_hours.empty:
        df_hours = df_hours.sort_values('hour_of_day')
        
        plt.figure(figsize=(16, 8))
        
        plt.plot(df_hours['hour_of_day'], df_hours['attack_count'], 
                 marker='o', linewidth=3, markersize=10, color='#1976d2')
        plt.fill_between(df_hours['hour_of_day'], df_hours['attack_count'], alpha=0.3, color='#1976d2')
        
        plt.xlabel('Hour of Day (0-23)', fontsize=13, fontweight='bold')
        plt.ylabel('Number of Failed Login Attempts', fontsize=13, fontweight='bold')
        plt.title('Attack Patterns Throughout the Day (5.8GB Dataset)', 
                  fontsize=15, fontweight='bold', pad=20)
        plt.xticks(range(0, 24))
        plt.grid(alpha=0.3)
        
        plt.axvspan(0, 6, alpha=0.1, color='red', label='Night Hours (Peak Attacks)')
        plt.legend(fontsize=11)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'attacks_by_hour.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: attacks_by_hour.png")
        plt.close()
        
except Exception as e:
    print(f"✗ Error creating hourly attacks chart: {e}")

# ============================================================
# VISUALIZATION 4: Top Firewall Blocked IPs (5GB)
# ============================================================
print("\n[5] Creating Visualization 4: Top Firewall Attackers (5GB)...")

try:
    df_fw = pd.read_csv(data_files['top_attackers.csv'])
    
    if not df_fw.empty:
        plt.figure(figsize=(16, 10))
        top_20 = df_fw.head(20)
        
        plt.barh(range(len(top_20)), top_20['blocked_attempts'], color='#e91e63', alpha=0.8)
        plt.yticks(range(len(top_20)), top_20['src_ip'], fontsize=10)
        plt.xlabel('Blocked Connection Attempts', fontsize=13, fontweight='bold')
        plt.ylabel('Source IP Address', fontsize=13, fontweight='bold')
        plt.title('Top 20 IPs with Most Blocked Firewall Attempts (5.8GB Dataset - 15M Events)', 
                  fontsize=15, fontweight='bold', pad=20)
        plt.gca().invert_yaxis()
        
        for i, v in enumerate(top_20['blocked_attempts']):
            plt.text(v + (v*0.02), i, f"{v:,}", va='center', fontweight='bold', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'firewall_top_attackers.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: firewall_top_attackers.png")
        plt.close()
        
except Exception as e:
    print(f"✗ Error creating firewall chart: {e}")

# ============================================================
# VISUALIZATION 5: Most Targeted Ports (5GB)
# ============================================================
print("\n[6] Creating Visualization 5: Most Targeted Ports (5GB)...")

try:
    df_ports = pd.read_csv(data_files['targeted_ports.csv'])
    
    if not df_ports.empty:
        plt.figure(figsize=(14, 10))
        top_15 = df_ports.head(15)
        
        port_names = {
            '22': 'SSH', '80': 'HTTP', '443': 'HTTPS',
            '3306': 'MySQL', '8080': 'HTTP-ALT', '3389': 'RDP',
            '21': 'FTP', '25': 'SMTP', '53': 'DNS'
        }
        
        labels = [f"{row['dst_port']} ({port_names.get(str(row['dst_port']), 'Other')})" 
                  for _, row in top_15.iterrows()]
        
        plt.bar(range(len(top_15)), top_15['attack_count'], color='#ff9800', alpha=0.8)
        plt.xticks(range(len(top_15)), labels, rotation=45, ha='right', fontsize=10)
        plt.ylabel('Number of Attack Attempts', fontsize=13, fontweight='bold')
        plt.xlabel('Port (Service)', fontsize=13, fontweight='bold')
        plt.title('Most Targeted Ports (5.8GB Dataset - 15M Firewall Events)', 
                  fontsize=15, fontweight='bold', pad=20)
        plt.grid(axis='y', alpha=0.3)
        
        for i, v in enumerate(top_15['attack_count']):
            plt.text(i, v + (v*0.02), f"{v:,}", ha='center', fontweight='bold', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'targeted_ports.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: targeted_ports.png")
        plt.close()
        
except Exception as e:
    print(f"✗ Error creating ports chart: {e}")

# ============================================================
# VISUALIZATION 6: SQL Injection Attackers (5GB)
# ============================================================
print("\n[7] Creating Visualization 6: SQL Injection Attackers (5GB)...")

try:
    df_sql = pd.read_csv(data_files['sql_attackers.csv'])
    
    if not df_sql.empty:
        plt.figure(figsize=(16, 10))
        top_20 = df_sql.head(20)
        
        plt.barh(range(len(top_20)), top_20['injection_attempts'], color='#9c27b0', alpha=0.8)
        plt.yticks(range(len(top_20)), top_20['ip_address'], fontsize=10)
        plt.xlabel('SQL Injection Attempts', fontsize=13, fontweight='bold')
        plt.ylabel('IP Address', fontsize=13, fontweight='bold')
        plt.title('Top 20 SQL Injection Attackers (5.8GB Dataset - 10M Web Logs)', 
                  fontsize=15, fontweight='bold', pad=20)
        plt.gca().invert_yaxis()
        
        for i, v in enumerate(top_20['injection_attempts']):
            plt.text(v + (v*0.02), i, f'{v:,}', va='center', fontweight='bold', fontsize=9)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'sql_injection_attackers.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: sql_injection_attackers.png")
        plt.close()
        
except Exception as e:
    print(f"✗ Error creating SQL injection chart: {e}")

# ============================================================
# VISUALIZATION 7: HTTP Status Code Distribution (5GB)
# ============================================================
print("\n[8] Creating Visualization 7: HTTP Status Code Distribution (5GB)...")

try:
    df_status = pd.read_csv(data_files['status_distribution.csv'])
    
    if not df_status.empty:
        plt.figure(figsize=(12, 10))
        
        colors = ['#4caf50', '#2196f3', '#ff9800', '#f44336', '#9e9e9e']
        explode = [0.05 if x == df_status['count'].max() else 0 for x in df_status['count']]
        
        plt.pie(df_status['count'], labels=df_status['status_code'], autopct='%1.1f%%',
                colors=colors, explode=explode, startangle=90, 
                textprops={'fontsize': 13, 'fontweight': 'bold'})
        plt.title('HTTP Status Code Distribution (5.8GB Dataset - 10M Requests)', 
                  fontsize=15, fontweight='bold', pad=20)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'http_status_distribution.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: http_status_distribution.png")
        plt.close()
        
except Exception as e:
    print(f"✗ Error creating status distribution chart: {e}")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "="*70)
print("VISUALIZATION GENERATION COMPLETE!")
print("="*70)
print(f"\n📁 All charts saved to: {OUTPUT_DIR.absolute()}")
print("\n📊 Generated visualizations from 5.8GB dataset:")
print("  1. brute_force_attacks.png")
print("  2. targeted_usernames.png (Arabic/Moroccan names)")
print("  3. attacks_by_hour.png")
print("  4. firewall_top_attackers.png")
print("  5. targeted_ports.png")
print("  6. sql_injection_attackers.png")
print("  7. http_status_distribution.png")
print("\n✅ Ready for dashboard and report!")
print("="*70)