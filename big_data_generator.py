"""
Full-Scale Cybersecurity Log Generator - 5GB Dataset
With Moroccan/Arabic usernames and Kafka streaming

Author: AMGHAR Yassine
École: La Cité des Métiers et des Compétences de Casa-Settat
Date: December 2025
"""

import random
import datetime
from pathlib import Path
import time
import json

# ============================================================================
# CONFIGURATION - 5GB Dataset
# ============================================================================

class Config:
    """Configuration for 5GB dataset generation"""
    
    OUTPUT_DIR = "bigdata_logs"
    
    # Target: 5GB total
    AUTH_LOGS_COUNT = 25_000_000      # ~2.5GB auth logs
    FIREWALL_LOGS_COUNT = 15_000_000  # ~1.5GB firewall logs
    WEB_LOGS_COUNT = 10_000_000       # ~1.0GB web logs
    
    # Time range: 6 months of realistic data
    START_DATE = datetime.datetime(2024, 7, 1, 0, 0, 0)
    END_DATE = datetime.datetime(2024, 12, 31, 23, 59, 59)
    
    # Attack patterns
    FAILED_LOGIN_RATE = 0.20
    BRUTE_FORCE_RATE = 0.08
    PORT_SCAN_RATE = 0.10
    SQL_INJECTION_RATE = 0.05
    
    # Performance
    BATCH_SIZE = 50_000
    PROGRESS_INTERVAL = 500_000

# ============================================================================
# MOROCCAN/ARABIC DATA SOURCES
# ============================================================================

class MoroccanDataSources:
    """Realistic Moroccan/Arabic usernames and data"""
    
    # Common Moroccan first names
    FIRST_NAMES = [
        # Male names
        'mohammed', 'ahmed', 'youssef', 'hassan', 'ali', 'omar', 'hamza',
        'mehdi', 'amine', 'rachid', 'karim', 'said', 'abdelilah', 'khalid',
        'hicham', 'mustapha', 'abderrahim', 'yassine', 'ayoub', 'bilal',
        'oussama', 'tarik', 'zakaria', 'marouane', 'othmane', 'ilyas',
        # Female names
        'fatima', 'khadija', 'aisha', 'hafsa', 'maryam', 'salma', 'sara',
        'nadia', 'karima', 'leila', 'samira', 'houda', 'amina', 'zineb',
        'imane', 'soundous', 'ikram', 'hanane', 'rajae', 'loubna'
    ]
    
    # Common Moroccan last names
    LAST_NAMES = [
        'alami', 'benali', 'el-idrissi', 'chennaoui', 'el-amrani', 'benjelloun',
        'el-fassi', 'tazi', 'sqalli', 'kettani', 'filali', 'andaloussi',
        'naciri', 'slaoui', 'tahiri', 'chraibi', 'lahlou', 'berrada',
        'mekouar', 'belkadi', 'lazrak', 'benabdellah', 'elmalki', 'bouazza',
        'el-mansouri', 'el-othmani', 'el-yazidi', 'essalhi', 'baraka',
        'lahrizi', 'zemrani', 'bennani', 'alaoui', 'hassani', 'kabbaj'
    ]
    
    # Generate full usernames (first.last format)
    USERNAMES = []
    for first in FIRST_NAMES[:30]:  # Use subset for variety
        for last in LAST_NAMES[:3]:  # 3 last names per first name
            USERNAMES.append(f"{first}.{last}")
    
    # Add system accounts (commonly attacked)
    USERNAMES.extend([
        'root', 'admin', 'administrator', 'user', 'guest', 'test',
        'backup', 'jenkins', 'gitlab', 'postgres', 'mysql', 'oracle',
        'apache', 'nginx', 'tomcat', 'www-data', 'ftp', 'webmaster'
    ])
    
    # Legitimate users (for successful logins) - Moroccan names
    LEGITIMATE_USERS = [
        'yassine.alami', 'fatima.benali', 'ahmed.el-idrissi', 'sara.chennaoui',
        'mohammed.el-amrani', 'khadija.benjelloun', 'omar.el-fassi', 'maryam.tazi',
        'hassan.sqalli', 'salma.kettani', 'ali.filali', 'aisha.andaloussi',
        'youssef.naciri', 'nadia.slaoui', 'hamza.tahiri', 'leila.chraibi',
        'backup', 'jenkins', 'gitlab', 'it_admin', 'dev_user'
    ]
    
    # Attack IPs (500 malicious IPs from various countries)
    ATTACK_IPS = []
    # Chinese ranges
    ATTACK_IPS.extend([f"218.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(100)])
    # Russian ranges
    ATTACK_IPS.extend([f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(100)])
    # Vietnamese ranges
    ATTACK_IPS.extend([f"14.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(50)])
    # Brazilian ranges
    ATTACK_IPS.extend([f"177.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(50)])
    # Other ranges
    ATTACK_IPS.extend([f"{random.choice([45,91,103,123])}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(200)])
    
    # Internal Moroccan network IPs
    INTERNAL_IPS = []
    INTERNAL_IPS.extend([f"192.168.1.{i}" for i in range(1, 255)])
    INTERNAL_IPS.extend([f"10.0.0.{i}" for i in range(1, 255)])
    INTERNAL_IPS.extend([f"172.16.0.{i}" for i in range(1, 255)])
    
    # External legitimate IPs
    EXTERNAL_IPS = [f"203.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(500)]
    
    # Services
    SERVICES = ['sshd', 'vsftpd', 'httpd', 'mysqld', 'systemd', 'nginx', 'apache2']
    
    # Ports
    COMMON_PORTS = [22, 80, 443, 21, 25, 110, 143, 3306, 5432, 8080]
    ATTACK_PORTS = list(range(1, 1025))
    
    # Web paths
    WEB_PATHS = [
        '/', '/index.html', '/about', '/contact', '/products', '/services',
        '/api/v1/users', '/api/v1/auth', '/api/v1/data',
        '/admin', '/admin/login', '/wp-admin', '/phpmyadmin',
        '/login', '/signin', '/auth', '/dashboard', '/profile'
    ]
    
    # SQL Injections
    SQL_INJECTIONS = [
        "' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--",
        "1' AND '1'='1", "'; DROP TABLE users--", "' OR 'a'='a"
    ]
    
    # User agents
    LEGITIMATE_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
    
    ATTACK_AGENTS = [
        'python-requests/2.28.0', 'sqlmap/1.6', 'Nmap Scripting Engine',
        'Nikto/2.1.6', 'masscan/1.0.5'
    ]

# ============================================================================
# LOG GENERATORS
# ============================================================================

class AuthLogGenerator:
    def __init__(self, config, data):
        self.config = config
        self.data = data
        self.start_ts = config.START_DATE.timestamp()
        self.end_ts = config.END_DATE.timestamp()
    
    def random_timestamp(self):
        ts = random.uniform(self.start_ts, self.end_ts)
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    
    def generate_successful_login(self):
        timestamp = self.random_timestamp()
        user = random.choice(self.data.LEGITIMATE_USERS)
        ip = random.choice(self.data.INTERNAL_IPS + self.data.EXTERNAL_IPS)
        port = random.choice([22, 3389])
        pid = random.randint(1000, 99999)
        return f"{timestamp} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2\n"
    
    def generate_failed_login(self):
        timestamp = self.random_timestamp()
        user = random.choice(self.data.USERNAMES)
        ip = random.choice(self.data.ATTACK_IPS + self.data.EXTERNAL_IPS)
        port = random.choice([22, 3389])
        pid = random.randint(1000, 99999)
        return f"{timestamp} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2\n"
    
    def generate_brute_force(self):
        attacker_ip = random.choice(self.data.ATTACK_IPS)
        base_time = random.uniform(self.start_ts, self.end_ts)
        logs = []
        
        attempts = random.randint(100, 500)
        for i in range(attempts):
            offset = random.uniform(0, 1800)
            timestamp = datetime.datetime.fromtimestamp(base_time + offset)
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            user = random.choice(self.data.USERNAMES[:20])
            pid = random.randint(1000, 99999)
            logs.append(f"{timestamp_str} sshd[{pid}]: Failed password for {user} from {attacker_ip} port 22 ssh2\n")
        
        return logs
    
    def generate_batch(self, count):
        logs = []
        brute_force_count = int(count * self.config.BRUTE_FORCE_RATE)
        failed_count = int(count * self.config.FAILED_LOGIN_RATE)
        success_count = count - brute_force_count - failed_count
        
        for _ in range(brute_force_count // 200):
            logs.extend(self.generate_brute_force())
        
        for _ in range(failed_count):
            logs.append(self.generate_failed_login())
        
        for _ in range(success_count):
            logs.append(self.generate_successful_login())
        
        return logs

class FirewallLogGenerator:
    def __init__(self, config, data):
        self.config = config
        self.data = data
        self.start_ts = config.START_DATE.timestamp()
        self.end_ts = config.END_DATE.timestamp()
    
    def random_timestamp(self):
        ts = random.uniform(self.start_ts, self.end_ts)
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    
    def generate_blocked_connection(self):
        timestamp = self.random_timestamp()
        src_ip = random.choice(self.data.ATTACK_IPS + self.data.EXTERNAL_IPS)
        dst_ip = random.choice(self.data.INTERNAL_IPS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.data.COMMON_PORTS)
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
        return f"{timestamp} FIREWALL BLOCK {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
    
    def generate_port_scan(self):
        attacker_ip = random.choice(self.data.ATTACK_IPS)
        target_ip = random.choice(self.data.INTERNAL_IPS)
        base_time = random.uniform(self.start_ts, self.end_ts)
        logs = []
        
        ports_to_scan = random.sample(self.data.ATTACK_PORTS, random.randint(100, 1000))
        for port in ports_to_scan:
            offset = random.uniform(0, 120)
            timestamp = datetime.datetime.fromtimestamp(base_time + offset)
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            src_port = random.randint(1024, 65535)
            logs.append(f"{timestamp_str} FIREWALL BLOCK TCP {attacker_ip}:{src_port} -> {target_ip}:{port}\n")
        
        return logs
    
    def generate_batch(self, count):
        logs = []
        port_scan_count = int(count * self.config.PORT_SCAN_RATE)
        blocked_count = count - port_scan_count
        
        for _ in range(port_scan_count // 500):
            logs.extend(self.generate_port_scan())
        
        for _ in range(blocked_count):
            logs.append(self.generate_blocked_connection())
        
        return logs

class WebLogGenerator:
    def __init__(self, config, data):
        self.config = config
        self.data = data
        self.start_ts = config.START_DATE.timestamp()
        self.end_ts = config.END_DATE.timestamp()
    
    def random_timestamp(self):
        ts = random.uniform(self.start_ts, self.end_ts)
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    
    def generate_normal_request(self):
        timestamp = self.random_timestamp()
        ip = random.choice(self.data.EXTERNAL_IPS + self.data.INTERNAL_IPS)
        method = random.choice(['GET', 'GET', 'GET', 'POST'])
        path = random.choice(self.data.WEB_PATHS)
        status = random.choice([200, 200, 200, 304, 404])
        size = random.randint(200, 50000)
        agent = random.choice(self.data.LEGITIMATE_AGENTS)
        return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"\n'
    
    def generate_sql_injection(self):
        timestamp = self.random_timestamp()
        ip = random.choice(self.data.ATTACK_IPS)
        method = 'GET'
        path = random.choice(self.data.WEB_PATHS)
        injection = random.choice(self.data.SQL_INJECTIONS)
        path_with_injection = f"{path}?id={injection}"
        status = random.choice([403, 500, 400])
        size = random.randint(100, 5000)
        agent = random.choice(self.data.ATTACK_AGENTS)
        return f'{ip} - - [{timestamp}] "{method} {path_with_injection} HTTP/1.1" {status} {size} "-" "{agent}"\n'
    
    def generate_batch(self, count):
        logs = []
        sql_count = int(count * self.config.SQL_INJECTION_RATE)
        normal_count = count - sql_count
        
        for _ in range(sql_count):
            logs.append(self.generate_sql_injection())
        
        for _ in range(normal_count):
            logs.append(self.generate_normal_request())
        
        return logs

# ============================================================================
# MAIN GENERATOR
# ============================================================================

class FullScaleGenerator:
    def __init__(self):
        self.config = Config()
        self.data = MoroccanDataSources()
        self.output_dir = Path(self.config.OUTPUT_DIR)
        self.output_dir.mkdir(exist_ok=True)
        
        self.auth_gen = AuthLogGenerator(self.config, self.data)
        self.firewall_gen = FirewallLogGenerator(self.config, self.data)
        self.web_gen = WebLogGenerator(self.config, self.data)
    
    def write_logs(self, logs, filepath):
        with open(filepath, 'a') as f:
            f.writelines(logs)
    
    def generate_auth_logs(self):
        print("\n" + "="*70)
        print("GENERATING AUTHENTICATION LOGS (~2.5GB)")
        print("="*70)
        
        filepath = self.output_dir / "auth_logs.log"
        total = self.config.AUTH_LOGS_COUNT
        generated = 0
        start_time = time.time()
        
        while generated < total:
            batch_size = min(self.config.BATCH_SIZE, total - generated)
            logs = self.auth_gen.generate_batch(batch_size)
            self.write_logs(logs, filepath)
            generated += len(logs)
            
            if generated % self.config.PROGRESS_INTERVAL == 0:
                elapsed = time.time() - start_time
                progress = (generated / total) * 100
                rate = generated / elapsed if elapsed > 0 else 0
                eta = (total - generated) / rate if rate > 0 else 0
                
                print(f"Progress: {generated:,} / {total:,} ({progress:.1f}%) | "
                      f"Rate: {rate:,.0f} logs/sec | ETA: {eta/60:.1f} min")
        
        elapsed_total = time.time() - start_time
        size_mb = filepath.stat().st_size / (1024 * 1024)
        print(f"✓ Completed in {elapsed_total/60:.1f} minutes | Size: {size_mb:.1f} MB")
    
    def generate_firewall_logs(self):
        print("\n" + "="*70)
        print("GENERATING FIREWALL LOGS (~1.5GB)")
        print("="*70)
        
        filepath = self.output_dir / "firewall_logs.log"
        total = self.config.FIREWALL_LOGS_COUNT
        generated = 0
        start_time = time.time()
        
        while generated < total:
            batch_size = min(self.config.BATCH_SIZE, total - generated)
            logs = self.firewall_gen.generate_batch(batch_size)
            self.write_logs(logs, filepath)
            generated += len(logs)
            
            if generated % self.config.PROGRESS_INTERVAL == 0:
                elapsed = time.time() - start_time
                progress = (generated / total) * 100
                rate = generated / elapsed if elapsed > 0 else 0
                eta = (total - generated) / rate if rate > 0 else 0
                
                print(f"Progress: {generated:,} / {total:,} ({progress:.1f}%) | "
                      f"Rate: {rate:,.0f} logs/sec | ETA: {eta/60:.1f} min")
        
        elapsed_total = time.time() - start_time
        size_mb = filepath.stat().st_size / (1024 * 1024)
        print(f"✓ Completed in {elapsed_total/60:.1f} minutes | Size: {size_mb:.1f} MB")
    
    def generate_web_logs(self):
        print("\n" + "="*70)
        print("GENERATING WEB SERVER LOGS (~1.0GB)")
        print("="*70)
        
        filepath = self.output_dir / "web_logs.log"
        total = self.config.WEB_LOGS_COUNT
        generated = 0
        start_time = time.time()
        
        while generated < total:
            batch_size = min(self.config.BATCH_SIZE, total - generated)
            logs = self.web_gen.generate_batch(batch_size)
            self.write_logs(logs, filepath)
            generated += len(logs)
            
            if generated % self.config.PROGRESS_INTERVAL == 0:
                elapsed = time.time() - start_time
                progress = (generated / total) * 100
                rate = generated / elapsed if elapsed > 0 else 0
                eta = (total - generated) / rate if rate > 0 else 0
                
                print(f"Progress: {generated:,} / {total:,} ({progress:.1f}%) | "
                      f"Rate: {rate:,.0f} logs/sec | ETA: {eta/60:.1f} min")
        
        elapsed_total = time.time() - start_time
        size_mb = filepath.stat().st_size / (1024 * 1024)
        print(f"✓ Completed in {elapsed_total/60:.1f} minutes | Size: {size_mb:.1f} MB")
    
    def generate_metadata(self):
        metadata = {
            'project': 'Cybersecurity Log Analysis - Big Data',
            'author': 'AMGHAR Yassine',
            'school': 'La Cité des Métiers et des Compétences de Casa-Settat',
            'generation_date': datetime.datetime.now().isoformat(),
            'date_range': {
                'start': self.config.START_DATE.isoformat(),
                'end': self.config.END_DATE.isoformat(),
            },
            'log_counts': {
                'authentication': self.config.AUTH_LOGS_COUNT,
                'firewall': self.config.FIREWALL_LOGS_COUNT,
                'web_server': self.config.WEB_LOGS_COUNT,
                'total': 50_000_000
            },
            'usernames': 'Moroccan/Arabic names',
            'technologies': ['HDFS', 'Spark', 'MapReduce', 'Python']
        }
        
        with open(self.output_dir / "dataset_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def run(self):
        print("\n" + "="*70)
        print("FULL-SCALE DATA GENERATOR - 5GB DATASET")
        print("="*70)
        print(f"Author: AMGHAR Yassine")
        print(f"School: La Cité des Métiers et des Compétences de Casa-Settat")
        print(f"Output: {self.output_dir.absolute()}")
        print(f"Target: ~5GB (50 million logs)")
        print(f"Usernames: Moroccan/Arabic names")
        print("="*70)
        
        overall_start = time.time()
        
        self.generate_auth_logs()
        self.generate_firewall_logs()
        self.generate_web_logs()
        self.generate_metadata()
        
        overall_time = time.time() - overall_start
        
        print("\n" + "="*70)
        print("GENERATION COMPLETE!")
        print("="*70)
        print(f"Total time: {overall_time/60:.1f} minutes")
        
        total_size = 0
        for file in self.output_dir.glob("*.log"):
            size_mb = file.stat().st_size / (1024 * 1024)
            total_size += size_mb
            print(f"  - {file.name}: {size_mb:.1f} MB")
        
        print(f"\nTotal: {total_size:.1f} MB ({total_size/1024:.2f} GB)")
        print("="*70)
        print("\n✅ Ready for HDFS upload!")

if __name__ == "__main__":
    try:
        generator = FullScaleGenerator()
        generator.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()