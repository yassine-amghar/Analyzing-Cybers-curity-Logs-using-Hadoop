"""
Kafka Streaming Log Generator - Real-Time Demo
Generates logs AND streams them to Kafka simultaneously

Author: AMGHAR Yassine
Date: January 2026

This demonstrates real-time Big Data streaming!
Run kafka_realtime_monitor.py in another terminal to see live results.
"""

import random
import datetime
import json
import time
from kafka import KafkaProducer
from kafka.errors import KafkaError

class KafkaStreamingDemo:
    """Generate and stream logs in real-time to Kafka"""
    
    def __init__(self):
        # Kafka producer
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=['localhost:9092'],
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                compression_type='gzip'
            )
            print("✓ Connected to Kafka at localhost:9092")
        except Exception as e:
            print(f"❌ Cannot connect to Kafka: {e}")
            print("   Make sure Kafka is running: docker ps | grep kafka")
            raise
        
        # Moroccan usernames
        self.usernames = [
            'yassine.alami', 'fatima.benali', 'ahmed.el-idrissi', 'sara.chennaoui',
            'mohammed.el-amrani', 'khadija.benjelloun', 'omar.el-fassi', 'maryam.tazi',
            'hassan.sqalli', 'salma.kettani', 'root', 'admin', 'test', 'user'
        ]
        
        # Attack IPs
        self.attack_ips = [
            f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            for _ in range(50)
        ]
        
        # Internal IPs
        self.internal_ips = [f"192.168.1.{i}" for i in range(1, 100)]
        
        # Stats
        self.stats = {
            'auth_events': 0,
            'firewall_events': 0,
            'web_events': 0,
            'start_time': time.time()
        }
    
    def generate_auth_event(self):
        """Generate authentication event"""
        timestamp = datetime.datetime.now().isoformat()
        
        # 30% failed, 70% success
        if random.random() < 0.3:
            status = 'failed'
            ip = random.choice(self.attack_ips)
            user = random.choice(self.usernames)
        else:
            status = 'success'
            ip = random.choice(self.internal_ips)
            user = random.choice(self.usernames[:8])  # Legitimate users
        
        event = {
            'timestamp': timestamp,
            'status': status,
            'user': user,
            'ip': ip,
            'port': 22
        }
        
        # Send to Kafka
        self.producer.send('cybersec-auth-logs', value=event)
        self.stats['auth_events'] += 1
        
        return event
    
    def generate_firewall_event(self):
        """Generate firewall event"""
        timestamp = datetime.datetime.now().isoformat()
        
        event = {
            'timestamp': timestamp,
            'action': 'block',
            'protocol': random.choice(['TCP', 'UDP']),
            'src_ip': random.choice(self.attack_ips),
            'dst_ip': random.choice(self.internal_ips),
            'dst_port': random.choice([22, 80, 443, 3306])
        }
        
        # Send to Kafka
        self.producer.send('cybersec-firewall-logs', value=event)
        self.stats['firewall_events'] += 1
        
        return event
    
    def generate_web_event(self):
        """Generate web event"""
        timestamp = datetime.datetime.now().isoformat()
        
        # 10% SQL injection
        if random.random() < 0.1:
            attack_type = 'sql_injection'
            ip = random.choice(self.attack_ips)
            path = f"/login?id=' OR '1'='1"
            status = 403
        else:
            attack_type = 'normal'
            ip = random.choice(self.internal_ips + self.attack_ips)
            path = random.choice(['/', '/api/users', '/dashboard', '/products'])
            status = 200
        
        event = {
            'timestamp': timestamp,
            'attack_type': attack_type,
            'ip': ip,
            'path': path,
            'status': status
        }
        
        # Send to Kafka
        self.producer.send('cybersec-web-logs', value=event)
        self.stats['web_events'] += 1
        
        return event
    
    def print_stats(self):
        """Print current statistics"""
        elapsed = time.time() - self.stats['start_time']
        total = self.stats['auth_events'] + self.stats['firewall_events'] + self.stats['web_events']
        rate = total / elapsed if elapsed > 0 else 0
        
        print(f"\r📊 Streaming: {total:,} events | "
              f"Auth: {self.stats['auth_events']:,} | "
              f"FW: {self.stats['firewall_events']:,} | "
              f"Web: {self.stats['web_events']:,} | "
              f"Rate: {rate:.1f}/sec", end='', flush=True)
    
    def run_demo(self, duration_seconds=300):
        """Run streaming demo for specified duration"""
        print("\n" + "="*70)
        print("KAFKA REAL-TIME STREAMING DEMO")
        print("="*70)
        print("Author: AMGHAR Yassine")
        print(f"Duration: {duration_seconds} seconds ({duration_seconds/60:.1f} minutes)")
        print("Kafka: localhost:9092")
        print("\n🎯 Open another terminal and run:")
        print("   python kafka_realtime_monitor.py")
        print("\nGenerating and streaming events... (Press Ctrl+C to stop)")
        print("="*70 + "\n")
        
        end_time = time.time() + duration_seconds
        last_stats_print = time.time()
        
        try:
            while time.time() < end_time:
                # Generate random events
                event_type = random.choices(
                    ['auth', 'firewall', 'web'],
                    weights=[0.5, 0.3, 0.2]  # 50% auth, 30% firewall, 20% web
                )[0]
                
                if event_type == 'auth':
                    self.generate_auth_event()
                elif event_type == 'firewall':
                    self.generate_firewall_event()
                else:
                    self.generate_web_event()
                
                # Print stats every second
                if time.time() - last_stats_print >= 1:
                    self.print_stats()
                    last_stats_print = time.time()
                
                # Small delay to control rate (100 events/sec)
                time.sleep(0.01)
            
            print("\n\n✅ Demo completed!")
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Demo stopped by user")
        
        finally:
            self.producer.flush()
            self.producer.close()
            
            elapsed = time.time() - self.stats['start_time']
            total = self.stats['auth_events'] + self.stats['firewall_events'] + self.stats['web_events']
            
            print("\n" + "="*70)
            print("STREAMING DEMO SUMMARY")
            print("="*70)
            print(f"Total events streamed: {total:,}")
            print(f"  - Auth events: {self.stats['auth_events']:,}")
            print(f"  - Firewall events: {self.stats['firewall_events']:,}")
            print(f"  - Web events: {self.stats['web_events']:,}")
            print(f"Duration: {elapsed:.1f} seconds")
            print(f"Average rate: {total/elapsed:.1f} events/sec")
            print("="*70)
            print("\n✅ Data streamed to Kafka topics:")
            print("   - cybersec-auth-logs")
            print("   - cybersec-firewall-logs")
            print("   - cybersec-web-logs")

def main():
    """Main function"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║       KAFKA REAL-TIME LOG STREAMING DEMONSTRATION                ║
║                                                                  ║
║  This demonstrates Big Data streaming using Apache Kafka         ║
║  Run kafka_realtime_monitor.py in another terminal to watch!     ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    import sys
    
    # Get duration from command line or use default
    duration = 300  # 5 minutes default
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except:
            print("Usage: python kafka_streaming_demo.py [duration_seconds]")
            print(f"Using default: {duration} seconds")
    
    try:
        demo = KafkaStreamingDemo()
        demo.run_demo(duration_seconds=duration)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("  1. Make sure Kafka is running:")
        print("     docker ps | grep kafka")
        print("  2. Make sure topics are created:")
        print("     docker exec kafka kafka-topics --list --bootstrap-server localhost:9092")
        print("  3. Install kafka-python:")
        print("     pip install kafka-python")

if __name__ == "__main__":
    main()