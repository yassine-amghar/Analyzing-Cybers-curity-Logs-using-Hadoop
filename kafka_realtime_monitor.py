"""
Fixed Kafka Monitor - Simplified and Working
Author: AMGHAR Yassine
"""

from kafka import KafkaConsumer
import json
import time
from datetime import datetime

print("="*70)
print("KAFKA REAL-TIME MONITOR (Fixed Version)")
print("="*70)
print("Connecting to Kafka...")

try:
    # Create consumer with minimal config
    consumer = KafkaConsumer(
        'cybersec-auth-logs',
        'cybersec-firewall-logs',
        'cybersec-web-logs',
        bootstrap_servers='localhost:9092',
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='monitor-group-' + str(int(time.time())),  # Unique group ID
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        # NO TIMEOUT - will wait forever for messages
    )
    print("✓ Connected to Kafka")
    print("✓ Subscribed to 3 topics")
    print("\nWaiting for messages... (Press Ctrl+C to stop)\n")
    
except Exception as e:
    print(f"✗ Connection failed: {e}")
    print("\nMake sure:")
    print("  1. Kafka is running: docker ps | grep kafka")
    print("  2. Topics exist: docker exec kafka kafka-topics --list --bootstrap-server localhost:9092")
    exit(1)

# Statistics
stats = {
    'total': 0,
    'auth': 0,
    'firewall': 0,
    'web': 0,
    'failed_logins': 0,
    'sql_injections': 0
}

start_time = time.time()

try:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Listening for events...\n")
    
    for message in consumer:
        stats['total'] += 1
        topic = message.topic
        data = message.value
        
        # Count by topic
        if 'auth' in topic:
            stats['auth'] += 1
            if data.get('status') == 'failed':
                stats['failed_logins'] += 1
                print(f"🚨 Failed login: {data.get('user')} from {data.get('ip')}")
        
        elif 'firewall' in topic:
            stats['firewall'] += 1
            if stats['firewall'] % 50 == 0:  # Print every 50th
                print(f"🛡️  Firewall: Blocked {stats['firewall']} connections")
        
        elif 'web' in topic:
            stats['web'] += 1
            if data.get('attack_type') == 'sql_injection':
                stats['sql_injections'] += 1
                print(f"💉 SQL Injection from {data.get('ip')}: {data.get('path')}")
        
        # Print stats every 100 events
        if stats['total'] % 100 == 0:
            elapsed = time.time() - start_time
            rate = stats['total'] / elapsed if elapsed > 0 else 0
            print(f"\n📊 [{datetime.now().strftime('%H:%M:%S')}] Stats:")
            print(f"   Total: {stats['total']} | Auth: {stats['auth']} | FW: {stats['firewall']} | Web: {stats['web']}")
            print(f"   Rate: {rate:.1f} events/sec | Failed logins: {stats['failed_logins']} | SQL: {stats['sql_injections']}\n")

except KeyboardInterrupt:
    print("\n\n⚠️  Stopped by user")

finally:
    elapsed = time.time() - start_time
    print("\n" + "="*70)
    print("FINAL STATISTICS")
    print("="*70)
    print(f"Total events: {stats['total']}")
    print(f"  - Auth: {stats['auth']}")
    print(f"  - Firewall: {stats['firewall']}")
    print(f"  - Web: {stats['web']}")
    print(f"\nFailed logins: {stats['failed_logins']}")
    print(f"SQL injections: {stats['sql_injections']}")
    print(f"\nDuration: {elapsed:.1f} seconds")
    if elapsed > 0:
        print(f"Average rate: {stats['total']/elapsed:.1f} events/sec")
    print("="*70)
    
    consumer.close()