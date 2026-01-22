# Analyzing-Cybersecurity-Logs-using-Hadoop
The project addresses the challenge of processing and analyzing massive volumes of security logs to detect intrusion attempts and attack patterns in real-time. Traditional tools cannot handle the scale, velocity, and variety of modern cybersecurity data.
Project Scale

Data Volume: 5.8 GB of logs
Events Processed: 50 million events
Time Period Simulated: 6 months of system activity (July-December 2024)
Processing Time: Less than 30 minutes for complete analysis

Key Technologies Used
Storage & Processing:

Hadoop HDFS - Distributed file storage with 2x replication
Apache Spark - In-memory parallel processing
MapReduce - Traditional batch processing
Apache Kafka - Real-time streaming (demonstration)

Development:

Python/PySpark - Script development and data generation
Docker - Containerized cluster environment

Architecture
Cluster Setup:

NameNode (hadoop-master) - Metadata management and Spark Master
DataNodes (worker1, worker2) - Distributed data storage
Kafka + Zookeeper - Streaming infrastructure

The project implements a simplified Lambda Architecture combining batch and real-time processing.
Types of Logs Analyzed

Authentication Logs (SSH) - 25 million events (~2.5 GB)

Failed login attempts
Successful connections


Firewall Logs - 15 million events (~1.5 GB)

Blocked TCP/UDP packets
Network scanning activity


Web Server Logs - 10 million events (~1 GB)

HTTP requests
SQL injection attempts



Attack Patterns Detected

Brute Force Attacks

~10 million failed login attempts detected
~500 attacking IP sources identified
Some IPs with 250,000+ attempts
Represents 8% of authentication logs


Port Scanning

Detected in 10% of firewall logs
IPs scanning 100-1000 ports in 1-2 minutes
Reconnaissance phase before targeted attacks


SQL Injection Attempts

~650,000 injection attempts detected
5% of web logs contain malicious payloads
Patterns: ' OR '1'='1, UNION SELECT, DROP TABLE
Associated with suspicious user-agents (sqlmap, nikto)



Key Results
Detection Capabilities:

Identified 487 distinct brute force attack sources
Detected coordinated attacks from multiple IPs
Mapped most targeted usernames and ports
Analyzed HTTP error code distributions

Performance Metrics:

Spark processing: 8-10 minutes per analysis type
Data generation: ~30 minutes for 5.8 GB
HDFS upload: 5-10 minutes per file type
Real-time processing: ~100 events/second via Kafka

Project Methodology (5 Phases)

Realistic Data Generation - Simulating normal and malicious behaviors
Distributed Storage in HDFS - Fault-tolerant data management
Batch Processing - Using Spark and MapReduce for historical analysis
Real-time Streaming - Kafka demonstration for live detection
Visualization & Analysis - Dashboards and actionable insights

Technical Achievements

Successfully processed 50 million events in a distributed environment
Implemented regex-based parsing for log analysis
Created statistical sampling methods for data validation
Generated realistic Moroccan usernames and geolocated IPs
Produced comprehensive visualizations showing:

Top attacking IPs
Most targeted users and ports
Temporal attack patterns
HTTP status code distributions



Security Recommendations Provided
Based on analysis results, the project generates actionable security recommendations such as:

Blocking suspicious IP addresses
Strengthening authentication policies
Improving firewall rules
Identifying critical vulnerabilities

Future Enhancements Suggested

Full Kafka integration for real-time ingestion
Machine Learning models for automated anomaly detection
Interactive dashboards for result visualization
Expanded attack pattern library

This project demonstrates the practical application of Big Data technologies to cybersecurity challenges, showing how distributed computing frameworks can transform massive volumes of raw log data into actionable security intelligence.
