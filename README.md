# Serverless Mini-SIEM Pipeline (AWS)

![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Splunk](https://img.shields.io/badge/splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

## Overview
This project is an end-to-end, serverless Security Information and Event Management (SIEM) pipeline built entirely on the AWS Free Tier. It simulates an enterprise Security Operations Center (SOC) environment by collecting Linux authentication telemetry, centralizing it via CloudWatch, and routing it through Python-based Lambda functions for real-time threat detection and log transformation. 

Malicious activity (e.g., SSH brute-force attempts) triggers automated SNS email alerts enriched with threat intelligence, while the transformed telemetry is streamed to a custom Splunk dashboard for visual investigation and threshold alerting.

## 🏗️ Architecture & Data Flow

1. **Telemetry Generation:** An Ubuntu EC2 honeypot generates SSH authentication logs (`/var/log/auth.log`).
2. **Ingestion:** The AWS CloudWatch Agent streams logs to a centralized `MiniSIEM-AuthLogs` Log Group.
3. **Fan-Out Routing (AWS Lambda):**
   * **Filter 1 (Threat Hunting):** A Python Lambda function parses logs for `Failed password` or `Invalid user`, counts threshold violations, queries the **AbuseIPDB API** for IP reputation, and publishes an **Amazon SNS** alert to the security team.
   * **Filter 2 (SIEM Routing):** A second Python Lambda decodes the base64/gzip CloudWatch payload, formats it into structured `_json`, and transmits it via HTTP POST to the Splunk instance.
4. **The SIEM Brain (Splunk):** Splunk Enterprise receives the data via an HTTPS Event Collector (HEC) on port 8088, indexing it for SPL queries, scheduled threshold alerts, and SOC visualization.

## ⚙️ Engineering & Resource Optimization
*A core objective of this project was executing an enterprise-grade pipeline within strict hardware constraints (AWS Free Tier).*

* **Compute Optimization:** Deployed Splunk Enterprise on a `t2.micro` (1GB RAM). Prevented Out-Of-Memory (OOM) kernel crashes by provisioning a 4GB Swap file and entirely disabling the MongoDB KV Store in `server.conf`.
* **Storage Engineering:** Bypassed Splunk's default 5GB minimum free space requirement (`minFreeSpace = 50`) to maintain ingestion on a limited 8GB EBS volume.
* **Query Efficiency:** Developed and verified all Search Processing Language (SPL) queries via the Linux CLI before committing them to the Web UI to preserve server RAM during dashboard rendering.

## 🚀 Project Status & Roadmap

- [x] **Phase 1: Telemetry Collection**
  - Provisioned EC2 honeypot and configured strict IAM roles.
  - Deployed AWS CloudWatch Agent to stream authentication logs.
- [x] **Phase 2: Serverless Detection Logic**
  - Developed Python Lambda function to parse SSH log strings.
  - Implemented logic for repeated failed SSH connection attempts.
- [x] **Phase 3: Alerting & Enrichment**
  - Integrated AbuseIPDB API for dynamic IP reputation scoring.
  - Configured Amazon SNS topic for real-time incident email alerts.
- [x] **Phase 4: Attack Simulation**
  - Executed simulated SSH brute-force attacks to validate pipeline execution.
- [x] **Phase 5: Splunk Infrastructure**
  - Provisioned secondary EC2 instance for Splunk Enterprise.
  - Configured HTTPS Event Collector (HEC) and `linux_auth` index.
- [x] **Phase 6: Log Transformation & Routing**
  - Built Python Lambda to decode CloudWatch base64/gzip payloads.
  - Implemented `urllib3` POST requests to route `_json` formatted logs to Splunk HEC.
- [x] **Phase 7: SIEM Dashboarding & Alerting**
  - Engineered SPL queries to extract attacker IPs and targeted usernames via Regex.
  - Built an interactive SOC-style dashboard with timecharts, IP drill-downs, and username investigations.
  - Configured automated Cron-scheduled threshold alerts (5+ failures in 60s).
- [X] **Phase 8: Incident Documentation**
  - Compile final architecture diagrams, Splunk dashboard screenshots, and incident response walkthroughs.

## 📂 Repository Structure
* `/aws` - Configuration files for AWS services (CloudWatch agent JSON, IAM trust policies).
* `/src` - Source code for AWS Lambda functions (`MiniSIEM-Detector` and `MiniSIEM-LogTransformation`).
* `/scripts` - Attack simulation scripts and Splunk CLI debug commands.
* `/docs` - Architecture diagrams and dashboard screenshots.