# Serverless Mini-SIEM Pipeline (AWS)

## Overview
This project simulates an enterprise Security Information and Event Management (SIEM) pipeline. It collects Linux authentication logs from an AWS EC2 instance, centralizes them in AWS CloudWatch, and triggers a serverless AWS Lambda function to detect suspicious login behavior (e.g., SSH brute force attacks). Alerts are enriched with threat intelligence and delivered in real-time via Amazon SNS.

## Architecture
1. **Telemetry:** AWS EC2 (Ubuntu) running the CloudWatch Agent.
2. **Ingestion:** AWS CloudWatch Logs (`/var/log/auth.log`).
3. **Detection:** AWS Lambda (Python) triggered by CloudWatch Log Subscriptions.
4. **Enrichment:** AbuseIPDB API for threat scoring.
5. **Alerting:** Amazon SNS for email notifications.
6. **Integrating:** Splunk for data ingestion and field extraction.
7. **Onboarding:** Creating a SIEM dashboard to display all results.

## Project Status & Roadmap

- [x] **Phase 1: Telemetry Collection**
  - Provisioned EC2 instance and configured IAM roles.
  - Deployed AWS CloudWatch Agent to stream `auth.log`.
- [x] **Phase 2: Serverless Detection Logic**
  - Create Lambda function to parse logs.
  - Implement detection logic for repeated failed SSH attempts.
- [x] **Phase 3: Alerting & Enrichment**
  - Integrate AbuseIPDB API for IP reputation scoring.
  - Configure SNS topic for real-time email alerts.
- [x] **Phase 4: Attack Simulation**
  - Execute simulated SSH brute-force attacks using Hydra/Nmap to validate the pipeline.
  - Write Bash scripts to verify brute-force attacks, port scan, and invalid spam user attempts.
- [x] **Phase 5: Splunk Integration**
  - Integrate Splunk to configure ingestion via Firehose.
  - Ensure JSON parsing and field extraction using certain fields.
- [x] **Phase 6: AWS Lambda Routing**
  - Configure S3 Event triggers on .log object creation & develop log transformation logic.
  - Implement HEC Post Request and establish error handling.
- [] **Phase 7: SIEM Dashboarding**
  - Execute simulated SSH brute-force attacks using Hydra/Nmap to validate the pipeline.
- [X] **Ongoing Phase**
  - Maintain structured repo layout and have a ReadME.md set up with usage.

## Repository Structure
* `/aws` - Configuration files for AWS services (CloudWatch agent, IAM policies).
* `/src` - Source code for AWS Lambda functions.
* `/scripts` - Attack simulation scripts.