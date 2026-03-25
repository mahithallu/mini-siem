# Serverless Mini-SIEM Pipeline (AWS)

## Overview
This project simulates an enterprise Security Information and Event Management (SIEM) pipeline. It collects Linux authentication logs from an AWS EC2 instance, centralizes them in AWS CloudWatch, and triggers a serverless AWS Lambda function to detect suspicious login behavior (e.g., SSH brute force attacks). Alerts are enriched with threat intelligence and delivered in real-time via Amazon SNS.

## Architecture
1. **Telemetry:** AWS EC2 (Ubuntu) running the CloudWatch Agent.
2. **Ingestion:** AWS CloudWatch Logs (`/var/log/auth.log`).
3. **Detection:** AWS Lambda (Python) triggered by CloudWatch Log Subscriptions.
4. **Enrichment:** AbuseIPDB API for threat scoring.
5. **Alerting:** Amazon SNS for email notifications.

## Project Status & Roadmap

- [x] **Phase 1: Telemetry Collection**
  - Provisioned EC2 instance and configured IAM roles.
  - Deployed AWS CloudWatch Agent to stream `auth.log`.
- [ ] **Phase 2: Serverless Detection Logic**
  - Create Lambda function to parse logs.
  - Implement detection logic for repeated failed SSH attempts.
- [ ] **Phase 3: Alerting & Enrichment**
  - Integrate AbuseIPDB API for IP reputation scoring.
  - Configure SNS topic for real-time email alerts.
- [ ] **Phase 4: Attack Simulation**
  - Execute simulated SSH brute-force attacks using Hydra/Nmap to validate the pipeline.

## Repository Structure
* `/aws` - Configuration files for AWS services (CloudWatch agent, IAM policies).
* `/src` - Source code for AWS Lambda functions.
* `/scripts` - Attack simulation scripts.