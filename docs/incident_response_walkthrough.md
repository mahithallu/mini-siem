# Security Incident Response Walkthrough: SSH Brute Force Campaign

## 📖 Incident Summary
On **04/12/2026**, the automated SIEM pipeline successfully detected, mitigated, and logged a simulated SSH brute-force attack targeting the AWS EC2 honeypot. The pipeline successfully identified the threat actor's IP, evaluated the reputation via AbuseIPDB, fired a real-time SNS email alert, and indexed the telemetry in Splunk for forensic investigation.
---

## 🛑 Phase 1: The Attack Vector
A simulated attack cluster was launched against the public-facing EC2 instance (`MiniSIEM-Target`) using an automated bash script (`brute_force_sim.sh`). The script rapidly cycled through high-value default usernames (`root`, `superadmin`, `fakeuser`) utilizing SSH Batch Mode to bypass interactive prompts and generate immediate connection failures.

* **Target Port:** TCP 22 (SSH)
* **Threshold Triggered:** > 5 failed attempts within 60 seconds.
![alt text](<VirtualBox Kali Linux Script Running.png>)
---

## ⚙️ Phase 2: Automated Detection & Routing
The AWS CloudWatch agent installed on the honeypot instantly captured the failed authentication logs from `/var/log/auth.log` and streamed them to the `MiniSIEM-AuthLogs` log group. This triggered a fan-out serverless response via AWS Lambda.

1. **The Transformation Lambda:** Decoded the base64/gzip CloudWatch payload, structured the raw string into a `_json` format, and executed a secure HTTP POST request to route the data to the Splunk HTTPS Event Collector (HEC).
2. **The Detection Lambda:** Parsed the log strings for `Failed password` or `Invalid user` indicators. 

![alt text](<CloudWatch Logs.png>)
---

## 🚨 Phase 3: Alert Generation
Upon calculating that the threat actor exceeded the configured threshold, the Detection Lambda queried the **AbuseIPDB API** to check the attacker's reputation score. The Lambda then published a payload to **Amazon SNS**, which delivered a real-time alert to the designated SOC Analyst inbox.

![alt text](<AWS SNS Email.jpg>)
---

## 🔍 Phase 4: SIEM Investigation & Verification
Following the email alert, the SOC Analyst logged into the Splunk Enterprise instance to verify the extent of the attack using the **SOC Authentication View** dashboard.

* **Top Attacker IPs:** Visualized as a pie chart, instantly identifying the dominant rogue IP.
* **Targeted Usernames:** Visualized as a bar chart, confirming the attacker was attempting to breach the `superadmin` and `fakeuser` accounts.
* **Drill-Down Analysis:** Clicking the attacker's IP on the dashboard executed an automated investigation query (`index="linux_auth" sshd src_ip=$click.value$`), revealing the exact timestamps and raw log strings of the campaign.

![alt text](<SOC Authentication View Dashboard.png>)
---

## ✅ Conclusion
The serverless architecture successfully handled the burst of log traffic, demonstrating zero dropped packets during the log transformation phase. Splunk effectively visualized the threat landscape within seconds of the initial attack, proving the viability of this lightweight, cloud-native SIEM model.