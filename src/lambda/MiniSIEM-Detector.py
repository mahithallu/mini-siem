#Step 1: Import necessary modules
import base64
import gzip
import json
import re
import os
import urllib.request
import urllib.parse
import boto3
from collections import defaultdict
import time
from datetime import datetime, timezone

failed_attempts = defaultdict(list)

def get_abuse_score(ip_address):
    #API KEY from AbuseIPDB
    api_key = os.environ['ABUSEIPDB_API_KEY']
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    req = urllib.request.Request(url, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            # AbuseIPDB returns a score from 0 to 100
            score = data['data']['abuseConfidenceScore']
            return score
    except Exception as e:
        print(f"Error querying AbuseIPDB: {e}")
        return None


#Uses SNS to send alert
def send_alert(ip_address, score, rule_name, event_type, username, attempt_count, timestamp):
    sns_client = boto3.client('sns')
    topic_arn = os.environ['SNS_TOPIC_ARN']
    
    # Format the message body
    message = (
    f"🚨 MINI-SIEM ALERT 🚨\n\n"
    f"Rule Triggered: {rule_name}\n"
    f"Event Type: {event_type}\n"
    f"Source IP: {ip_address}\n"
    f"Username: {username}\n"
    f"Attempts (last 60s): {attempt_count}\n"
    f"Threat Score: {score if score is not None else 'N/A'}/100\n\n"
    f"Timestamp: {timestamp}\n"
    f"Recommended Action: Investigate IP activity and consider blocking if malicious."

    )
    
    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Subject=f"Security Alert: {rule_name} from {ip_address}",
            Message=message
        )
        print(f"Alert sent to SNS! Message ID: {response['MessageId']}")
    except Exception as e:
        print(f"Error sending SNS alert: {e}")



def lambda_handler(event, context):
    #Step 2: Unpack the payload

    #Extract Data Payload from event['awslogs]['data]
    extractedDataPayload = event['awslogs']['data']
    #Decode Base64 encoded data into bytes
    decodedBytes = base64.b64decode(extractedDataPayload)
    #Decompress bytes into readable string
    json_bytes = gzip.decompress(decodedBytes)
    json_string = json_bytes.decode('utf-8')
    #Load Unzipped string into Python Dictionary using JSON module
    data = json.loads(json_string)

    #Defaulting to an empty list
    logEvents = data.get('logEvents', [])

    #Step 3: Hunt for Threat
    #Loop to iterate through each item in logEvents
    for item in logEvents:
        #Extract message from current event
        message = item.get('message', '')
        timestamp = item.get('timestamp')
        readable_timestamp = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).isoformat()
        current_time = time.time()

        #Check if string exists in message
        if "Failed password for invalid user" in message:
            event_type = "invalid_user_failed_password"
            status = "failure"
        elif "Failed password" in message:
            event_type = "failed_password"
            status = "failure"
        elif "Invalid user" in message:
            event_type = "invalid_user"
            status = "failure"
        elif "Accepted publickey" in message or "Accepted password" in message:
            event_type = "login_success"
            status = "success"
        else:
            continue
        

        user_match = re.search(r'for (?:invalid user )?([A-Za-z0-9._-]+)', message)
        username = user_match.group(1) if user_match else "unknown"

        attempt_count = 0
        rule_name = event_type

        #IPV4 Pattern to check in below if statement
        pattern = r'\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b'

        #If there is a match, pull IP address out of the string
        matches = re.findall(pattern, message)
        if not matches:
            continue

        extracted_ip = matches[0]

        if status == "failure":
            failed_attempts[extracted_ip].append(current_time)
            failed_attempts[extracted_ip] = [
                t for t in failed_attempts[extracted_ip]
                if current_time - t <= 60
            ]
            attempt_count = len(failed_attempts[extracted_ip])

            if attempt_count >= 5:
                rule_name = "brute_force_threshold"
            else:
                rule_name = event_type
        else:
            attempt_count = len(failed_attempts.get(extracted_ip, []))
            rule_name = event_type

        
        
        print(f"Parsed {event_type} event from IP: {extracted_ip}")        
        
        # 2. Send the SNS alert if a valid score was retrieved
        should_alert = False
        threat_score = None

        if status == "failure" and attempt_count >= 5:
            should_alert = True
        elif status == "success" and len(failed_attempts.get(extracted_ip, [])) >= 3:
            rule_name = "success_after_failures"
            should_alert = True
            attempt_count = len(failed_attempts.get(extracted_ip, []))
        
        if should_alert:
            print(f"Enriching Threat IP: {extracted_ip} via AbuseIPDB...")
            threat_score = get_abuse_score(extracted_ip)
            send_alert(
                extracted_ip,
                threat_score,
                rule_name,
                event_type,
                username,
                attempt_count,
                readable_timestamp
            )
            if rule_name == "success_after_failures":
                failed_attempts[extracted_ip] = []
            

        alert_record = {
            "timestamp": readable_timestamp,
            "src_ip": extracted_ip,
            "username": username,
            "status": status,
            "event_type": event_type,
            "rule_name": rule_name,
            "attempt_count": attempt_count,
            "threat_score": threat_score
        }

        print(json.dumps(alert_record))
    
    #Return successfully
    return {
        'statusCode': 200,
        'body': 'Log processing complete!'
    }

