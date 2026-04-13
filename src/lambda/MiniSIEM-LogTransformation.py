import base64
import gzip
import json
import urllib3
import boto3
import os

# Initialize AWS clients
http = urllib3.PoolManager(cert_reqs='CERT_NONE')
sns_client = boto3.client('sns')

# Environment Variables
SPLUNK_HEC_URL = os.environ['SPLUNK_HEC_URL'] 
SPLUNK_HEC_TOKEN = os.environ['SPLUNK_HEC_TOKEN']
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN') 

def lambda_handler(event, context):
    try:
        # 1. Unpack the CloudWatch Payload
        cw_data = event['awslogs']['data']
        compressed_payload = base64.b64decode(cw_data)
        uncompressed_payload = gzip.decompress(compressed_payload)
        payload = json.loads(uncompressed_payload)
        
        # 2. Iterate through the log events in the batch
        for log_event in payload['logEvents']:
            raw_message = log_event['message']
            
            # Skip empty lines
            if not raw_message.strip(): continue
            
            # 3. Log Transformation Logic (Phase 6a)
            # You will add your specific parsing logic/regex here later
            parsed_data = {
                "raw_log": raw_message,
                "event_type": "ssh_auth_attempt",
                "log_group": payload.get('logGroup', 'unknown')
            }
            
            # 4. Construct the Splunk HEC payload
            splunk_payload = {
                "index": "linux_auth",
                "sourcetype": "_json",
                "event": parsed_data
            }
            
            # 5. Route to Splunk
            headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
            encoded_data = json.dumps(splunk_payload).encode('utf-8')
            
            r = http.request(
                'POST', 
                SPLUNK_HEC_URL, 
                body=encoded_data, 
                headers=headers,
                retries=urllib3.Retry(3) 
            )
            
            if r.status != 200:
                print(f"Failed to send to Splunk. Status Code: {r.status}")
                # Raising an error triggers the SQS DLQ
                raise Exception(f"Splunk HEC returned status {r.status}")

        return {"status": "Success, logs routed to Splunk"}

    except Exception as e:
        print(f"Error processing CloudWatch logs: {str(e)}")
        raise e