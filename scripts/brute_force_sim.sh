#!/bin/bash
# ==============================================================================
# Script Name: brute_force_sim.sh
# Description: Automates SSH connection failures against an authorized target 
#              to trigger CloudWatch/Splunk SIEM threshold alerts.
# WARNING:     Execute ONLY against your authorized AWS EC2 Honeypot instance.
# ==============================================================================

TARGET_IP="EC2_HONEYPOT_IP"

USERS=("root" "superadmin" "fakeuser")

echo "=================================================="
echo "🚨 Initiating SIEM Brute-Force Simulation"
echo "🎯 Target: $TARGET_IP"
echo "=================================================="

# Loop through each fake user
for user in "${USERS[@]}"; do
    echo "[*] Launching rapid attack cluster for user: $user"
    
    for i in {1..6}; do
        # -o BatchMode=yes prevents interactive password prompts so it fails instantly
        # -o StrictHostKeyChecking=no bypasses the initial fingerprint prompt
        # -o ConnectTimeout=2 prevents the script from hanging
        ssh -o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no ${user}@${TARGET_IP} 2>/dev/null
        
        echo "    -> Attempt $i logged."
        sleep 1 # 1-second delay to ensure CloudWatch logs them sequentially
    done
    echo "[+] Cluster complete for $user."
    sleep 2
done

echo "=================================================="
echo "✅ Simulation Complete."
echo "🔍 Verify CloudWatch, check your email for the SNS alert," 
echo "   and refresh the Splunk SOC Dashboard."
echo "=================================================="