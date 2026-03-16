# 🛠️ Lab Setup Guide

> Complete walkthrough for deploying the Cloud Honeypot Detection Lab — both the simulated local version and the real AWS version (when cloud access is available).

---

## Table of Contents

1. [Local Simulation Setup](#1-local-simulation-setup)
2. [Cowrie Honeypot via Docker](#2-cowrie-honeypot-via-docker)
3. [AWS Deployment Guide](#3-aws-deployment-guide-reference)
4. [GuardDuty Simulation](#4-guardduty-simulation)
5. [Log Pipeline Configuration](#5-log-pipeline-configuration)
6. [Alerting Setup](#6-alerting-setup)
7. [Verification Checklist](#7-verification-checklist)

---

## 1. Local Simulation Setup

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04 / macOS 12 | Ubuntu 22.04 LTS |
| RAM | 2 GB | 4 GB |
| Disk | 5 GB | 10 GB |
| Python | 3.8+ | 3.11+ |
| Docker | 20.x | 24.x |

### Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Clone the repository
git clone https://github.com/yourname/Cloud-Honeypot-Detection-Lab.git
cd Cloud-Honeypot-Detection-Lab

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### requirements.txt contents

```
boto3==1.34.0
botocore==1.34.0
requests==2.31.0
pandas==2.1.4
geoip2==4.8.0
colorama==0.4.6
tabulate==0.9.0
python-dateutil==2.8.2
ipaddress==1.0.23
```

---

## 2. Cowrie Honeypot via Docker

Cowrie is a medium-to-high interaction SSH/Telnet honeypot. We run it in Docker to safely capture attacker behavior.

### Start Cowrie

```bash
# Pull the official Cowrie Docker image
docker pull cowrie/cowrie:latest

# Create data directories
mkdir -p cowrie-data/{log,dl,tty}

# Run Cowrie (maps host port 2222 to honeypot SSH port 22)
docker run -d \
  --name cowrie-honeypot \
  -p 2222:2222 \
  -p 2223:2223 \
  -v $(pwd)/cowrie-data/log:/cowrie/var/log/cowrie \
  -v $(pwd)/cowrie-data/dl:/cowrie/var/lib/cowrie/downloads \
  -v $(pwd)/cowrie-data/tty:/cowrie/var/lib/cowrie/tty \
  cowrie/cowrie:latest

# Verify it's running
docker ps | grep cowrie
docker logs cowrie-honeypot
```

### Configure Cowrie (cowrie.cfg)

```ini
[honeypot]
# Hostname shown to attackers
hostname = prod-web-server-01

# Fake filesystem contents
contents_path = honeyfs

# Log format
log_format = json

# Download captured malware samples
download_limit_size = 10485760

[output_jsonlog]
enabled = true
logfile = /cowrie/var/log/cowrie/cowrie.json

[output_elasticsearch]
enabled = false

[ssh]
# Fake SSH version string
version = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
listen_endpoints = tcp:2222:interface=0.0.0.0

# Fake credentials that will be accepted (to lure attackers in)
auth_none_enabled = false
```

### View Live Logs

```bash
# Watch logs in real-time
docker exec -it cowrie-honeypot tail -f /cowrie/var/log/cowrie/cowrie.json

# Copy logs to project
docker cp cowrie-honeypot:/cowrie/var/log/cowrie/cowrie.json logs/cowrie_logs.json
```

---

## 3. AWS Deployment Guide (Reference)

> **Note**: This section documents what a real AWS deployment looks like. You do NOT need an AWS account to use this lab — the simulation uses pre-generated logs that match this structure exactly.

### 3.1 EC2 Honeypot Instance

```bash
# Launch EC2 instance (t2.micro - Free Tier eligible)
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.micro \
  --key-name MyKeyPair \
  --security-group-ids sg-honeypot \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Honeypot-01}]'

# Security Group Configuration
# IMPORTANT: Intentionally permissive to attract attackers
aws ec2 authorize-security-group-ingress \
  --group-id sg-honeypot \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id sg-honeypot \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0
```

### 3.2 GuardDuty Enablement

```bash
# Enable GuardDuty in your region
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES

# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Create sample findings (for testing)
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce"
```

### 3.3 CloudTrail Configuration

```bash
# Create S3 bucket for CloudTrail logs
aws s3 mb s3://honeypot-cloudtrail-logs-$(date +%s)

# Create trail
aws cloudtrail create-trail \
  --name HoneypotTrail \
  --s3-bucket-name honeypot-cloudtrail-logs \
  --include-global-service-events \
  --is-multi-region-trail

# Start logging
aws cloudtrail start-logging --name HoneypotTrail
```

### 3.4 SNS Alerting

```bash
# Create SNS topic
aws sns create-topic --name HoneypotAlerts

# Subscribe email
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:HoneypotAlerts \
  --protocol email \
  --notification-endpoint your-email@domain.com

# Create CloudWatch alarm for GuardDuty HIGH findings
aws cloudwatch put-metric-alarm \
  --alarm-name "GuardDuty-High-Severity" \
  --metric-name "HighSeverityFindingCount" \
  --namespace "AWS/GuardDuty" \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:HoneypotAlerts
```

---

## 4. GuardDuty Simulation

When running without AWS, we generate GuardDuty-compatible findings from Cowrie logs:

```bash
# Generate simulated GuardDuty findings from Cowrie logs
python3 scripts/threat_analysis.py \
  --mode simulate-guardduty \
  --input logs/cowrie_logs.json \
  --output logs/guardduty_findings.json

# View generated findings
python3 -c "
import json
with open('logs/guardduty_findings.json') as f:
    findings = json.load(f)
for f in findings[:3]:
    print(f['type'], '-', f['severity'], '-', f['description'][:60])
"
```

---

## 5. Log Pipeline Configuration

### Log Flow

```
Cowrie JSON logs
      │
      ▼
ip_extractor.py ──────────→ attacker_ips.txt
      │
      ▼
threat_analysis.py ────────→ guardduty_findings.json
      │                        (simulated findings)
      ▼
attack-report.md ──────────→ Human-readable report
      │
      ▼
auto_ip_blocker.py ────────→ iptables rules / NACL entries
```

### Automate with Cron (optional)

```bash
# Add to crontab for hourly analysis
crontab -e

# Add these lines:
0 * * * * cd /path/to/lab && python3 scripts/ip_extractor.py --input logs/cowrie_logs.json >> logs/pipeline.log 2>&1
5 * * * * cd /path/to/lab && python3 scripts/threat_analysis.py >> logs/pipeline.log 2>&1
10 * * * * cd /path/to/lab && python3 scripts/auto_ip_blocker.py --ip-list logs/attacker_ips.txt >> logs/pipeline.log 2>&1
```

---

## 6. Alerting Setup

### Local Email Alerts (via SMTP)

```python
# Add to threat_analysis.py config
ALERT_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender": "your-alert-sender@gmail.com",
    "recipient": "your-email@gmail.com",
    "severity_threshold": "HIGH"  # Only alert on HIGH/CRITICAL
}
```

### Slack Webhook Integration

```bash
# Set environment variable
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Test alert
python3 scripts/threat_analysis.py --test-alert
```

---

## 7. Verification Checklist

Run through this checklist to confirm your lab is configured correctly:

```bash
# ✅ Check 1: Python scripts are executable
python3 scripts/ip_extractor.py --help
python3 scripts/threat_analysis.py --help
python3 scripts/auto_ip_blocker.py --help

# ✅ Check 2: Log files exist and are valid JSON
python3 -c "import json; json.load(open('logs/cowrie_logs.json')); print('✅ cowrie_logs.json valid')"
python3 -c "import json; json.load(open('logs/guardduty_findings.json')); print('✅ guardduty_findings.json valid')"

# ✅ Check 3: IP extractor produces output
python3 scripts/ip_extractor.py --input logs/cowrie_logs.json --output /tmp/test_ips.txt
wc -l /tmp/test_ips.txt  # Should show 300+ IPs

# ✅ Check 4: Full pipeline end-to-end
python3 scripts/threat_analysis.py --full-report

# ✅ Check 5: Blocker dry-run (no actual blocking)
python3 scripts/auto_ip_blocker.py --ip-list logs/attacker_ips.txt --dry-run
```

---

## 🔧 Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError` | Missing packages | Run `pip install -r requirements.txt` |
| `Permission denied` on scripts | Wrong permissions | Run `chmod +x scripts/*.py` |
| Docker not starting | Docker daemon down | Run `sudo systemctl start docker` |
| Empty attacker_ips.txt | Log parsing issue | Check log format with `--debug` flag |
| Cowrie not receiving connections | Port not open | Check `sudo ufw allow 2222/tcp` |
