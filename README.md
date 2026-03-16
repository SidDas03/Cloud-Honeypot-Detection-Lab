# Cloud Honeypot Detection Lab

> A simulated cloud-based honeypot infrastructure for detecting, logging, and analyzing real-world attacker behavior — built to mirror production AWS deployments without requiring live cloud access.

---

## Project Overview

This lab simulates a **cloud honeypot environment** that mimics an exposed EC2 instance running SSH and HTTP services. It captures attacker interactions, generates GuardDuty-style threat findings, and maps observed behaviors to the **MITRE ATT&CK framework**.

The entire lab is designed to be **runnable locally** using Docker and Python — no AWS account required — while producing artifacts and logs that are structurally identical to what a real cloud deployment would generate.

---

## Objectives

| Goal | Description |
|------|-------------|
| **Deception** | Deploy a believable honeypot that looks like a misconfigured cloud VM |
| **Detection** | Capture brute-force, port scan, and exploit attempts |
| **Analysis** | Extract attacker IPs, TTPs, and session commands |
| **Response** | Auto-block malicious IPs using firewall rules |
| **Reporting** | Generate structured threat intelligence reports |

---

## Architecture

```
Internet
    │
    ▼
[Simulated EC2 Instance - t2.micro]
    ├── Cowrie SSH Honeypot (port 2222 → 22)
    ├── HTTP Honeypot (port 8080 → 80)
    └── CloudWatch Agent (log forwarding)
         │
         ▼
    [AWS Services - Simulated]
    ├── GuardDuty  → Threat findings
    ├── CloudTrail → API call logs
    ├── S3 Bucket  → Log storage
    └── SNS Topic  → Alert notifications
         │
         ▼
    [Analysis Pipeline]
    ├── ip_extractor.py     → Parse attacker IPs
    ├── threat_analysis.py  → Classify TTPs
    └── auto_ip_blocker.py  → Block via iptables/NACL
```

---

## Repository Structure

```
Cloud-Honeypot-Detection-Lab/
├── README.md                        ← You are here
├── architecture/
│   ├── architecture-diagram.png     ← System architecture
│   └── data-flow.png                ← Attack data flow
├── setup/
│   └── lab-setup.md                 ← Step-by-step setup guide
├── scripts/
│   ├── ip_extractor.py              ← Extract IPs from Cowrie logs
│   ├── threat_analysis.py           ← Classify and score threats
│   └── auto_ip_blocker.py           ← Automated IP blocking
├── logs/
│   ├── cowrie_logs.json             ← Simulated Cowrie honeypot logs
│   ├── guardduty_findings.json      ← Simulated GuardDuty findings
│   └── attacker_ips.txt             ← Extracted attacker IP list
├── analysis/
│   └── attack-report.md             ← Full threat analysis report
├── screenshots/
│   ├── ec2_setup.png                ← EC2 configuration screenshot
│   ├── cowrie_attack.png            ← Cowrie capturing an attack
│   ├── guardduty_alert.png          ← GuardDuty finding alert
│   └── cloudtrail_logs.png          ← CloudTrail API logs
└── mitre_attack/
    └── mitre_mapping.md             ← MITRE ATT&CK TTP mapping
```

---

## Quick Start

### Prerequisites

```bash
# Python 3.8+
python3 --version

# Docker (for running Cowrie locally)
docker --version

# Required Python packages
pip install -r requirements.txt
```

### Run the Analysis Pipeline

```bash
# Step 1: Extract attacker IPs from logs
python3 scripts/ip_extractor.py --input logs/cowrie_logs.json --output logs/attacker_ips.txt

# Step 2: Analyze threats and generate report
python3 scripts/threat_analysis.py --logs logs/cowrie_logs.json --findings logs/guardduty_findings.json

# Step 3: Block identified malicious IPs
python3 scripts/auto_ip_blocker.py --ip-list logs/attacker_ips.txt --dry-run
```

---

## Key Findings Summary

During the simulated 72-hour observation window:

| Metric | Value |
|--------|-------|
| Total Connection Attempts | **14,823** |
| Unique Attacker IPs | **347** |
| Successful Honeypot Logins | **89** |
| Distinct Countries | **42** |
| Top Attack Type | **SSH Brute Force (78%)** |
| Credentials Attempted | **2,341 unique pairs** |
| Malware Drop Attempts | **23** |
| GuardDuty HIGH Findings | **7** |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Count |
|--------|-----------|-------|
| Initial Access | T1110 - Brute Force | 11,234 |
| Execution | T1059.004 - Unix Shell | 89 |
| Discovery | T1046 - Network Scan | 456 |
| Persistence | T1136 - Create Account | 12 |
| C2 | T1071 - App Layer Protocol | 23 |
| Exfiltration | T1048 - Exfil Over Alt Protocol | 4 |

---

## Defensive Actions Taken

1. **IP Blocking** — 347 IPs added to simulated Network ACL deny list
2. **Credential Blacklist** — Top 50 attempted credential pairs documented
3. **IOC Export** — All indicators exported in STIX 2.1 format
4. **Alerting** — SNS notifications triggered for HIGH severity findings

---

## Disclaimer

> This project is **for educational and research purposes only**. All logs, IP addresses, and findings are **simulated** to reflect realistic attack patterns observed in real honeypot deployments. Do not use the blocking scripts against real infrastructure without proper authorization.

---

## References

- [Cowrie Honeypot Documentation](https://cowrie.readthedocs.io/)
- [AWS GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [SANS Honeypot Resources](https://www.sans.org/security-resources/honeypots/)

---

## 👤 Author

**Security Research Lab**
- Built as a portfolio demonstration of cloud threat detection capabilities
- Simulates real-world SOC workflows without requiring cloud infrastructure costs
