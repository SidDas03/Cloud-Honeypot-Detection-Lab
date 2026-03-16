#!/usr/bin/env python3
"""
threat_analysis.py — Analyze honeypot logs and generate threat intelligence report

Usage:
    python3 threat_analysis.py --logs logs/cowrie_logs.json --findings logs/guardduty_findings.json
    python3 threat_analysis.py --full-report
    python3 threat_analysis.py --mode simulate-guardduty --input logs/cowrie_logs.json --output logs/gd_sim.json
"""

import json
import argparse
import sys
import os
from collections import defaultdict, Counter
from datetime import datetime
import hashlib
import uuid

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

COMMAND_TO_MITRE = {
    "uname":         ("Discovery",          "T1082",     "System Information Discovery"),
    "id":            ("Discovery",          "T1033",     "System Owner/User Discovery"),
    "whoami":        ("Discovery",          "T1033",     "System Owner/User Discovery"),
    "ps aux":        ("Discovery",          "T1057",     "Process Discovery"),
    "netstat":       ("Discovery",          "T1049",     "System Network Connections Discovery"),
    "cat /etc/passwd": ("Discovery",        "T1087.001", "Account Discovery: Local Account"),
    "cat ~/.aws":    ("Credential Access",  "T1552.001", "Credentials In Files"),
    "169.254.169.254": ("Credential Access","T1552.005", "Cloud Instance Metadata API"),
    "find / -name": ("Credential Access",  "T1083",     "File and Directory Discovery"),
    "wget":          ("Execution",          "T1105",     "Ingress Tool Transfer"),
    "curl":          ("Execution",          "T1105",     "Ingress Tool Transfer"),
    "chmod +x":      ("Execution",          "T1059.004", "Unix Shell"),
    "bash":          ("Execution",          "T1059.004", "Unix Shell"),
    "crontab":       ("Persistence",        "T1053.003", "Scheduled Task/Job: Cron"),
    "/etc/crontab":  ("Persistence",        "T1053.003", "Scheduled Task/Job: Cron"),
    "useradd":       ("Persistence",        "T1136.001", "Create Account: Local Account"),
    "adduser":       ("Persistence",        "T1136.001", "Create Account: Local Account"),
    "iptables -F":   ("Defense Evasion",    "T1562.004", "Disable or Modify System Firewall"),
    "socket":        ("C2",                 "T1059.006", "Python Reverse Shell"),
    "/bin/sh":       ("C2",                 "T1059.004", "Unix Shell C2"),
    "xmrig":         ("Impact",             "T1496",     "Resource Hijacking"),
    "stratum+tcp":   ("Impact",             "T1496",     "Resource Hijacking"),
    "minexmr":       ("Impact",             "T1496",     "Resource Hijacking"),
}

class ThreatAnalyzer:
    def __init__(self, cowrie_log: str, guardduty_log: str = None):
        self.cowrie_log = cowrie_log
        self.guardduty_log = guardduty_log
        self.cowrie_events = []
        self.guardduty_findings = {}
        self.threat_report = {}

    def load_data(self):
        """Load Cowrie and GuardDuty log files."""
        try:
            with open(self.cowrie_log) as f:
                self.cowrie_events = json.load(f)
            print(f"{C.GREEN}[+] Loaded {len(self.cowrie_events)} Cowrie events{C.RESET}")
        except Exception as e:
            print(f"{C.RED}[ERROR] Failed to load Cowrie logs: {e}{C.RESET}")
            sys.exit(1)

        if self.guardduty_log and os.path.exists(self.guardduty_log):
            try:
                with open(self.guardduty_log) as f:
                    self.guardduty_findings = json.load(f)
                count = len(self.guardduty_findings.get("findings", []))
                print(f"{C.GREEN}[+] Loaded {count} GuardDuty findings{C.RESET}")
            except Exception as e:
                print(f"{C.YELLOW}[WARN] Could not load GuardDuty file: {e}{C.RESET}")

    def analyze(self):
        """Run full threat analysis pipeline."""
        print(f"\n{C.CYAN}[*] Running threat analysis...{C.RESET}")

        # Aggregate session data
        sessions = defaultdict(lambda: {
            "ip": None, "commands": [], "logins": [], "downloads": [],
            "start": None, "end": None
        })

        ip_activity = defaultdict(lambda: {
            "total_attempts": 0, "successes": 0, "sessions": [],
            "commands": [], "downloads": [], "mitre_ttps": set()
        })

        login_creds = Counter()
        successful_creds = []

        for event in self.cowrie_events:
            ip = event.get("src_ip", "unknown")
            session = event.get("session", "unknown")
            eid = event.get("eventid", "")
            ts = event.get("timestamp")

            sessions[session]["ip"] = ip
            if ts:
                if not sessions[session]["start"]:
                    sessions[session]["start"] = ts
                sessions[session]["end"] = ts

            if eid == "cowrie.login.failed":
                ip_activity[ip]["total_attempts"] += 1
                cred = f"{event.get('username','?')}:{event.get('password','?')}"
                login_creds[cred] += 1

            elif eid == "cowrie.login.success":
                ip_activity[ip]["successes"] += 1
                cred = f"{event.get('username','?')}:{event.get('password','?')}"
                successful_creds.append({"ip": ip, "credential": cred, "timestamp": ts})

            elif eid == "cowrie.command.input":
                cmd = event.get("input", "")
                ip_activity[ip]["commands"].append(cmd)
                sessions[session]["commands"].append(cmd)

                # Map to MITRE
                for keyword, (tactic, technique, name) in COMMAND_TO_MITRE.items():
                    if keyword.lower() in cmd.lower():
                        ip_activity[ip]["mitre_ttps"].add((tactic, technique, name))

            elif eid == "cowrie.session.file_download":
                url = event.get("url", "")
                sha = event.get("shasum", "")
                ip_activity[ip]["downloads"].append({"url": url, "sha256": sha})

        # Compile report
        self.threat_report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "observation_window": "72 hours",
            "sensor": "honeypot-ec2-01",
            "total_events": len(self.cowrie_events),
            "unique_attackers": len(ip_activity),
            "successful_logins": len(successful_creds),
            "total_sessions": len(sessions),
            "top_credentials_attempted": [
                {"credential": cred, "count": count}
                for cred, count in login_creds.most_common(20)
            ],
            "successful_credentials": successful_creds,
            "ip_analysis": {
                ip: {
                    "login_attempts": data["total_attempts"],
                    "successful_logins": data["successes"],
                    "commands": data["commands"],
                    "file_downloads": data["downloads"],
                    "mitre_ttps": [
                        {"tactic": t, "technique": tech, "name": name}
                        for t, tech, name in data["mitre_ttps"]
                    ]
                }
                for ip, data in ip_activity.items()
            },
            "mitre_summary": self._build_mitre_summary(ip_activity),
            "iocs": self._extract_iocs(ip_activity),
            "guardduty_summary": self.guardduty_findings.get("summary", {})
        }

        return self.threat_report

    def _build_mitre_summary(self, ip_activity: dict) -> dict:
        """Aggregate MITRE ATT&CK TTPs across all sessions."""
        tactic_counts = Counter()
        technique_counts = Counter()

        for ip, data in ip_activity.items():
            for tactic, technique, name in data["mitre_ttps"]:
                tactic_counts[tactic] += 1
                technique_counts[f"{technique}: {name}"] += 1

        return {
            "tactics_observed": dict(tactic_counts.most_common()),
            "techniques_observed": dict(technique_counts.most_common(15))
        }

    def _extract_iocs(self, ip_activity: dict) -> dict:
        """Extract Indicators of Compromise."""
        malicious_ips = []
        malicious_urls = []
        file_hashes = []
        domains = set()

        for ip, data in ip_activity.items():
            if data["successes"] > 0 or data["downloads"]:
                malicious_ips.append(ip)

            for dl in data["downloads"]:
                url = dl.get("url", "")
                sha = dl.get("sha256", "")
                if url:
                    malicious_urls.append(url)
                    # Extract domain
                    try:
                        domain = url.split("/")[2]
                        domains.add(domain)
                    except IndexError:
                        pass
                if sha:
                    file_hashes.append(sha)

        return {
            "malicious_ips": malicious_ips,
            "malicious_urls": malicious_urls,
            "file_hashes": file_hashes,
            "domains": list(domains)
        }

    def print_report(self):
        """Print formatted threat analysis report."""
        r = self.threat_report
        print(f"\n{C.BOLD}{'═' * 70}")
        print("  🔍 THREAT ANALYSIS REPORT")
        print("  Cloud Honeypot Detection Lab")
        print(f"{'═' * 70}{C.RESET}")

        print(f"\n{C.CYAN}📊 OBSERVATION SUMMARY{C.RESET}")
        print(f"  Generated At     : {r.get('generated_at')}")
        print(f"  Sensor           : {r.get('sensor')}")
        print(f"  Window           : {r.get('observation_window')}")
        print(f"  Total Events     : {r.get('total_events')}")
        print(f"  Unique Attackers : {r.get('unique_attackers')}")
        print(f"  Successful Logins: {r.get('successful_logins')}")

        print(f"\n{C.CYAN}🗺️  MITRE ATT&CK TACTICS OBSERVED{C.RESET}")
        for tactic, count in r.get("mitre_summary", {}).get("tactics_observed", {}).items():
            bar = "█" * min(count * 5, 30)
            print(f"  {tactic:<30} {bar} {count}")

        print(f"\n{C.CYAN}🔑 TOP ATTEMPTED CREDENTIALS{C.RESET}")
        print(f"  {'Credential':<35} {'Count':>8}")
        print(f"  {'-' * 45}")
        for item in r.get("top_credentials_attempted", [])[:15]:
            print(f"  {item['credential']:<35} {item['count']:>8}")

        print(f"\n{C.CYAN}✅ SUCCESSFUL LOGINS (HONEYPOT CAPTURES){C.RESET}")
        for login in r.get("successful_credentials", []):
            print(f"  {C.RED}[CRITICAL]{C.RESET} {login['ip']} logged in with: {login['credential']} @ {login['timestamp']}")

        print(f"\n{C.CYAN}🚨 INDICATORS OF COMPROMISE{C.RESET}")
        iocs = r.get("iocs", {})
        print(f"  Malicious IPs  : {', '.join(iocs.get('malicious_ips', []))}")
        print(f"  Malicious URLs : {len(iocs.get('malicious_urls', []))} observed")
        for url in iocs.get("malicious_urls", []):
            print(f"    → {url}")

        if self.guardduty_findings:
            summary = r.get("guardduty_summary", {})
            print(f"\n{C.CYAN}🛡️  GUARDDUTY FINDINGS SUMMARY{C.RESET}")
            print(f"  Total     : {summary.get('total_findings', 0)}")
            print(f"  Critical  : {C.RED}{summary.get('critical', 0)}{C.RESET}")
            print(f"  High      : {C.YELLOW}{summary.get('high', 0)}{C.RESET}")
            print(f"  Medium    : {summary.get('medium', 0)}")

        print(f"\n{C.GREEN}[✓] Analysis complete.{C.RESET}\n")

    def simulate_guardduty(self, output_file: str):
        """Generate GuardDuty-compatible finding JSON from Cowrie data."""
        findings = []
        r = self.threat_report

        for login in r.get("successful_credentials", []):
            ip = login["ip"]
            ip_data = r["ip_analysis"].get(ip, {})
            ttps = ip_data.get("mitre_ttps", [])
            primary_ttp = ttps[0] if ttps else {"tactic": "Initial Access", "technique": "T1110", "name": "Brute Force"}

            finding = {
                "id": str(uuid.uuid4())[:12],
                "accountId": "123456789012",
                "type": "UnauthorizedAccess:EC2/SSHBruteForce",
                "severity": 8.5 if ip_data.get("successful_logins", 0) > 0 else 5.0,
                "description": f"Attacker {ip} successfully authenticated to honeypot instance.",
                "createdAt": login["timestamp"],
                "resource": {"instanceId": "i-0a1b2c3d4e5f67890"},
                "remoteIp": ip,
                "loginCredential": login["credential"],
                "mitre_attack": primary_ttp
            }
            findings.append(finding)

        result = {"findings": findings, "generated_by": "threat_analysis.py (simulation)", "source": self.cowrie_log}
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"{C.GREEN}[+] Simulated {len(findings)} GuardDuty findings → {output_file}{C.RESET}")

def main():
    parser = argparse.ArgumentParser(description="Honeypot Threat Analysis Engine")
    parser.add_argument("--logs", default="logs/cowrie_logs.json", help="Cowrie log file")
    parser.add_argument("--findings", default="logs/guardduty_findings.json", help="GuardDuty findings file")
    parser.add_argument("--full-report", action="store_true", help="Run full analysis and print report")
    parser.add_argument("--mode", choices=["simulate-guardduty"], help="Special operation modes")
    parser.add_argument("--input", help="Input file for special modes")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--test-alert", action="store_true", help="Test alerting pipeline")

    args = parser.parse_args()

    analyzer = ThreatAnalyzer(
        cowrie_log=args.input or args.logs,
        guardduty_log=args.findings if not args.mode else None
    )
    analyzer.load_data()
    analyzer.analyze()

    if args.mode == "simulate-guardduty":
        out = args.output or "logs/guardduty_findings_sim.json"
        analyzer.simulate_guardduty(out)
    else:
        analyzer.print_report()


if __name__ == "__main__":
    main()
