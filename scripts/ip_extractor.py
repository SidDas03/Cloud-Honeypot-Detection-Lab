#!/usr/bin/env python3
"""
ip_extractor.py — Extract and enrich attacker IPs from Cowrie honeypot logs

Usage:
    python3 ip_extractor.py --input logs/cowrie_logs.json --output logs/attacker_ips.txt
    python3 ip_extractor.py --input logs/cowrie_logs.json --format csv
    python3 ip_extractor.py --input logs/cowrie_logs.json --top 20
"""

import json
import argparse
import sys
import os
from collections import defaultdict, Counter
from datetime import datetime


# ─────────────────────────────────────────────
# ANSI Colors for terminal output
# ─────────────────────────────────────────────
class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def cprint(msg, color=Colors.WHITE):
    print(f"{color}{msg}{Colors.RESET}")


# ─────────────────────────────────────────────
# IP Extractor Core
# ─────────────────────────────────────────────
class IPExtractor:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.events = []
        self.ip_stats = defaultdict(lambda: {
            "connections": 0,
            "login_attempts": 0,
            "login_successes": 0,
            "commands_executed": [],
            "files_downloaded": [],
            "sessions": set(),
            "first_seen": None,
            "last_seen": None,
            "usernames_tried": set(),
            "passwords_tried": set(),
            "attack_types": set()
        })

    def load_logs(self) -> bool:
        """Load and parse Cowrie JSON log file."""
        if not os.path.exists(self.log_file):
            cprint(f"[ERROR] Log file not found: {self.log_file}", Colors.RED)
            return False

        try:
            with open(self.log_file, "r") as f:
                self.events = json.load(f)
            cprint(f"[+] Loaded {len(self.events)} events from {self.log_file}", Colors.GREEN)
            return True
        except json.JSONDecodeError as e:
            cprint(f"[ERROR] Invalid JSON in log file: {e}", Colors.RED)
            return False

    def parse_events(self):
        """Parse events and aggregate stats per IP address."""
        cprint("[*] Parsing events...", Colors.CYAN)

        for event in self.events:
            ip = event.get("src_ip")
            if not ip:
                continue

            stats = self.ip_stats[ip]
            event_id = event.get("eventid", "")
            timestamp = event.get("timestamp")

            # Track timestamps
            if timestamp:
                if stats["first_seen"] is None or timestamp < stats["first_seen"]:
                    stats["first_seen"] = timestamp
                if stats["last_seen"] is None or timestamp > stats["last_seen"]:
                    stats["last_seen"] = timestamp

            # Session connect
            if event_id == "cowrie.session.connect":
                stats["connections"] += 1
                session = event.get("session")
                if session:
                    stats["sessions"].add(session)

            # Login attempts
            elif event_id == "cowrie.login.failed":
                stats["login_attempts"] += 1
                stats["attack_types"].add("SSH_BRUTEFORCE")
                if event.get("username"):
                    stats["usernames_tried"].add(event["username"])
                if event.get("password"):
                    stats["passwords_tried"].add(event["password"])

            elif event_id == "cowrie.login.success":
                stats["login_successes"] += 1
                stats["attack_types"].add("SSH_LOGIN_SUCCESS")

            # Commands
            elif event_id == "cowrie.command.input":
                cmd = event.get("input", "")
                stats["commands_executed"].append(cmd)
                self._classify_command(cmd, stats)

            # File downloads
            elif event_id == "cowrie.session.file_download":
                url = event.get("url", "")
                stats["files_downloaded"].append(url)
                stats["attack_types"].add("MALWARE_DOWNLOAD")

        cprint(f"[+] Parsed data for {len(self.ip_stats)} unique IP addresses", Colors.GREEN)

    def _classify_command(self, cmd: str, stats: dict):
        """Classify command intent and tag the attack type."""
        cmd_lower = cmd.lower()

        if any(k in cmd_lower for k in ["wget", "curl", "chmod +x", ".update", "bash"]):
            stats["attack_types"].add("MALWARE_EXECUTION")

        if any(k in cmd_lower for k in ["crontab", "cron.d", "crontabs", "/etc/crontab"]):
            stats["attack_types"].add("PERSISTENCE_CRON")

        if any(k in cmd_lower for k in ["useradd", "adduser", "passwd"]):
            stats["attack_types"].add("PERSISTENCE_ACCOUNT")

        if any(k in cmd_lower for k in ["169.254.169.254", "imds", "iam/security-credentials", "metadata"]):
            stats["attack_types"].add("CLOUD_METADATA_ABUSE")

        if any(k in cmd_lower for k in [".aws/credentials", ".pem", ".key", "id_rsa"]):
            stats["attack_types"].add("CREDENTIAL_THEFT")

        if any(k in cmd_lower for k in ["socket", "subprocess", "dup2", "/bin/sh", "netcat", "nc -"]):
            stats["attack_types"].add("REVERSE_SHELL")

        if any(k in cmd_lower for k in ["xmrig", "minexmr", "mining", "stratum+tcp", "monero"]):
            stats["attack_types"].add("CRYPTOMINER")

        if any(k in cmd_lower for k in ["iptables -f", "ufw disable"]):
            stats["attack_types"].add("DEFENSE_EVASION")

    def get_severity(self, stats: dict) -> str:
        """Determine severity level based on attack behavior."""
        critical_types = {"REVERSE_SHELL", "PERSISTENCE_CRON", "PERSISTENCE_ACCOUNT", "CLOUD_METADATA_ABUSE"}
        high_types = {"MALWARE_EXECUTION", "MALWARE_DOWNLOAD", "CRYPTOMINER", "CREDENTIAL_THEFT"}

        attack_types = stats["attack_types"]

        if attack_types & critical_types:
            return "CRITICAL"
        elif attack_types & high_types:
            return "HIGH"
        elif stats["login_successes"] > 0:
            return "HIGH"
        elif stats["login_attempts"] > 20:
            return "MEDIUM"
        else:
            return "LOW"

    def print_summary(self):
        """Print a formatted summary table to stdout."""
        cprint("\n" + "═" * 100, Colors.BLUE)
        cprint("  HONEYPOT ATTACKER IP SUMMARY", Colors.BOLD)
        cprint("═" * 100, Colors.BLUE)

        # Header
        print(f"{'IP ADDRESS':<20} {'CONNECTIONS':>12} {'LOGIN ATTEMPTS':>15} {'LOGINS':>8} {'SEVERITY':<10} {'ATTACK TYPES'}")
        print("─" * 100)

        # Sort by severity then connections
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: (severity_order.get(self.get_severity(x[1]), 4), -x[1]["connections"])
        )

        for ip, stats in sorted_ips:
            severity = self.get_severity(stats)
            color = {
                "CRITICAL": Colors.RED,
                "HIGH": Colors.YELLOW,
                "MEDIUM": Colors.CYAN,
                "LOW": Colors.WHITE
            }.get(severity, Colors.WHITE)

            attack_str = ", ".join(sorted(stats["attack_types"])) or "SCANNING"
            print(
                f"{color}{ip:<20} {stats['connections']:>12} {stats['login_attempts']:>15} "
                f"{stats['login_successes']:>8} {severity:<10} {attack_str}{Colors.RESET}"
            )

        print("─" * 100)
        cprint(f"\nTotal unique attackers: {len(self.ip_stats)}", Colors.GREEN)

        # Top credentials
        all_passwords = Counter()
        all_usernames = Counter()
        for stats in self.ip_stats.values():
            all_passwords.update(stats["passwords_tried"])
            all_usernames.update(stats["usernames_tried"])

        cprint("\n📊 Top 10 Attempted Passwords:", Colors.CYAN)
        for pw, count in all_passwords.most_common(10):
            print(f"  {count:>5}x  {pw}")

        cprint("\n📊 Top 10 Attempted Usernames:", Colors.CYAN)
        for un, count in all_usernames.most_common(10):
            print(f"  {count:>5}x  {un}")

    def save_to_file(self, output_file: str, fmt: str = "txt"):
        """Save extracted IPs to file in specified format."""
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)

        if fmt == "txt":
            self._save_txt(output_file)
        elif fmt == "csv":
            self._save_csv(output_file)
        elif fmt == "json":
            self._save_json(output_file)
        else:
            cprint(f"[ERROR] Unknown format: {fmt}", Colors.RED)

    def _save_txt(self, output_file: str):
        with open(output_file, "w") as f:
            f.write(f"# Extracted by ip_extractor.py\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n")
            f.write(f"# Total IPs: {len(self.ip_stats)}\n\n")
            for ip, stats in sorted(self.ip_stats.items()):
                severity = self.get_severity(stats)
                attacks = ",".join(sorted(stats["attack_types"])) or "SCANNING"
                f.write(f"{ip} | SEVERITY:{severity} | ATTACKS:{attacks} | "
                        f"CONNECTIONS:{stats['connections']} | "
                        f"LOGIN_ATTEMPTS:{stats['login_attempts']} | "
                        f"SUCCESSES:{stats['login_successes']}\n")
        cprint(f"[+] Saved {len(self.ip_stats)} IPs to {output_file}", Colors.GREEN)

    def _save_csv(self, output_file: str):
        with open(output_file, "w") as f:
            f.write("ip,severity,connections,login_attempts,login_successes,attack_types,first_seen,last_seen\n")
            for ip, stats in sorted(self.ip_stats.items()):
                severity = self.get_severity(stats)
                attacks = "|".join(sorted(stats["attack_types"]))
                f.write(f"{ip},{severity},{stats['connections']},{stats['login_attempts']},"
                        f"{stats['login_successes']},{attacks},"
                        f"{stats['first_seen']},{stats['last_seen']}\n")
        cprint(f"[+] Saved CSV to {output_file}", Colors.GREEN)

    def _save_json(self, output_file: str):
        output = {}
        for ip, stats in self.ip_stats.items():
            output[ip] = {
                "severity": self.get_severity(stats),
                "connections": stats["connections"],
                "login_attempts": stats["login_attempts"],
                "login_successes": stats["login_successes"],
                "attack_types": sorted(stats["attack_types"]),
                "commands_executed": stats["commands_executed"][:10],
                "files_downloaded": stats["files_downloaded"],
                "usernames_tried": list(stats["usernames_tried"])[:20],
                "passwords_tried": list(stats["passwords_tried"])[:20],
                "first_seen": stats["first_seen"],
                "last_seen": stats["last_seen"]
            }
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        cprint(f"[+] Saved JSON to {output_file}", Colors.GREEN)


# ─────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Extract and analyze attacker IPs from Cowrie honeypot logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ip_extractor.py --input logs/cowrie_logs.json --output logs/attacker_ips.txt
  python3 ip_extractor.py --input logs/cowrie_logs.json --format csv --output logs/ips.csv
  python3 ip_extractor.py --input logs/cowrie_logs.json --top 10
  python3 ip_extractor.py --input logs/cowrie_logs.json --severity CRITICAL
        """
    )
    parser.add_argument("--input", "-i", required=True, help="Path to Cowrie JSON log file")
    parser.add_argument("--output", "-o", default=None, help="Output file path (default: stdout only)")
    parser.add_argument("--format", "-f", choices=["txt", "csv", "json"], default="txt", help="Output format")
    parser.add_argument("--top", "-n", type=int, default=None, help="Show only top N IPs by connection count")
    parser.add_argument("--severity", "-s", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        default=None, help="Filter by minimum severity")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    cprint("=" * 60, Colors.BLUE)
    cprint("  🍯 Cloud Honeypot IP Extractor", Colors.BOLD)
    cprint("=" * 60, Colors.BLUE)

    extractor = IPExtractor(args.input)

    if not extractor.load_logs():
        sys.exit(1)

    extractor.parse_events()
    extractor.print_summary()

    if args.output:
        extractor.save_to_file(args.output, args.format)

    cprint("\n[✓] IP extraction complete.", Colors.GREEN)


if __name__ == "__main__":
    main()
