#!/usr/bin/env python3
"""
auto_ip_blocker.py — Automatically block malicious IPs from honeypot logs

Supports multiple blocking backends:
  - iptables (Linux local firewall)
  - UFW (Ubuntu Uncomplicated Firewall)
  - AWS Network ACL (requires boto3 + AWS credentials)
  - Hosts file / null-routing
  - Export only (dry-run / generate blocklist file)

Usage:
    python3 auto_ip_blocker.py --ip-list logs/attacker_ips.txt --dry-run
    python3 auto_ip_blocker.py --ip-list logs/attacker_ips.txt --backend iptables
    python3 auto_ip_blocker.py --ip-list logs/attacker_ips.txt --severity HIGH --dry-run
    python3 auto_ip_blocker.py --logs logs/cowrie_logs.json --auto-extract --dry-run
"""

import json
import argparse
import sys
import os
import subprocess
import ipaddress
from datetime import datetime
from collections import defaultdict

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

WHITELIST = {
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",    # RFC1918 private
    "172.16.0.0/12", # RFC1918 private
    "192.168.0.0/16", # RFC1918 private
    "169.254.169.254", # AWS IMDS - never block
}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_whitelisted(ip: str) -> bool:
    """Return True if IP should never be blocked."""
    if ip in WHITELIST:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in PRIVATE_RANGES:
            if ip_obj in net:
                return True
    except ValueError:
        return False
    return False

def load_ips_from_file(filepath: str, min_severity: str = "LOW") -> list:
    """Load IPs from attacker_ips.txt with optional severity filter."""
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_rank = severity_rank.get(min_severity, 0)
    ips = []

    if not os.path.exists(filepath):
        print(f"{C.RED}[ERROR] File not found: {filepath}{C.RESET}")
        sys.exit(1)

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            ip = parts[0].strip()

            if not ip:
                continue

            severity = "LOW"
            for part in parts[1:]:
                part = part.strip()
                if part.startswith("SEVERITY:"):
                    severity = part.replace("SEVERITY:", "").strip()

            rank = severity_rank.get(severity, 0)
            if rank >= min_rank and not is_whitelisted(ip):
                ips.append({"ip": ip, "severity": severity})

    return ips


def extract_ips_from_cowrie(log_file: str) -> list:
    """Extract attacker IPs directly from Cowrie log file."""
    if not os.path.exists(log_file):
        print(f"{C.RED}[ERROR] Cowrie log not found: {log_file}{C.RESET}")
        sys.exit(1)

    with open(log_file) as f:
        events = json.load(f)

    ip_data = defaultdict(lambda: {"attempts": 0, "successes": 0})
    for event in events:
        ip = event.get("src_ip")
        if not ip:
            continue
        eid = event.get("eventid", "")
        if "login.failed" in eid:
            ip_data[ip]["attempts"] += 1
        elif "login.success" in eid:
            ip_data[ip]["successes"] += 1

    result = []
    for ip, data in ip_data.items():
        if is_whitelisted(ip):
            continue
        severity = "CRITICAL" if data["successes"] > 0 else ("HIGH" if data["attempts"] > 20 else "MEDIUM")
        result.append({"ip": ip, "severity": severity})

    return result
  
class IPTablesBackend:
    """Block IPs using Linux iptables."""
    CHAIN = "HONEYPOT-BLOCK"

    def setup(self):
        """Create blocking chain if not exists."""
        try:
            subprocess.run(["iptables", "-N", self.CHAIN], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "-j", self.CHAIN], capture_output=True)
            print(f"{C.GREEN}[+] iptables chain '{self.CHAIN}' ready{C.RESET}")
        except FileNotFoundError:
            print(f"{C.RED}[ERROR] iptables not found. Run on Linux with root privileges.{C.RESET}")
            sys.exit(1)

    def block(self, ip: str) -> bool:
        """Add DROP rule for IP."""
        try:
            result = subprocess.run(
                ["iptables", "-A", self.CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception as e:
            print(f"{C.RED}[ERROR] iptables block failed for {ip}: {e}{C.RESET}")
            return False

    def unblock(self, ip: str) -> bool:
        """Remove DROP rule for IP."""
        try:
            result = subprocess.run(
                ["iptables", "-D", self.CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def list_blocked(self) -> list:
        """List all currently blocked IPs."""
        try:
            result = subprocess.run(
                ["iptables", "-L", self.CHAIN, "-n"],
                capture_output=True, text=True
            )
            lines = result.stdout.strip().split("\n")
            blocked = []
            for line in lines[2:]:  # Skip header lines
                if "DROP" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        blocked.append(parts[3])
            return blocked
        except Exception:
            return []


class UFWBackend:
    """Block IPs using Ubuntu UFW."""

    def block(self, ip: str) -> bool:
        try:
            result = subprocess.run(
                ["ufw", "deny", "from", ip, "to", "any"],
                capture_output=True, text=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            print(f"{C.RED}[ERROR] ufw not found{C.RESET}")
            return False


class AWSNACLBackend:
    """
    Block IPs using AWS Network ACL.
    Requires: boto3 installed and AWS credentials configured.
    
    In production:
        export AWS_ACCESS_KEY_ID=...
        export AWS_SECRET_ACCESS_KEY=...
        export AWS_DEFAULT_REGION=us-east-1
    """
    def __init__(self, nacl_id: str, region: str = "us-east-1"):
        self.nacl_id = nacl_id
        self.region = region
        self.rule_number_start = 100
        self._current_rule = self.rule_number_start

    def block(self, ip: str) -> bool:
        """
        Add DENY entry to Network ACL.
        Note: In simulation mode, this just prints the boto3 call.
        """
        print(f"{C.YELLOW}  [AWS-NACL] Would call:{C.RESET}")
        print(f"    ec2.create_network_acl_entry(")
        print(f"      NetworkAclId='{self.nacl_id}',")
        print(f"      RuleNumber={self._current_rule},")
        print(f"      Protocol='-1',")
        print(f"      RuleAction='deny',")
        print(f"      Egress=False,")
        print(f"      CidrBlock='{ip}/32'")
        print(f"    )")
        self._current_rule += 1
        return True  # Simulated success


class ExportBackend:
    """Export blocklist to file (no actual blocking)."""
    def __init__(self, output_file: str):
        self.output_file = output_file
        self.blocked = []

    def block(self, ip: str) -> bool:
        self.blocked.append(ip)
        return True

    def save(self):
        os.makedirs(os.path.dirname(self.output_file) if os.path.dirname(self.output_file) else ".", exist_ok=True)
        with open(self.output_file, "w") as f:
            f.write(f"# Auto-generated blocklist\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}Z\n")
            f.write(f"# Total IPs: {len(self.blocked)}\n\n")
            for ip in self.blocked:
                f.write(f"{ip}\n")
        print(f"{C.GREEN}[+] Blocklist saved to {self.output_file} ({len(self.blocked)} IPs){C.RESET}")

class AutoIPBlocker:
    def __init__(self, backend: str = "dry-run", dry_run: bool = True):
        self.backend_name = backend
        self.dry_run = dry_run
        self.blocked_count = 0
        self.skipped_count = 0
        self.failed_count = 0
        self.results = []

    def run(self, ip_list: list):
        """Process list of IPs and apply blocking."""
        print(f"\n{C.BOLD}{'═' * 60}")
        print("  🛡️  AUTO IP BLOCKER")
        print(f"  Backend : {self.backend_name.upper()}")
        print(f"  Mode    : {'DRY RUN (no changes)' if self.dry_run else 'LIVE (applying rules)'}")
        print(f"  IPs     : {len(ip_list)} to process")
        print(f"{'═' * 60}{C.RESET}\n")

        for entry in ip_list:
            ip = entry["ip"]
            severity = entry.get("severity", "UNKNOWN")

            # Safety check
            if is_whitelisted(ip):
                print(f"  {C.YELLOW}[SKIP]{C.RESET} {ip} — whitelisted")
                self.skipped_count += 1
                continue

            # Severity color
            color = {
                "CRITICAL": C.RED,
                "HIGH": C.YELLOW,
                "MEDIUM": C.CYAN,
                "LOW": C.BLUE
            }.get(severity, C.BLUE)

            if self.dry_run:
                print(f"  {C.GREEN}[DRY-RUN]{C.RESET} Would block: {color}{ip:<20}{C.RESET} [{severity}]")
                self.blocked_count += 1
                self.results.append({"ip": ip, "severity": severity, "action": "would_block", "status": "dry_run"})
            else:
                success = self._apply_block(ip)
                status = "blocked" if success else "failed"
                symbol = f"{C.GREEN}[BLOCKED]{C.RESET}" if success else f"{C.RED}[FAILED]{C.RESET}"
                print(f"  {symbol} {ip:<20} [{severity}]")

                if success:
                    self.blocked_count += 1
                else:
                    self.failed_count += 1
                self.results.append({"ip": ip, "severity": severity, "action": "block", "status": status})

        self._print_summary()

    def _apply_block(self, ip: str) -> bool:
        """Apply block via selected backend."""
        if self.backend_name == "iptables":
            b = IPTablesBackend()
            return b.block(ip)
        elif self.backend_name == "ufw":
            b = UFWBackend()
            return b.block(ip)
        elif self.backend_name == "aws-nacl":
            b = AWSNACLBackend(nacl_id="acl-0a1b2c3d4e5f67890")
            return b.block(ip)
        else:
            return False

    def _print_summary(self):
        print(f"\n{C.BOLD}── BLOCKING SUMMARY ──────────────────────────{C.RESET}")
        print(f"  Total Processed : {len(self.results)}")
        print(f"  {'Would Block' if self.dry_run else 'Blocked'} : {C.GREEN}{self.blocked_count}{C.RESET}")
        print(f"  Skipped   : {C.YELLOW}{self.skipped_count}{C.RESET}")
        print(f"  Failed    : {C.RED}{self.failed_count}{C.RESET}")

        if self.dry_run:
            print(f"\n  {C.YELLOW}⚠️  DRY RUN MODE — No actual firewall rules were modified.{C.RESET}")
            print(f"  {C.CYAN}   Re-run without --dry-run to apply changes.{C.RESET}")

        # Breakdown by severity
        sev_counts = {}
        for r in self.results:
            s = r.get("severity", "UNKNOWN")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        print(f"\n  Severity Breakdown:")
        for sev, count in sorted(sev_counts.items(), key=lambda x: ["LOW","MEDIUM","HIGH","CRITICAL"].index(x[0]) if x[0] in ["LOW","MEDIUM","HIGH","CRITICAL"] else 99, reverse=True):
            color = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN}.get(sev, C.BLUE)
            print(f"    {color}{sev:<10}{C.RESET}: {count}")

    def save_report(self, output_file: str = "logs/block_report.json"):
        with open(output_file, "w") as f:
            json.dump({
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "backend": self.backend_name,
                "dry_run": self.dry_run,
                "total_blocked": self.blocked_count,
                "results": self.results
            }, f, indent=2)
        print(f"{C.GREEN}[+] Block report saved to {output_file}{C.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="Auto IP Blocker for Honeypot Threat Response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run (show what would be blocked):
  python3 auto_ip_blocker.py --ip-list logs/attacker_ips.txt --dry-run

  # Block only HIGH and above with iptables (requires root):
  sudo python3 auto_ip_blocker.py --ip-list logs/attacker_ips.txt --backend iptables --severity HIGH

  # Extract from logs and dry-run:
  python3 auto_ip_blocker.py --logs logs/cowrie_logs.json --auto-extract --dry-run

  # Export blocklist file:
  python3 auto_ip_blocker.py --ip-list logs/attacker_ips.txt --backend export --output logs/blocklist.txt
        """
    )
    parser.add_argument("--ip-list", help="Path to attacker_ips.txt file")
    parser.add_argument("--logs", help="Path to Cowrie logs (for --auto-extract)")
    parser.add_argument("--auto-extract", action="store_true", help="Extract IPs from Cowrie logs directly")
    parser.add_argument("--backend", choices=["iptables", "ufw", "aws-nacl", "export", "dry-run"],
                        default="dry-run", help="Blocking backend to use")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Simulate without making changes")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        default="LOW", help="Minimum severity to block")
    parser.add_argument("--output", default="logs/blocklist.txt", help="Output file for export backend")
    parser.add_argument("--save-report", action="store_true", help="Save block report to JSON")

    args = parser.parse_args()

    # Force dry-run for export backend
    dry_run = args.dry_run or args.backend == "dry-run"

    # Load IPs
    if args.auto_extract and args.logs:
        ip_list = extract_ips_from_cowrie(args.logs)
        # Apply severity filter
        severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_rank = severity_rank.get(args.severity, 0)
        ip_list = [x for x in ip_list if severity_rank.get(x["severity"], 0) >= min_rank]
    elif args.ip_list:
        ip_list = load_ips_from_file(args.ip_list, args.severity)
    else:
        print(f"{C.RED}[ERROR] Provide --ip-list or --logs + --auto-extract{C.RESET}")
        parser.print_help()
        sys.exit(1)

    if not ip_list:
        print(f"{C.YELLOW}[WARN] No IPs to process after filtering.{C.RESET}")
        sys.exit(0)

    # Run blocker
    blocker = AutoIPBlocker(backend=args.backend, dry_run=dry_run)
    blocker.run(ip_list)

    if args.save_report:
        blocker.save_report()

    # If export backend, save file
    if args.backend == "export":
        exporter = ExportBackend(args.output)
        for entry in ip_list:
            exporter.block(entry["ip"])
        exporter.save()


if __name__ == "__main__":
    main()
