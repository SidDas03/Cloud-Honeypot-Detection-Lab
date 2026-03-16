#!/usr/bin/env python3
"""
normalizer.py — Normalize logs from multiple sources into a unified schema

Takes raw logs from Cowrie, GuardDuty, or Linux syslog auth.log
and outputs a standard format the pipeline can process.

Usage:
    python3 scripts/normalizer.py --input logs/cowrie_logs.json --source cowrie
    python3 scripts/normalizer.py --input logs/guardduty_findings.json --source guardduty
    python3 scripts/normalizer.py --demo
"""

import json
import argparse
import os
import re
import sys
from datetime import datetime


class C:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


# ─────────────────────────────────────────────
# Unified Event Schema
# ─────────────────────────────────────────────
def make_event(src_ip, event_type, detail, timestamp,
               username=None, severity=None, source_system=None):
    """Creates a normalized event in the unified schema."""
    return {
        "timestamp":     timestamp,
        "src_ip":        src_ip,
        "event_type":    event_type,
        "detail":        detail,
        "username":      username,
        "severity":      severity or "INFO",
        "source_system": source_system or "unknown",
        "normalized_at": datetime.utcnow().isoformat() + "Z"
    }


# ─────────────────────────────────────────────
# Cowrie Normalizer
# ─────────────────────────────────────────────
def normalize_cowrie(raw_events: list) -> list:
    """Normalize Cowrie SSH honeypot JSON logs."""
    normalized = []

    event_map = {
        "cowrie.session.connect":      ("CONNECTION",    "INFO"),
        "cowrie.login.failed":         ("LOGIN_FAILED",  "LOW"),
        "cowrie.login.success":        ("LOGIN_SUCCESS", "HIGH"),
        "cowrie.command.input":        ("COMMAND_RUN",   "MEDIUM"),
        "cowrie.session.file_download":("FILE_DOWNLOAD", "HIGH"),
        "cowrie.session.closed":       ("SESSION_CLOSED","INFO"),
    }

    for raw in raw_events:
        eid = raw.get("eventid", "")
        event_type, severity = event_map.get(eid, ("UNKNOWN", "INFO"))

        # Elevate severity for dangerous commands
        if eid == "cowrie.command.input":
            cmd = raw.get("input", "").lower()
            if any(k in cmd for k in ["169.254.169.254", "socket", "/bin/sh -i", "4444"]):
                severity = "CRITICAL"
            elif any(k in cmd for k in ["crontab", "useradd", "xmrig", "wget", "curl"]):
                severity = "HIGH"

        detail = (raw.get("input")
                  or raw.get("url")
                  or raw.get("password")
                  or raw.get("message", ""))

        normalized.append(make_event(
            src_ip        = raw.get("src_ip", "unknown"),
            event_type    = event_type,
            detail        = str(detail)[:300],
            timestamp     = raw.get("timestamp", ""),
            username      = raw.get("username"),
            severity      = severity,
            source_system = "cowrie"
        ))

    return normalized


# ─────────────────────────────────────────────
# GuardDuty Normalizer
# ─────────────────────────────────────────────
def normalize_guardduty(raw: dict) -> list:
    """Normalize AWS GuardDuty findings JSON."""
    normalized = []
    findings = raw.get("findings", [])

    sev_map = {
        range(0, 4):   "LOW",
        range(4, 7):   "MEDIUM",
        range(7, 9):   "HIGH",
        range(9, 11):  "CRITICAL"
    }

    def map_severity(score):
        for r, label in sev_map.items():
            if int(score) in r:
                return label
        return "HIGH"

    for finding in findings:
        try:
            net_action = (finding.get("service", {})
                                 .get("action", {})
                                 .get("networkConnectionAction", {}))
            remote_ip = (net_action.get("remoteIpDetails", {})
                                   .get("ipAddressV4", "unknown"))
        except Exception:
            remote_ip = "unknown"

        sev_score = finding.get("severity", 5)

        normalized.append(make_event(
            src_ip        = remote_ip,
            event_type    = "GUARDDUTY_FINDING",
            detail        = finding.get("type", "") + ": " + finding.get("description", "")[:200],
            timestamp     = finding.get("createdAt", ""),
            severity      = map_severity(sev_score),
            source_system = "guardduty"
        ))

    return normalized


# ─────────────────────────────────────────────
# Syslog auth.log Normalizer
# ─────────────────────────────────────────────
def normalize_syslog(lines: list) -> list:
    """
    Normalize Linux /var/log/auth.log lines.
    Handles: Failed password, Accepted password, Invalid user
    """
    normalized = []

    # Regex patterns for common auth.log entries
    patterns = [
        (r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)",
         "LOGIN_FAILED", "LOW"),
        (r"Failed password for invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)",
         "LOGIN_FAILED_INVALID_USER", "MEDIUM"),
        (r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)",
         "LOGIN_SUCCESS", "HIGH"),
        (r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)",
         "INVALID_USER", "MEDIUM"),
        (r"Connection closed by (\d+\.\d+\.\d+\.\d+)",
         "CONNECTION_CLOSED", "INFO"),
    ]

    # Rough timestamp extraction from syslog format
    ts_pattern = re.compile(r"^(\w+\s+\d+\s+\d+:\d+:\d+)")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        ts_match = ts_pattern.match(line)
        timestamp = ts_match.group(1) if ts_match else ""

        for pattern, event_type, severity in patterns:
            match = re.search(pattern, line)
            if match:
                groups = match.groups()
                username = groups[0] if len(groups) >= 1 else None
                src_ip   = groups[1] if len(groups) >= 2 else groups[0]

                normalized.append(make_event(
                    src_ip        = src_ip,
                    event_type    = event_type,
                    detail        = line[:300],
                    timestamp     = timestamp,
                    username      = username,
                    severity      = severity,
                    source_system = "syslog_auth"
                ))
                break

    return normalized


# ─────────────────────────────────────────────
# Auto-detect source type
# ─────────────────────────────────────────────
def detect_source(filepath: str) -> str:
    """Try to auto-detect log source from file content."""
    try:
        with open(filepath) as f:
            content = f.read(500)
        if "eventid" in content and "cowrie" in content:
            return "cowrie"
        if "guardduty" in content.lower() or "findings" in content.lower():
            return "guardduty"
        if "Failed password" in content or "Accepted password" in content:
            return "syslog"
    except Exception:
        pass
    return "unknown"


# ─────────────────────────────────────────────
# Main normalize function
# ─────────────────────────────────────────────
def normalize(filepath: str, source: str = "auto") -> list:
    """Normalize a log file. Returns list of unified events."""

    if not os.path.exists(filepath):
        print(f"{C.RED}[ERROR] File not found: {filepath}{C.RESET}")
        return []

    if source == "auto":
        source = detect_source(filepath)
        print(f"{C.CYAN}[*] Auto-detected source type: {source}{C.RESET}")

    if source == "cowrie":
        with open(filepath) as f:
            raw = json.load(f)
        events = normalize_cowrie(raw)

    elif source == "guardduty":
        with open(filepath) as f:
            raw = json.load(f)
        events = normalize_guardduty(raw)

    elif source == "syslog":
        with open(filepath) as f:
            lines = f.readlines()
        events = normalize_syslog(lines)

    else:
        print(f"{C.RED}[ERROR] Unknown source type: {source}{C.RESET}")
        print(f"  Supported: cowrie, guardduty, syslog")
        return []

    print(f"{C.GREEN}[+] Normalized {len(events)} events from {source}{C.RESET}")
    return events


# ─────────────────────────────────────────────
# Stats summary
# ─────────────────────────────────────────────
def print_stats(events: list):
    from collections import Counter
    types   = Counter(e["event_type"] for e in events)
    sevs    = Counter(e["severity"]   for e in events)
    sources = Counter(e["source_system"] for e in events)
    ips     = Counter(e["src_ip"] for e in events)

    print(f"\n{C.BOLD}── NORMALIZATION SUMMARY ─────────────────────{C.RESET}")
    print(f"  Total events  : {len(events)}")
    print(f"  Unique IPs    : {len(ips)}")

    print(f"\n  Severity breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sevs.get(sev, 0)
        if count:
            col = C.RED if sev=="CRITICAL" else (C.YELLOW if sev=="HIGH" else "")
            print(f"    {col}{sev:<10}{C.RESET}: {count}")

    print(f"\n  Event types:")
    for etype, count in types.most_common(8):
        print(f"    {etype:<35}: {count}")

    print(f"\n  Top 5 attacker IPs:")
    for ip, count in ips.most_common(5):
        print(f"    {ip:<22}: {count} events")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Normalize honeypot logs from multiple sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/normalizer.py --input logs/cowrie_logs.json --source cowrie
  python3 scripts/normalizer.py --input logs/guardduty_findings.json --source guardduty
  python3 scripts/normalizer.py --input /var/log/auth.log --source syslog
  python3 scripts/normalizer.py --input logs/cowrie_logs.json --output logs/normalized.json
  python3 scripts/normalizer.py --demo
        """
    )
    parser.add_argument("--input",  "-i", help="Input log file path")
    parser.add_argument("--source", "-s", default="auto",
                        choices=["auto", "cowrie", "guardduty", "syslog"],
                        help="Log source type (default: auto-detect)")
    parser.add_argument("--output", "-o", help="Save normalized events to JSON file")
    parser.add_argument("--demo",   action="store_true", help="Run demo with existing log files")

    args = parser.parse_args()

    print(f"{C.BOLD}{'=' * 50}{C.RESET}")
    print(f"{C.BOLD}  📋 LOG NORMALIZER — Cloud Honeypot Lab{C.RESET}")
    print(f"{'=' * 50}")

    if args.demo:
        all_events = []

        cowrie_path = "logs/cowrie_logs.json"
        gd_path     = "logs/guardduty_findings.json"

        if os.path.exists(cowrie_path):
            print(f"\n{C.CYAN}[1/2] Normalizing Cowrie logs...{C.RESET}")
            all_events += normalize(cowrie_path, "cowrie")

        if os.path.exists(gd_path):
            print(f"\n{C.CYAN}[2/2] Normalizing GuardDuty findings...{C.RESET}")
            all_events += normalize(gd_path, "guardduty")

        print_stats(all_events)

        output = "logs/normalized_events.json"
        os.makedirs("logs", exist_ok=True)
        with open(output, "w") as f:
            json.dump(all_events, f, indent=2)
        print(f"\n{C.GREEN}[+] Saved {len(all_events)} normalized events → {output}{C.RESET}")

    elif args.input:
        events = normalize(args.input, args.source)
        print_stats(events)

        if args.output:
            os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
            with open(args.output, "w") as f:
                json.dump(events, f, indent=2)
            print(f"\n{C.GREEN}[+] Saved → {args.output}{C.RESET}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
