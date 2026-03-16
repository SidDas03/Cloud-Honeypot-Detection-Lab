#!/usr/bin/env python3
"""
ai_triage.py — AI-powered threat triage using Claude API

Takes a honeypot attack session and returns a structured
analyst verdict: intent, skill level, risk score, and response.

Usage:
    python3 scripts/ai_triage.py --test
    python3 scripts/ai_triage.py --all --input logs/cowrie_logs.json
    python3 scripts/ai_triage.py --session logs/cowrie_logs.json --ip 185.220.101.47
    python3 scripts/ai_triage.py --all --api-key YOUR_ANTHROPIC_KEY --output logs/triage_results.json
"""

import json
import os
import sys
import argparse
from datetime import datetime

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
    
MOCK_VERDICTS = {
    "185.220.101.47": {
        "intent": "botnet_recruitment",
        "skill_level": "intermediate",
        "threat_actor_profile": "Automated campaign operator running credential stuffing tools. Downloads and executes Mirai-variant malware immediately after login. Likely part of a DDoS-for-hire operation.",
        "risk_score": 85,
        "recommended_response": "Block IP at perimeter firewall. Scan internal network for Mirai C2 beacons on ports 23 and 2323. Check /tmp for suspicious ELF binaries.",
        "mitre_primary": "T1105 - Ingress Tool Transfer",
        "confidence": "HIGH",
        "iocs": ["193.32.162.157", "http://193.32.162.157/x86", "d4f3a1c2e9b87654"]
    },
    "218.92.0.195": {
        "intent": "espionage_or_ransomware_staging",
        "skill_level": "advanced",
        "threat_actor_profile": "Manual operator with strong post-exploitation tradecraft. Disables firewall then establishes Python reverse shell to port 4444 — consistent with Metasploit handler. Human-operated, not automated.",
        "risk_score": 97,
        "recommended_response": "CRITICAL — Isolate instance immediately. Rotate all credentials. Check CloudTrail for API calls using the instance IAM role. Preserve memory dump for forensics.",
        "mitre_primary": "T1059.006 - Python Reverse Shell",
        "confidence": "HIGH",
        "iocs": ["218.92.0.195:4444", "python3 socket reverse shell"]
    },
    "5.188.206.26": {
        "intent": "persistent_access_establishment",
        "skill_level": "intermediate",
        "threat_actor_profile": "Persistence-focused operator. Installs two redundant backdoors: cron job and new sudo user. Consistent with ransomware pre-positioning or selling access on dark web markets.",
        "risk_score": 92,
        "recommended_response": "Block IP. Remove backdoor_user account. Audit /etc/crontab and all cron directories. Treat as full compromise and rotate credentials.",
        "mitre_primary": "T1053.003 - Scheduled Task: Cron",
        "confidence": "HIGH",
        "iocs": ["5.188.206.26/update.sh", "backdoor_user account", "malicious crontab entry"]
    },
    "45.227.255.190": {
        "intent": "cryptomining",
        "skill_level": "low_intermediate",
        "threat_actor_profile": "Opportunistic cryptominer. Checks CPU count before deploying XMRig — script optimizing for compute resources. Not targeted, purely financial. Causes real billing damage on cloud VMs.",
        "risk_score": 74,
        "recommended_response": "Block IP. Kill xmrig process. Check CPU billing spike. Search /tmp for miner binaries. Add pool.minexmr.com to DNS blocklist.",
        "mitre_primary": "T1496 - Resource Hijacking",
        "confidence": "HIGH",
        "iocs": ["pool.minexmr.com:443", "xmrig binary", "45.227.255.190/xmrig"]
    },
    "80.94.95.130": {
        "intent": "cloud_credential_theft",
        "skill_level": "advanced",
        "threat_actor_profile": "Cloud-aware attacker specifically targeting AWS IAM credentials via IMDS. Searches for .pem keys before querying metadata service. Attempting to pivot to cloud control plane.",
        "risk_score": 95,
        "recommended_response": "CRITICAL — Rotate all IAM credentials immediately. Enable IMDSv2. Check CloudTrail for API calls with the instance IAM role in the last 24 hours.",
        "mitre_primary": "T1552.005 - Cloud Instance Metadata API",
        "confidence": "HIGH",
        "iocs": ["169.254.169.254 IMDS query", "~/.aws/credentials access"]
    },
    "91.92.251.103": {
        "intent": "botnet_recruitment",
        "skill_level": "intermediate",
        "threat_actor_profile": "Botnet operator executing a remote shell script from C2 server. Pattern matches Mirai botnet installer — targets Linux servers for DDoS botnet.",
        "risk_score": 71,
        "recommended_response": "Block IP and C2 host 45.155.205.233. Check for outbound connections to known Mirai C2 infrastructure.",
        "mitre_primary": "T1059.004 - Unix Shell",
        "confidence": "MEDIUM",
        "iocs": ["45.155.205.233/bot.sh", "curl pipe bash execution"]
    }
}

def build_session(events: list, target_ip: str) -> dict:
    """Group all Cowrie events for a specific IP into a session summary."""
    session = {
        "ip": target_ip,
        "total_events": 0,
        "login_attempts": 0,
        "login_successes": 0,
        "credentials_tried": [],
        "commands_executed": [],
        "files_downloaded": [],
        "first_seen": None,
        "last_seen": None
    }

    for event in events:
        if event.get("src_ip") != target_ip:
            continue

        session["total_events"] += 1
        ts = event.get("timestamp")
        if ts:
            if not session["first_seen"] or ts < session["first_seen"]:
                session["first_seen"] = ts
            if not session["last_seen"] or ts > session["last_seen"]:
                session["last_seen"] = ts

        eid = event.get("eventid", "")

        if eid == "cowrie.login.failed":
            session["login_attempts"] += 1
            cred = f"{event.get('username','?')}:{event.get('password','?')}"
            if cred not in session["credentials_tried"]:
                session["credentials_tried"].append(cred)

        elif eid == "cowrie.login.success":
            session["login_successes"] += 1
            cred = f"SUCCESS:{event.get('username','?')}:{event.get('password','?')}"
            session["credentials_tried"].append(cred)

        elif eid == "cowrie.command.input":
            cmd = event.get("input", "")
            if cmd:
                session["commands_executed"].append(cmd)

        elif eid == "cowrie.session.file_download":
            session["files_downloaded"].append({
                "url": event.get("url", ""),
                "sha256": event.get("shasum", "")
            })

    return session

def rule_based_verdict(session: dict) -> dict:
    """Generate a verdict using rules when AI is unavailable."""
    cmds = session.get("commands_executed", [])
    downloads = session.get("files_downloaded", [])
    successes = session.get("login_successes", 0)
    attempts = session.get("login_attempts", 0)
    cmds_str = " ".join(cmds).lower()

    score = 0
    score += successes * 15
    score += min(len(cmds) * 2, 20)
    score += len(downloads) * 10

    intent = "opportunistic_scanning"
    skill = "script_kiddie"
    response = "Block IP at firewall. Monitor for further activity."
    mitre = "T1110 - Brute Force"

    if any(k in cmds_str for k in ["socket", "subprocess", "/bin/sh -i", "4444"]):
        intent, skill, mitre = "espionage_or_ransomware_staging", "advanced", "T1059.006 - Python Reverse Shell"
        response = "CRITICAL: Isolate instance. Rotate all credentials."
        score += 25
    elif any(k in cmds_str for k in ["169.254.169.254", ".aws/credentials", ".pem"]):
        intent, skill, mitre = "cloud_credential_theft", "advanced", "T1552.005 - Cloud Instance Metadata API"
        response = "Rotate IAM credentials immediately. Enable IMDSv2."
        score += 20
    elif any(k in cmds_str for k in ["crontab", "useradd", "/etc/crontab"]):
        intent, skill, mitre = "persistent_access_establishment", "intermediate", "T1053.003 - Scheduled Task: Cron"
        response = "Remove persistence. Audit cron jobs and user accounts."
        score += 20
    elif any(k in cmds_str for k in ["xmrig", "minexmr", "stratum"]):
        intent, skill, mitre = "cryptomining", "low_intermediate", "T1496 - Resource Hijacking"
        response = "Kill miner. Block mining pool domain. Check billing."
        score += 15
    elif downloads:
        intent, skill, mitre = "botnet_recruitment", "intermediate", "T1105 - Ingress Tool Transfer"
        response = "Block C2 host. Scan network for botnet beacons."
        score += 10

    return {
        "intent": intent,
        "skill_level": skill,
        "threat_actor_profile": f"Rule-based: {attempts} login attempts, {successes} successes, {len(cmds)} commands.",
        "risk_score": min(round(score), 100),
        "recommended_response": response,
        "mitre_primary": mitre,
        "confidence": "HIGH" if successes > 0 else ("MEDIUM" if attempts > 5 else "LOW"),
        "iocs": [session.get("ip", "unknown")],
        "_source": "rule_based_fallback",
        "_analyzed_at": datetime.utcnow().isoformat() + "Z"
    }

def ai_triage_session(session: dict, api_key: str = None) -> dict:
    """
    Send session to Claude API for AI triage.
    Falls back to mock or rule-based verdict if no API key.
    """
    ip = session.get("ip", "")

    # No API key — use mock or rule-based
    if not api_key:
        if ip in MOCK_VERDICTS:
            v = MOCK_VERDICTS[ip].copy()
            v["_source"] = "mock_verdict"
            v["_analyzed_at"] = datetime.utcnow().isoformat() + "Z"
            return v
        return rule_based_verdict(session)

    # Call Claude API
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        prompt = f"""You are a senior SOC analyst reviewing a honeypot attack session.
Analyze the session below and return a JSON verdict.

SESSION:
{json.dumps(session, indent=2)}

Return ONLY valid JSON with these exact fields:
{{
  "intent": "cryptomining | botnet_recruitment | espionage_or_ransomware_staging | persistent_access_establishment | cloud_credential_theft | opportunistic_scanning | unknown",
  "skill_level": "script_kiddie | low_intermediate | intermediate | advanced | nation_state",
  "threat_actor_profile": "2-3 sentences on who this attacker likely is and their motivation",
  "risk_score": <integer 0-100>,
  "recommended_response": "specific actionable SOC response steps",
  "mitre_primary": "T#### - Technique Name",
  "confidence": "LOW | MEDIUM | HIGH",
  "iocs": ["list of indicators of compromise"]
}}

Score rules: +15 per successful login, +2 per command (max 20), +10 per download,
+25 for reverse shell, +20 for IMDS/credential theft, +15 for cryptominer, +10 for persistence.
Cap at 100. Return JSON only."""

        msg = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = msg.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        verdict = json.loads(raw.strip())
        verdict["_source"] = "claude-api"
        verdict["_analyzed_at"] = datetime.utcnow().isoformat() + "Z"
        return verdict

    except ImportError:
        print(f"{C.YELLOW}[WARN] Run: pip install anthropic{C.RESET}")
        return rule_based_verdict(session)
    except Exception as e:
        print(f"{C.YELLOW}[WARN] API failed ({e}), using rule-based verdict{C.RESET}")
        return rule_based_verdict(session)

def triage_all(log_file: str, api_key: str = None) -> dict:
    """Triage all IPs that had successful logins."""

    with open(log_file) as f:
        events = json.load(f)

    # Collect IPs with successful logins first, then all others
    priority_ips = set()
    all_ips = set()
    for event in events:
        ip = event.get("src_ip")
        if ip:
            all_ips.add(ip)
            if event.get("eventid") == "cowrie.login.success":
                priority_ips.add(ip)

    print(f"{C.CYAN}[*] {len(all_ips)} unique IPs found, {len(priority_ips)} with successful logins{C.RESET}")
    print(f"{C.CYAN}[*] Triaging {len(priority_ips)} priority sessions...\n{C.RESET}")

    results = {}
    for ip in sorted(priority_ips):
        session = build_session(events, ip)
        print(f"  {C.BLUE}Triaging {ip}...{C.RESET}", end=" ", flush=True)
        verdict = ai_triage_session(session, api_key)
        results[ip] = {"session": session, "verdict": verdict}
        score = verdict.get("risk_score", 0)
        col = C.RED if score >= 80 else (C.YELLOW if score >= 50 else C.GREEN)
        print(f"{col}{score}/100 — {verdict.get('intent')}{C.RESET}")

    return results

def print_verdict(ip: str, result: dict):
    v = result["verdict"]
    s = result["session"]
    score = v.get("risk_score", 0)
    col = C.RED if score >= 80 else (C.YELLOW if score >= 50 else C.GREEN)

    print(f"\n{C.BOLD}{'═' * 62}{C.RESET}")
    print(f"{C.BOLD}  AI VERDICT — {ip}{C.RESET}")
    print(f"{'═' * 62}")
    print(f"  Risk Score    : {col}{score}/100{C.RESET}")
    print(f"  Intent        : {C.CYAN}{v.get('intent')}{C.RESET}")
    print(f"  Skill Level   : {v.get('skill_level')}")
    print(f"  Confidence    : {v.get('confidence')}")
    print(f"  MITRE         : {v.get('mitre_primary')}")
    print(f"  Source        : {v.get('_source')}")
    print(f"\n  {C.BOLD}Profile:{C.RESET}")
    print(f"  {v.get('threat_actor_profile')}")
    print(f"\n  {C.BOLD}Response:{C.RESET}")
    print(f"  {C.YELLOW}{v.get('recommended_response')}{C.RESET}")
    print(f"\n  {C.BOLD}IOCs:{C.RESET}")
    for ioc in v.get("iocs", []):
        print(f"  → {ioc}")
    print(f"\n  {C.BOLD}Session:{C.RESET} {s.get('login_attempts')} attempts / "
          f"{s.get('login_successes')} successes / "
          f"{len(s.get('commands_executed', []))} commands / "
          f"{len(s.get('files_downloaded', []))} downloads")
    
def main():
    parser = argparse.ArgumentParser(
        description="AI-powered honeypot threat triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/ai_triage.py --test
  python3 scripts/ai_triage.py --all --input logs/cowrie_logs.json
  python3 scripts/ai_triage.py --session logs/cowrie_logs.json --ip 218.92.0.195
  python3 scripts/ai_triage.py --all --api-key sk-ant-... --output logs/triage.json
        """
    )
    parser.add_argument("--test", action="store_true", help="Run with mock verdicts, no API key needed")
    parser.add_argument("--all", action="store_true", help="Triage all IPs with successful logins")
    parser.add_argument("--input", default="logs/cowrie_logs.json", help="Cowrie log file path")
    parser.add_argument("--session", help="Cowrie log file (for single IP mode)")
    parser.add_argument("--ip", help="Specific IP to triage")
    parser.add_argument("--api-key", default=None, help="Anthropic API key")
    parser.add_argument("--output", default=None, help="Save results to JSON file")

    args = parser.parse_args()
    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")

    print(f"{C.BOLD}{'=' * 62}{C.RESET}")
    print(f"{C.BOLD}  🤖 AI THREAT TRIAGE ENGINE — Cloud Honeypot Lab{C.RESET}")
    print(f"{'=' * 62}")

    if api_key:
        print(f"{C.GREEN}[+] API key found — using Claude AI for analysis{C.RESET}")
    else:
        print(f"{C.YELLOW}[~] No API key — using mock/rule-based verdicts{C.RESET}")
        print(f"    Set ANTHROPIC_API_KEY env var or pass --api-key to use real AI")

    # Run modes
    if args.test or args.all:
        log = args.input
        if not os.path.exists(log):
            print(f"{C.RED}[ERROR] Not found: {log}{C.RESET}")
            sys.exit(1)
        results = triage_all(log, api_key)
        for ip, result in results.items():
            print_verdict(ip, result)

        if args.output:
            os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n{C.GREEN}[+] Results saved → {args.output}{C.RESET}")

    elif args.session and args.ip:
        if not os.path.exists(args.session):
            print(f"{C.RED}[ERROR] Not found: {args.session}{C.RESET}")
            sys.exit(1)
        with open(args.session) as f:
            events = json.load(f)
        session = build_session(events, args.ip)
        if session["total_events"] == 0:
            print(f"{C.YELLOW}[WARN] No events for IP {args.ip}{C.RESET}")
            sys.exit(0)
        print(f"\n{C.CYAN}[*] Triaging {args.ip}...{C.RESET}")
        verdict = ai_triage_session(session, api_key)
        print_verdict(args.ip, {"session": session, "verdict": verdict})

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
