#!/usr/bin/env python3
"""
pipeline.py — Automated end-to-end threat detection and response pipeline

This is the system integrator's centrepiece. Chains every component:

  Cowrie Logs ──► Normalize ──► Extract IPs ──► Threat Analysis
                                                       │
                                             ┌─────────┘
                                             ▼
                                       AI Triage (Claude)
                                             │
                                  ┌──────────┴──────────┐
                                  ▼                     ▼
                             Slack/Email Alert     Auto IP Block
                                             │
                                             ▼
                                      pipeline_report.json

Usage:
    python3 pipeline.py                           # dry-run, console alerts
    python3 pipeline.py --api-key sk-ant-...      # with real AI triage
    python3 pipeline.py --slack-webhook URL       # with Slack alerts
    python3 pipeline.py --live-block              # actually block IPs (root)
"""

import json
import os
import sys
import argparse
import time
from datetime import datetime


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.normalizer      import normalize
from scripts.ip_extractor    import IPExtractor
from scripts.threat_analysis import ThreatAnalyzer
from scripts.ai_triage       import triage_all
from scripts.auto_ip_blocker import AutoIPBlocker
from scripts.notifier        import build_notifier, SlackNotifier


class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


def banner(step, total, title):
    print(f"\n{C.BOLD}{C.BLUE}[{step}/{total}] {title}{C.RESET}")
    print(f"      {'─' * (len(title) + 4)}")

def ok(msg):   print(f"      {C.GREEN}✔  {msg}{C.RESET}")
def warn(msg): print(f"      {C.YELLOW}⚠  {msg}{C.RESET}")
def info(msg): print(f"      {C.CYAN}→  {msg}{C.RESET}")
def err(msg):  print(f"      {C.RED}✘  {msg}{C.RESET}")


class HoneypotPipeline:

    def __init__(self, config: dict):
        self.cowrie_log      = config.get("cowrie_log",      "logs/cowrie_logs.json")
        self.gd_log          = config.get("gd_log",          "logs/guardduty_findings.json")
        self.api_key         = config.get("api_key")         or os.environ.get("ANTHROPIC_API_KEY")
        self.dry_run         = config.get("dry_run",         True)
        self.alert_threshold = config.get("alert_threshold", 60)
        self.notifier        = build_notifier(config.get("notifier", {"type": "console"}))

        self.report = {
            "started_at":        datetime.utcnow().isoformat() + "Z",
            "finished_at":       None,
            "steps_completed":   [],
            "normalized_events": 0,
            "unique_ips":        0,
            "successful_logins": 0,
            "triage_results":    {},
            "alerts_sent":       0,
            "ips_blocked":       0,
            "errors":            []
        }

    def step_normalize(self):
        banner(1, 5, "Normalizing log sources")
        total = 0

        if os.path.exists(self.cowrie_log):
            events = normalize(self.cowrie_log, "cowrie")
            total += len(events)
            ok(f"Cowrie logs: {len(events)} events")
        else:
            warn(f"Cowrie log not found: {self.cowrie_log}")

        if os.path.exists(self.gd_log):
            events = normalize(self.gd_log, "guardduty")
            total += len(events)
            ok(f"GuardDuty findings: {len(events)} events")
        else:
            info("GuardDuty log not found — skipping")

        self.report["normalized_events"] = total
        self.report["steps_completed"].append("normalize")
        info(f"Total: {total} events normalized")

    def step_extract_ips(self):
        banner(2, 5, "Extracting and scoring attacker IPs")

        ex = IPExtractor(self.cowrie_log)
        if not ex.load_logs():
            err("Could not load logs for IP extraction")
            return

        ex.parse_events()
        unique     = len(ex.ip_stats)
        successful = sum(1 for s in ex.ip_stats.values() if s["login_successes"] > 0)

        self.report["unique_ips"]        = unique
        self.report["successful_logins"] = successful
        self.report["steps_completed"].append("extract_ips")

        ok(f"{unique} unique attacker IPs found")
        ok(f"{successful} IPs with successful logins")

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for ip, stats in ex.ip_stats.items():
            sev = ex.get_severity(stats)
            counts[sev] = counts.get(sev, 0) + 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts[sev]:
                col = C.RED if sev == "CRITICAL" else (C.YELLOW if sev == "HIGH" else "")
                info(f"  {col}{sev}: {counts[sev]} IPs{C.RESET}")

    def step_threat_analysis(self):
        banner(3, 5, "Threat analysis + MITRE ATT&CK mapping")

        analyzer = ThreatAnalyzer(self.cowrie_log, self.gd_log)
        analyzer.load_data()
        report = analyzer.analyze()

        tactics = report.get("mitre_summary", {}).get("tactics_observed", {})
        for tactic, count in list(tactics.items())[:5]:
            info(f"  {tactic}: {count}")

        iocs = report.get("iocs", {})
        ok(f"IOCs: {len(iocs.get('malicious_ips', []))} IPs, "
           f"{len(iocs.get('malicious_urls', []))} URLs")

        self.report["steps_completed"].append("threat_analysis")

    def step_ai_triage(self) -> dict:
        banner(4, 5, "AI triage — classifying sessions with Claude")

        if self.api_key:
            ok("Anthropic API key found — using Claude AI")
        else:
            warn("No API key — using mock/rule-based verdicts")
            info("Set ANTHROPIC_API_KEY to enable real AI analysis")

        triage = triage_all(self.cowrie_log, self.api_key)

        self.report["triage_results"] = {
            ip: {
                "risk_score": r["verdict"].get("risk_score", 0),
                "intent":     r["verdict"].get("intent"),
                "skill":      r["verdict"].get("skill_level"),
                "response":   r["verdict"].get("recommended_response"),
                "source":     r["verdict"].get("_source")
            }
            for ip, r in triage.items()
        }
        self.report["steps_completed"].append("ai_triage")

        high_risk = [(ip, r) for ip, r in triage.items()
                     if r["verdict"].get("risk_score", 0) >= self.alert_threshold]
        ok(f"{len(triage)} sessions triaged")
        ok(f"{len(high_risk)} above alert threshold (score >= {self.alert_threshold})")
        return triage
      
    def step_alert_and_block(self, triage: dict):
        banner(5, 5, "Sending alerts and blocking malicious IPs")

        alerts_sent  = 0
        ips_to_block = []

        for ip, result in sorted(triage.items(),
                                 key=lambda x: x[1]["verdict"].get("risk_score", 0),
                                 reverse=True):
            score = result["verdict"].get("risk_score", 0)
            if score >= self.alert_threshold:
                info(f"Alerting: {ip} (score {score}/100)")
                if self.notifier.send_alert(ip, result["verdict"], result["session"]):
                    alerts_sent += 1
                ips_to_block.append({"ip": ip, "severity": "HIGH"})

        if isinstance(self.notifier, SlackNotifier) and triage:
            self.notifier.send_summary(triage)

        if ips_to_block:
            mode = "iptables" if not self.dry_run else "dry-run"
            blocker = AutoIPBlocker(backend=mode, dry_run=self.dry_run)
            blocker.run(ips_to_block)

        self.report["alerts_sent"] = alerts_sent
        self.report["ips_blocked"] = len(ips_to_block)
        self.report["steps_completed"].append("alert_and_block")

        ok(f"{alerts_sent} alerts sent")
        ok(f"{len(ips_to_block)} IPs {'blocked' if not self.dry_run else 'flagged (dry-run)'}")

    def save_report(self, path="logs/pipeline_report.json"):
        self.report["finished_at"] = datetime.utcnow().isoformat() + "Z"
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.report, f, indent=2)
        ok(f"Report saved → {path}")

    def run(self):
        print(f"\n{C.BOLD}{'═' * 60}{C.RESET}")
        print(f"{C.BOLD}  🍯 CLOUD HONEYPOT — AUTOMATED THREAT PIPELINE{C.RESET}")
        print(f"  {'─' * 58}")
        print(f"  Cowrie Log   : {self.cowrie_log}")
        print(f"  GD Log       : {self.gd_log}")
        print(f"  AI Engine    : {'Claude API' if self.api_key else 'Mock/Rule-based'}")
        print(f"  Mode         : {'LIVE BLOCKING ⚡' if not self.dry_run else 'DRY RUN (safe)'}")
        print(f"  Alert Level  : Risk score >= {self.alert_threshold}")
        print(f"{'═' * 60}\n")

        t0 = time.time()

        try:
            self.step_normalize()
            self.step_extract_ips()
            self.step_threat_analysis()
            triage = self.step_ai_triage()
            self.step_alert_and_block(triage)
        except KeyboardInterrupt:
            warn("Pipeline interrupted by user")
        except Exception as e:
            err(f"Pipeline error: {e}")
            self.report["errors"].append(str(e))
            import traceback; traceback.print_exc()

        elapsed = round(time.time() - t0, 2)
        self.save_report()

        print(f"\n{C.BOLD}{'─' * 60}{C.RESET}")
        print(f"{C.BOLD}  PIPELINE COMPLETE  ({elapsed}s){C.RESET}")
        print(f"{'─' * 60}")
        print(f"  Steps done       : {len(self.report['steps_completed'])}/5")
        print(f"  Events processed : {self.report['normalized_events']}")
        print(f"  Unique attackers : {self.report['unique_ips']}")
        print(f"  Logins captured  : {self.report['successful_logins']}")
        print(f"  Alerts sent      : {self.report['alerts_sent']}")
        print(f"  IPs blocked      : {self.report['ips_blocked']}")
        print(f"{'═' * 60}\n")

def main():
    parser = argparse.ArgumentParser(
        description="Automated honeypot threat pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pipeline.py
  python3 pipeline.py --api-key sk-ant-YOUR_KEY
  python3 pipeline.py --slack-webhook https://hooks.slack.com/services/...
  python3 pipeline.py --api-key sk-ant-... --slack-webhook https://...
  sudo python3 pipeline.py --live-block --api-key sk-ant-...

  # Or use environment variables (recommended):
  export ANTHROPIC_API_KEY=sk-ant-...
  export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
  python3 pipeline.py
        """
    )
    parser.add_argument("--cowrie-log",      default="logs/cowrie_logs.json")
    parser.add_argument("--gd-log",          default="logs/guardduty_findings.json")
    parser.add_argument("--api-key",         default=None, help="Anthropic API key")
    parser.add_argument("--slack-webhook",   default=None, help="Slack webhook URL")
    parser.add_argument("--email-sender",    default=None)
    parser.add_argument("--email-password",  default=None)
    parser.add_argument("--email-recipient", default=None)
    parser.add_argument("--live-block",      action="store_true", help="Actually block IPs (needs root)")
    parser.add_argument("--alert-threshold", type=int, default=60)
    args = parser.parse_args()

    if args.slack_webhook or os.environ.get("SLACK_WEBHOOK_URL"):
        notifier = {"type": "slack",
                    "webhook_url": args.slack_webhook or os.environ.get("SLACK_WEBHOOK_URL")}
    elif args.email_sender:
        notifier = {"type": "email", "sender": args.email_sender,
                    "password": args.email_password, "recipient": args.email_recipient}
    else:
        notifier = {"type": "console"}

    pipeline = HoneypotPipeline({
        "cowrie_log":      args.cowrie_log,
        "gd_log":          args.gd_log,
        "api_key":         args.api_key,
        "dry_run":         not args.live_block,
        "alert_threshold": args.alert_threshold,
        "notifier":        notifier,
    })
    pipeline.run()


if __name__ == "__main__":
    main()
