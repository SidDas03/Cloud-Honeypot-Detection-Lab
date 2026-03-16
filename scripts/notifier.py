#!/usr/bin/env python3
"""
notifier.py — Alert delivery for honeypot threat events

Supports:
  - Slack webhook (free, 5 min setup)
  - Email via Gmail SMTP
  - Console/log fallback

Usage (standalone test):
    python3 scripts/notifier.py --test-slack --webhook https://hooks.slack.com/...
    python3 scripts/notifier.py --test-email --to your@email.com
"""

import json
import os
import smtplib
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


# ─────────────────────────────────────────────
# Slack Notifier
# ─────────────────────────────────────────────
class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_alert(self, ip: str, verdict: dict, session: dict) -> bool:
        """Send a formatted Slack alert for a threat verdict."""
        if not REQUESTS_AVAILABLE:
            print(f"{C.YELLOW}[WARN] requests not installed. Run: pip install requests{C.RESET}")
            return False

        score = verdict.get("risk_score", 0)
        intent = verdict.get("intent", "unknown")
        skill = verdict.get("skill_level", "unknown")
        response = verdict.get("recommended_response", "N/A")
        mitre = verdict.get("mitre_primary", "N/A")
        confidence = verdict.get("confidence", "N/A")

        color = "danger" if score >= 80 else ("warning" if score >= 50 else "good")
        emoji = "🚨" if score >= 80 else ("⚠️" if score >= 50 else "ℹ️")

        payload = {
            "text": f"{emoji} *HONEYPOT ALERT* — Threat detected from `{ip}`",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Attacker IP",     "value": ip,           "short": True},
                        {"title": "Risk Score",       "value": f"{score}/100","short": True},
                        {"title": "Intent",           "value": intent,       "short": True},
                        {"title": "Skill Level",      "value": skill,        "short": True},
                        {"title": "Confidence",       "value": confidence,   "short": True},
                        {"title": "MITRE Technique",  "value": mitre,        "short": True},
                        {"title": "Login Successes",  "value": str(session.get("login_successes", 0)), "short": True},
                        {"title": "Commands Run",     "value": str(len(session.get("commands_executed", []))), "short": True},
                        {"title": "Recommended Action", "value": response,  "short": False},
                    ],
                    "footer": f"Cloud Honeypot Lab | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }

        # Add IOCs if present
        iocs = verdict.get("iocs", [])
        if iocs:
            payload["attachments"].append({
                "color": "#888888",
                "title": "Indicators of Compromise",
                "text": "\n".join([f"• {ioc}" for ioc in iocs]),
                "mrkdwn_in": ["text"]
            })

        try:
            r = requests.post(self.webhook_url, json=payload, timeout=10)
            if r.status_code == 200:
                print(f"{C.GREEN}[+] Slack alert sent for {ip}{C.RESET}")
                return True
            else:
                print(f"{C.RED}[ERROR] Slack returned {r.status_code}: {r.text}{C.RESET}")
                return False
        except Exception as e:
            print(f"{C.RED}[ERROR] Slack send failed: {e}{C.RESET}")
            return False

    def send_summary(self, results: dict) -> bool:
        """Send a summary of all triage results."""
        if not REQUESTS_AVAILABLE:
            return False

        total = len(results)
        critical = sum(1 for r in results.values() if r["verdict"].get("risk_score", 0) >= 80)
        high = sum(1 for r in results.values() if 50 <= r["verdict"].get("risk_score", 0) < 80)

        lines = []
        for ip, r in sorted(results.items(), key=lambda x: x[1]["verdict"].get("risk_score", 0), reverse=True):
            score = r["verdict"].get("risk_score", 0)
            intent = r["verdict"].get("intent", "unknown")
            lines.append(f"• `{ip}` — Score: {score}/100 — {intent}")

        payload = {
            "text": f"📊 *Honeypot Pipeline Complete* — {total} sessions triaged",
            "attachments": [{
                "color": "danger" if critical > 0 else "warning",
                "fields": [
                    {"title": "Total Sessions", "value": str(total),    "short": True},
                    {"title": "Critical (80+)", "value": str(critical), "short": True},
                    {"title": "High (50-79)",   "value": str(high),     "short": True},
                ],
                "text": "\n".join(lines),
                "footer": f"Cloud Honeypot Lab | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
            }]
        }

        try:
            r = requests.post(self.webhook_url, json=payload, timeout=10)
            return r.status_code == 200
        except Exception:
            return False


# ─────────────────────────────────────────────
# Email Notifier
# ─────────────────────────────────────────────
class EmailNotifier:
    def __init__(self, sender: str, password: str, recipient: str,
                 smtp_server: str = "smtp.gmail.com", smtp_port: int = 587):
        self.sender = sender
        self.password = password
        self.recipient = recipient
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def send_alert(self, ip: str, verdict: dict, session: dict) -> bool:
        """Send email alert for a threat verdict."""
        score = verdict.get("risk_score", 0)
        intent = verdict.get("intent", "unknown")
        severity = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else "MEDIUM")

        subject = f"[HONEYPOT {severity}] {intent.upper()} from {ip} — Risk {score}/100"

        body = f"""
HONEYPOT THREAT ALERT
{'=' * 50}

Attacker IP     : {ip}
Risk Score      : {score}/100
Intent          : {intent}
Skill Level     : {verdict.get('skill_level')}
Confidence      : {verdict.get('confidence')}
MITRE Technique : {verdict.get('mitre_primary')}
Detected At     : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

THREAT ACTOR PROFILE
{'-' * 50}
{verdict.get('threat_actor_profile')}

RECOMMENDED RESPONSE
{'-' * 50}
{verdict.get('recommended_response')}

INDICATORS OF COMPROMISE
{'-' * 50}
{chr(10).join(['• ' + ioc for ioc in verdict.get('iocs', [])])}

SESSION STATISTICS
{'-' * 50}
Login Attempts  : {session.get('login_attempts', 0)}
Successful Logins: {session.get('login_successes', 0)}
Commands Executed: {len(session.get('commands_executed', []))}
Files Downloaded : {len(session.get('files_downloaded', []))}

TOP COMMANDS OBSERVED
{'-' * 50}
{chr(10).join(['$ ' + cmd for cmd in session.get('commands_executed', [])[:5]])}

--
Cloud Honeypot Detection Lab
Automated Alert System
        """.strip()

        msg = MIMEMultipart()
        msg["From"] = self.sender
        msg["To"] = self.recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(self.sender, self.password)
                server.sendmail(self.sender, self.recipient, msg.as_string())
            print(f"{C.GREEN}[+] Email alert sent to {self.recipient} for {ip}{C.RESET}")
            return True
        except smtplib.SMTPAuthenticationError:
            print(f"{C.RED}[ERROR] Email auth failed. Use Gmail App Password, not your main password.{C.RESET}")
            print(f"        Guide: https://support.google.com/accounts/answer/185833")
            return False
        except Exception as e:
            print(f"{C.RED}[ERROR] Email send failed: {e}{C.RESET}")
            return False


# ─────────────────────────────────────────────
# Console Notifier (fallback / always works)
# ─────────────────────────────────────────────
class ConsoleNotifier:
    def send_alert(self, ip: str, verdict: dict, session: dict) -> bool:
        score = verdict.get("risk_score", 0)
        col = C.RED if score >= 80 else (C.YELLOW if score >= 50 else C.CYAN)
        print(f"\n{col}{'━' * 55}{C.RESET}")
        print(f"{col}  ALERT: {ip} | Score: {score}/100 | {verdict.get('intent')}{C.RESET}")
        print(f"  Response: {verdict.get('recommended_response')}")
        print(f"{col}{'━' * 55}{C.RESET}")
        return True


# ─────────────────────────────────────────────
# Notifier Factory
# ─────────────────────────────────────────────
def build_notifier(config: dict):
    """
    Build the right notifier from config dict.

    Config example:
        {"type": "slack", "webhook_url": "https://hooks.slack.com/..."}
        {"type": "email", "sender": "...", "password": "...", "recipient": "..."}
        {"type": "console"}
    """
    t = config.get("type", "console")

    if t == "slack":
        webhook = config.get("webhook_url") or os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook:
            print(f"{C.YELLOW}[WARN] No Slack webhook. Set SLACK_WEBHOOK_URL or pass webhook_url in config.{C.RESET}")
            return ConsoleNotifier()
        return SlackNotifier(webhook)

    elif t == "email":
        sender    = config.get("sender")    or os.environ.get("ALERT_EMAIL_SENDER")
        password  = config.get("password")  or os.environ.get("ALERT_EMAIL_PASSWORD")
        recipient = config.get("recipient") or os.environ.get("ALERT_EMAIL_RECIPIENT")
        if not all([sender, password, recipient]):
            print(f"{C.YELLOW}[WARN] Email config incomplete. Falling back to console.{C.RESET}")
            return ConsoleNotifier()
        return EmailNotifier(sender, password, recipient)

    else:
        return ConsoleNotifier()


# ─────────────────────────────────────────────
# Standalone test
# ─────────────────────────────────────────────
def _test_notification(notifier_type: str, **kwargs):
    """Send a test alert using mock data."""
    mock_verdict = {
        "intent": "cryptomining",
        "skill_level": "intermediate",
        "threat_actor_profile": "Test alert — automated pipeline verification. Not a real threat.",
        "risk_score": 74,
        "recommended_response": "This is a test. No action needed.",
        "mitre_primary": "T1496 - Resource Hijacking",
        "confidence": "HIGH",
        "iocs": ["test.malicious-host.example", "xmrig-binary-sha256-test"]
    }
    mock_session = {
        "login_attempts": 5,
        "login_successes": 1,
        "commands_executed": ["id", "uname -a", "./xmrig --pool stratum+tcp://..."],
        "files_downloaded": [{"url": "http://test.example/xmrig", "sha256": "abc123"}]
    }
    test_ip = "1.2.3.4"

    if notifier_type == "slack":
        n = SlackNotifier(kwargs["webhook"])
    elif notifier_type == "email":
        n = EmailNotifier(kwargs["sender"], kwargs["password"], kwargs["to"])
    else:
        n = ConsoleNotifier()

    print(f"{C.CYAN}[*] Sending test alert via {notifier_type}...{C.RESET}")
    success = n.send_alert(test_ip, mock_verdict, mock_session)
    if success:
        print(f"{C.GREEN}[+] Test alert delivered successfully!{C.RESET}")
    else:
        print(f"{C.RED}[-] Test alert failed.{C.RESET}")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Honeypot alert notifier")
    parser.add_argument("--test-slack", action="store_true")
    parser.add_argument("--test-email", action="store_true")
    parser.add_argument("--test-console", action="store_true")
    parser.add_argument("--webhook", help="Slack webhook URL")
    parser.add_argument("--sender", help="Gmail sender address")
    parser.add_argument("--password", help="Gmail App Password")
    parser.add_argument("--to", help="Recipient email")
    args = parser.parse_args()

    if args.test_slack:
        webhook = args.webhook or os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook:
            print(f"{C.RED}[ERROR] Provide --webhook or set SLACK_WEBHOOK_URL{C.RESET}")
            print("  Get a free webhook at: https://api.slack.com/messaging/webhooks")
            return
        _test_notification("slack", webhook=webhook)

    elif args.test_email:
        sender   = args.sender   or os.environ.get("ALERT_EMAIL_SENDER")
        password = args.password or os.environ.get("ALERT_EMAIL_PASSWORD")
        to       = args.to       or os.environ.get("ALERT_EMAIL_RECIPIENT")
        if not all([sender, password, to]):
            print(f"{C.RED}[ERROR] Provide --sender, --password, --to for email test{C.RESET}")
            print("  Gmail: create an App Password at https://myaccount.google.com/apppasswords")
            return
        _test_notification("email", sender=sender, password=password, to=to)

    else:
        _test_notification("console")


if __name__ == "__main__":
    main()
