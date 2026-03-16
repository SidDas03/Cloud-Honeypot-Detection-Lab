"""
dashboard.py — Streamlit Web Dashboard for Cloud Honeypot Detection Lab

Run with:
    streamlit run dashboard.py

Requirements:
    pip install streamlit plotly
"""

import json
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter, defaultdict
from datetime import datetime

st.set_page_config(
    page_title="Honeypot Threat Dashboard",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: #1a1f2e;
        border: 1px solid #2a3a2a;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .metric-value { font-size: 2.5rem; font-weight: 700; color: #00ff88; }
    .metric-label { font-size: 0.85rem; color: #888; margin-top: 4px; }
    .critical { color: #ff4444 !important; }
    .high     { color: #ffaa00 !important; }
    .medium   { color: #4488ff !important; }
    .low      { color: #888888 !important; }
    .finding-box {
        background: #1a1f2e;
        border-left: 4px solid #ff4444;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .finding-box.high  { border-left-color: #ffaa00; }
    .finding-box.medium { border-left-color: #4488ff; }
    .stDataFrame { background: #1a1f2e; }
    div[data-testid="stMetricValue"] { font-size: 2rem; }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_cowrie_logs():
    with open("logs/cowrie_logs.json") as f:
        return json.load(f)

@st.cache_data
def load_guardduty():
    with open("logs/guardduty_findings.json") as f:
        return json.load(f)

@st.cache_data
def parse_logs(events):
    ip_data = defaultdict(lambda: {
        "connections": 0,
        "login_attempts": 0,
        "login_successes": 0,
        "commands": [],
        "downloads": [],
        "usernames": [],
        "passwords": [],
        "sessions": set(),
        "first_seen": None,
        "last_seen": None,
    })

    for e in events:
        ip = e.get("src_ip", "unknown")
        eid = e.get("eventid", "")
        ts  = e.get("timestamp", "")

        if ip_data[ip]["first_seen"] is None:
            ip_data[ip]["first_seen"] = ts
        ip_data[ip]["last_seen"] = ts

        if eid == "cowrie.session.connect":
            ip_data[ip]["connections"] += 1
        elif eid == "cowrie.login.failed":
            ip_data[ip]["login_attempts"] += 1
            ip_data[ip]["usernames"].append(e.get("username", ""))
            ip_data[ip]["passwords"].append(e.get("password", ""))
        elif eid == "cowrie.login.success":
            ip_data[ip]["login_successes"] += 1
            ip_data[ip]["usernames"].append(e.get("username", ""))
            ip_data[ip]["passwords"].append(e.get("password", ""))
        elif eid == "cowrie.command.input":
            ip_data[ip]["commands"].append(e.get("input", ""))
        elif eid == "cowrie.session.file_download":
            ip_data[ip]["downloads"].append(e.get("url", ""))

    return ip_data

try:
    events   = load_cowrie_logs()
    gd_data  = load_guardduty()
    ip_data  = parse_logs(events)
    findings = gd_data.get("findings", [])
    gd_summary = gd_data.get("summary", {})
except FileNotFoundError as e:
    st.error(f"Log file not found: {e}. Make sure you're running from the project root folder.")
    st.stop()

with st.sidebar:
    st.image("https://img.icons8.com/emoji/96/honeypot.png", width=60)
    st.title("🍯 Honeypot Lab")
    st.caption("Cloud Threat Detection Dashboard")
    st.divider()

    page = st.radio("Navigate", [
        "📊 Overview",
        "🌍 Attacker IPs",
        "🛡️ GuardDuty Findings",
        "💻 Session Commands",
        "🗺️ MITRE ATT&CK",
        "🔑 Credentials",
    ])

    st.divider()
    st.caption(f"Sensor: honeypot-ec2-01")
    st.caption(f"Events loaded: {len(events)}")
    st.caption(f"Unique IPs: {len(ip_data)}")

def sev_color(sev):
    return {"CRITICAL": "#ff4444", "HIGH": "#ffaa00",
            "MEDIUM": "#4488ff", "LOW": "#888888"}.get(sev, "#888")

def get_severity(stats):
    if stats["login_successes"] > 0 and stats["commands"]:
        cmds = " ".join(stats["commands"]).lower()
        if any(k in cmds for k in ["socket", "/bin/sh", "reverse"]):
            return "CRITICAL"
        if any(k in cmds for k in ["wget", "curl", "xmrig", "crontab", "useradd", "169.254"]):
            return "HIGH"
        return "HIGH"
    elif stats["login_successes"] > 0:
        return "HIGH"
    elif stats["login_attempts"] > 10:
        return "MEDIUM"
    return "LOW"

if page == "📊 Overview":
    st.title("📊 Threat Overview")
    st.caption("72-hour observation window — Simulated EC2 Honeypot (us-east-1)")
    st.divider()

    # Top metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Events",      f"{len(events):,}")
    c2.metric("Unique Attackers",  f"{len(ip_data)}")
    c3.metric("Login Attempts",    f"{sum(v['login_attempts'] for v in ip_data.values()):,}")
    c4.metric("Successful Logins", f"{sum(v['login_successes'] for v in ip_data.values())}")
    c5.metric("GuardDuty Findings",f"{gd_summary.get('total_findings', len(findings))}")

    st.divider()
    col1, col2 = st.columns(2)

    # Attack type breakdown
    with col1:
        st.subheader("Attack Type Breakdown")
        attack_types = {
            "SSH Brute Force": sum(v["login_attempts"] for v in ip_data.values()),
            "Successful Logins": sum(v["login_successes"] for v in ip_data.values()),
            "Commands Executed": sum(len(v["commands"]) for v in ip_data.values()),
            "File Downloads": sum(len(v["downloads"]) for v in ip_data.values()),
        }
        fig = px.pie(
            values=list(attack_types.values()),
            names=list(attack_types.keys()),
            color_discrete_sequence=["#ff4444", "#ffaa00", "#4488ff", "#00ff88"],
            hole=0.45
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#cccccc",
            legend=dict(orientation="h", y=-0.1),
            margin=dict(t=20, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)

    # GuardDuty severity breakdown
    with col2:
        st.subheader("GuardDuty Severity")
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            s = f.get("severity", 0)
            if s >= 9:   sev_counts["CRITICAL"] += 1
            elif s >= 7: sev_counts["HIGH"] += 1
            elif s >= 4: sev_counts["MEDIUM"] += 1
            else:        sev_counts["LOW"] += 1

        fig2 = go.Figure(go.Bar(
            x=list(sev_counts.keys()),
            y=list(sev_counts.values()),
            marker_color=["#ff4444", "#ffaa00", "#4488ff", "#888888"],
            text=list(sev_counts.values()),
            textposition="outside"
        ))
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#cccccc",
            yaxis=dict(gridcolor="#1a2a1a"),
            margin=dict(t=20, b=20),
            showlegend=False
        )
        st.plotly_chart(fig2, use_container_width=True)

    # Events timeline
    st.subheader("Events Timeline")
    hour_counts = Counter()
    for e in events:
        ts = e.get("timestamp", "")
        if ts:
            try:
                hour = ts[11:13]
                hour_counts[f"{hour}:00"] += 1
            except:
                pass

    if hour_counts:
        sorted_hours = sorted(hour_counts.items())
        fig3 = go.Figure(go.Scatter(
            x=[h[0] for h in sorted_hours],
            y=[h[1] for h in sorted_hours],
            mode="lines+markers",
            line=dict(color="#00ff88", width=2),
            marker=dict(color="#00ff88", size=6),
            fill="tozeroy",
            fillcolor="rgba(0,255,136,0.08)"
        ))
        fig3.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#cccccc",
            xaxis=dict(gridcolor="#1a2a1a"),
            yaxis=dict(gridcolor="#1a2a1a", title="Events"),
            margin=dict(t=10, b=30)
        )
        st.plotly_chart(fig3, use_container_width=True)

elif page == "🌍 Attacker IPs":
    st.title("🌍 Attacker IP Analysis")
    st.divider()

    # Build table data
    rows = []
    for ip, stats in ip_data.items():
        sev = get_severity(stats)
        rows.append({
            "IP Address":       ip,
            "Severity":         sev,
            "Connections":      stats["connections"],
            "Login Attempts":   stats["login_attempts"],
            "Successful Logins":stats["login_successes"],
            "Commands Run":     len(stats["commands"]),
            "Files Downloaded": len(stats["downloads"]),
            "First Seen":       stats["first_seen"][:19] if stats["first_seen"] else "",
        })

    rows.sort(key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["Severity"]))

    # Filter
    sev_filter = st.selectbox("Filter by severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    if sev_filter != "ALL":
        rows = [r for r in rows if r["Severity"] == sev_filter]

    st.dataframe(rows, use_container_width=True, height=350)

    st.divider()

    # Top IPs bar chart
    st.subheader("Top IPs by Login Attempts")
    top_ips = sorted(ip_data.items(), key=lambda x: x[1]["login_attempts"], reverse=True)[:10]
    fig = go.Figure(go.Bar(
        x=[i[0] for i in top_ips],
        y=[i[1]["login_attempts"] for i in top_ips],
        marker_color=[sev_color(get_severity(i[1])) for i in top_ips],
        text=[i[1]["login_attempts"] for i in top_ips],
        textposition="outside"
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#cccccc",
        xaxis=dict(tickangle=-30),
        yaxis=dict(gridcolor="#1a2a1a"),
        margin=dict(t=20, b=80),
        showlegend=False
    )
    st.plotly_chart(fig, use_container_width=True)

    # IP detail expander
    st.subheader("IP Deep Dive")
    selected_ip = st.selectbox("Select an IP to inspect", list(ip_data.keys()))
    if selected_ip:
        stats = ip_data[selected_ip]
        sev = get_severity(stats)
        col1, col2, col3 = st.columns(3)
        col1.metric("Login Attempts",    stats["login_attempts"])
        col2.metric("Successful Logins", stats["login_successes"])
        col3.metric("Commands Executed", len(stats["commands"]))

        if stats["commands"]:
            st.markdown("**Commands executed:**")
            for cmd in stats["commands"]:
                st.code(cmd, language="bash")

        if stats["downloads"]:
            st.markdown("**Files downloaded:**")
            for url in stats["downloads"]:
                st.code(url)

elif page == "🛡️ GuardDuty Findings":
    st.title("🛡️ GuardDuty Findings")
    st.caption("Simulated AWS GuardDuty threat detection findings")
    st.divider()

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f.get("severity", 0)
        if s >= 9:   sev_counts["CRITICAL"] += 1
        elif s >= 7: sev_counts["HIGH"] += 1
        elif s >= 4: sev_counts["MEDIUM"] += 1
        else:        sev_counts["LOW"] += 1

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", len(findings))
    c2.metric("Critical",       sev_counts["CRITICAL"])
    c3.metric("High",           sev_counts["HIGH"])
    c4.metric("Medium",         sev_counts["MEDIUM"])

    st.divider()

    for f in findings:
        sev_score = f.get("severity", 0)
        if sev_score >= 9:   sev_label, cls = "CRITICAL", "critical"
        elif sev_score >= 7: sev_label, cls = "HIGH",     "high"
        else:                sev_label, cls = "MEDIUM",   "medium"

        ip   = f.get("remoteIp") or f.get("service", {}).get("action", {}).get(
                "networkConnectionAction", {}).get("remoteIpDetails", {}).get("ipAddressV4", "Unknown")
        mitre = f.get("mitre_attack", {})

        border = {"CRITICAL": "#ff4444", "HIGH": "#ffaa00", "MEDIUM": "#4488ff"}.get(sev_label, "#888")

        st.markdown(f"""
        <div style="background:#1a1f2e;border-left:4px solid {border};
                    border-radius:8px;padding:16px 20px;margin-bottom:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <span style="color:{border};font-weight:700;font-size:0.8rem;
                             background:{border}22;padding:3px 10px;border-radius:4px;">{sev_label}</span>
                <span style="color:#555;font-size:0.75rem;">Severity Score: {sev_score}</span>
            </div>
            <div style="color:#e0e0e0;font-weight:600;margin-bottom:4px;">{f.get('type','')}</div>
            <div style="color:#aaa;font-size:0.85rem;margin-bottom:8px;">{f.get('description','')}</div>
            <div style="display:flex;gap:20px;font-size:0.78rem;color:#666;">
                <span>📍 IP: <span style="color:#88bb88;">{ip}</span></span>
                <span>🗺️ MITRE: <span style="color:#88aa88;">{mitre.get('technique','')} — {mitre.get('technique_name','')}</span></span>
            </div>
        </div>
        """, unsafe_allow_html=True)

elif page == "💻 Session Commands":
    st.title("💻 Attacker Session Commands")
    st.caption("Commands executed by attackers after successfully logging in")
    st.divider()

    all_commands = []
    for ip, stats in ip_data.items():
        for cmd in stats["commands"]:
            all_commands.append({"ip": ip, "command": cmd})

    if not all_commands:
        st.info("No commands recorded in logs.")
    else:
        st.metric("Total Commands Captured", len(all_commands))
        st.divider()

        for ip, stats in ip_data.items():
            if stats["commands"]:
                sev = get_severity(stats)
                color = sev_color(sev)
                st.markdown(f"""
                <div style="background:#1a1f2e;border-radius:8px;padding:14px 18px;margin-bottom:8px;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:10px;">
                        <span style="color:#88bb88;font-family:monospace;font-size:0.9rem;">{ip}</span>
                        <span style="color:{color};font-size:0.78rem;background:{color}22;
                                     padding:2px 8px;border-radius:4px;">{sev}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                for cmd in stats["commands"]:
                    danger = any(k in cmd.lower() for k in [
                        "wget", "curl", "chmod", "bash", "python", "socket",
                        "crontab", "useradd", "iptables", "xmrig", "169.254"
                    ])
                    icon = "🔴" if danger else "⚪"
                    st.code(f"{icon}  {cmd}", language="bash")
                st.divider()

elif page == "🗺️ MITRE ATT&CK":
    st.title("🗺️ MITRE ATT&CK Mapping")
    st.caption("Attacker behaviors mapped to the MITRE ATT&CK Enterprise Framework")
    st.divider()

    COMMAND_TO_MITRE = {
        "uname":          ("Discovery",         "T1082",     "System Information Discovery"),
        "id":             ("Discovery",         "T1033",     "System Owner/User Discovery"),
        "whoami":         ("Discovery",         "T1033",     "System Owner/User Discovery"),
        "ps aux":         ("Discovery",         "T1057",     "Process Discovery"),
        "netstat":        ("Discovery",         "T1049",     "Network Connections Discovery"),
        "cat /etc/passwd":("Discovery",         "T1087.001", "Account Discovery"),
        "cat ~/.aws":     ("Credential Access", "T1552.001", "Credentials In Files"),
        "169.254.169.254":("Credential Access", "T1552.005", "Cloud Instance Metadata API"),
        "find / -name":   ("Credential Access", "T1083",     "File and Directory Discovery"),
        "wget":           ("Execution",         "T1105",     "Ingress Tool Transfer"),
        "curl":           ("Execution",         "T1105",     "Ingress Tool Transfer"),
        "chmod +x":       ("Execution",         "T1059.004", "Unix Shell"),
        "crontab":        ("Persistence",       "T1053.003", "Scheduled Task: Cron"),
        "/etc/crontab":   ("Persistence",       "T1053.003", "Scheduled Task: Cron"),
        "useradd":        ("Persistence",       "T1136.001", "Create Local Account"),
        "iptables -F":    ("Defense Evasion",   "T1562.004", "Disable System Firewall"),
        "socket":         ("C2",                "T1059.006", "Python Reverse Shell"),
        "xmrig":          ("Impact",            "T1496",     "Resource Hijacking"),
        "stratum+tcp":    ("Impact",            "T1496",     "Resource Hijacking"),
    }

    tactic_hits = Counter()
    ttp_hits    = Counter()

    for stats in ip_data.values():
        for cmd in stats["commands"]:
            for keyword, (tactic, technique, name) in COMMAND_TO_MITRE.items():
                if keyword.lower() in cmd.lower():
                    tactic_hits[tactic] += 1
                    ttp_hits[f"{technique}: {name}"] += 1

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Tactics Observed")
        if tactic_hits:
            fig = px.bar(
                x=list(tactic_hits.values()),
                y=list(tactic_hits.keys()),
                orientation="h",
                color=list(tactic_hits.values()),
                color_continuous_scale=["#1a2a1a", "#00ff88"],
                text=list(tactic_hits.values())
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#cccccc",
                xaxis=dict(gridcolor="#1a2a1a"),
                coloraxis_showscale=False,
                margin=dict(t=10, b=10),
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No MITRE mappings found in current logs.")

    with col2:
        st.subheader("Top Techniques")
        if ttp_hits:
            for ttp, count in ttp_hits.most_common(8):
                technique_id = ttp.split(":")[0]
                technique_name = ttp.split(": ", 1)[1] if ": " in ttp else ttp
                st.markdown(f"""
                <div style="background:#1a1f2e;border-radius:6px;padding:10px 14px;
                            margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <span style="color:#4488ff;font-family:monospace;font-size:0.8rem;">{technique_id}</span>
                        <span style="color:#aaa;font-size:0.85rem;margin-left:10px;">{technique_name}</span>
                    </div>
                    <span style="color:#00ff88;font-weight:700;">{count}</span>
                </div>
                """, unsafe_allow_html=True)

    st.divider()
    st.info("💡 Tip: Import `mitre_attack/mitre_mapping.md` ATT&CK Navigator JSON at https://mitre-attack.github.io/attack-navigator/ to see a visual heatmap of all detected techniques.")

elif page == "🔑 Credentials":
    st.title("🔑 Credential Analysis")
    st.caption("Usernames and passwords attempted by attackers")
    st.divider()

    all_usernames = Counter()
    all_passwords = Counter()
    successful    = []

    for ip, stats in ip_data.items():
        all_usernames.update(stats["usernames"])
        all_passwords.update(stats["passwords"])
        if stats["login_successes"] > 0:
            for u, p in zip(stats["usernames"], stats["passwords"]):
                successful.append({"IP": ip, "Username": u, "Password": p})

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Top Usernames Attempted")
        if all_usernames:
            top_u = all_usernames.most_common(12)
            fig = px.bar(
                x=[u[1] for u in top_u],
                y=[u[0] for u in top_u],
                orientation="h",
                color=[u[1] for u in top_u],
                color_continuous_scale=["#1a2a1a", "#4488ff"],
                text=[u[1] for u in top_u]
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#cccccc",
                coloraxis_showscale=False,
                margin=dict(t=10, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Top Passwords Attempted")
        if all_passwords:
            top_p = all_passwords.most_common(12)
            fig2 = px.bar(
                x=[p[1] for p in top_p],
                y=[p[0] for p in top_p],
                orientation="h",
                color=[p[1] for p in top_p],
                color_continuous_scale=["#1a2a1a", "#ffaa00"],
                text=[p[1] for p in top_p]
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#cccccc",
                coloraxis_showscale=False,
                margin=dict(t=10, b=10)
            )
            st.plotly_chart(fig2, use_container_width=True)

    st.divider()
    st.subheader("✅ Successfully Used Credentials")
    if successful:
        st.warning(f"{len(successful)} credential(s) successfully authenticated to the honeypot")
        st.dataframe(successful, use_container_width=True)
    else:
        st.success("No successful logins recorded.")

    st.divider()
    st.subheader("🔍 Key Insight")
    st.markdown("""
    > Most attackers use **automated tools** (Hydra, Medusa) to spray common
    > default credentials. The top attempted passwords are almost always
    > `123456`, `admin`, `password`, `root` — demonstrating why **strong,
    > unique passwords** and **key-based SSH auth** are critical defences.
    """)
