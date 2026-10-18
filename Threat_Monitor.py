
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st

LOG_FILE = Path("/opt/cowrie/var/log/cowrie/cowrie.json")
FAILED_LOGIN_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5
MAX_LOG_LINES = 50000

# Each pattern is an indicator to investigate, not proof of compromise.
COMMAND_RULES = [
    ("HIGH", "Credential discovery",
     r"/etc/shadow|/etc/passwd|\.ssh/(authorized_keys|id_rsa|id_ed25519)|"
     r"ssh-keygen|secret|credentials"),
    ("HIGH", "Download or remote execution",
     r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bsocat\b|"
     r"\bchmod\s+\+x\b|\bbase64\s+-d\b"),
    ("HIGH", "Persistence attempt",
     r"\b(crontab|systemctl\s+enable|useradd|usermod)\b|"
     r"/etc/cron|/etc/rc\.local"),
    ("MEDIUM", "System reconnaissance",
     r"\b(whoami|id|uname|hostname|ifconfig|ip\s+addr|"
     r"ps|netstat|ss|lscpu|lsb_release)\b"),
    ("MEDIUM", "Privilege escalation or destructive action",
     r"\bsudo\b|\bsu\s+-?\b|\bchmod\s+[0-7]{3,4}\b|"
     r"\brm\s+-rf\b|\bmkfs\b"),
]

LOCAL_IPS = {"127.0.0.1", "::1"}


def parse_timestamp(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result
    except (ValueError, TypeError):
        return None


def load_events():
    events = []
    if not LOG_FILE.exists():
        return events, "Cowrie JSON log was not found."

    try:
        with LOG_FILE.open("r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()[-MAX_LOG_LINES:]
    except OSError as error:
        return events, f"Unable to read log: {error}"

    for line in lines:
        try:
            event = json.loads(line)
            if isinstance(event, dict) and event.get("eventid"):
                events.append(event)
        except json.JSONDecodeError:
            continue

    return events, None


def classify_command(command):
    matches = []
    for severity, category, pattern in COMMAND_RULES:
        if re.search(pattern, command, re.IGNORECASE):
            matches.append((severity, category))
    return matches


def detect(events):
    alerts = []
    failed_logins = []

    for event in events:
        event_id = event.get("eventid", "")
        source = event.get("src_ip", "Unknown")
        timestamp = parse_timestamp(event.get("timestamp"))
        local = source in LOCAL_IPS

        if event_id == "cowrie.login.failed" and timestamp:
            failed_logins.append({
                "time": timestamp,
                "ip": source,
                "username": event.get("username", "unknown"),
                "local": local,
            })

        if event_id == "cowrie.login.success":
            alerts.append({
                "time": timestamp,
                "severity": "INFO",
                "category": "Successful login",
                "ip": source,
                "details": f"Username: {event.get('username', 'unknown')}",
                "local": local,
            })

        if event_id == "cowrie.command.input":
            command = event.get("input", "")
            for severity, category in classify_command(command):
                alerts.append({
                    "time": timestamp,
                    "severity": severity,
                    "category": category,
                    "ip": source,
                    "details": command[:300],
                    "local": local,
                })

    # Detect repeated failed logins in a rolling five-minute window.
    by_ip = defaultdict(list)
    for attempt in failed_logins:
        by_ip[attempt["ip"]].append(attempt)

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda item: item["time"])
        left = 0
        for right, current in enumerate(attempts):
            while (
                current["time"] - attempts[left]["time"]
                > timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
            ):
                left += 1

            window = attempts[left:right + 1]
            if len(window) >= FAILED_LOGIN_THRESHOLD:
                alerts.append({
                    "time": current["time"],
                    "severity": "HIGH",
                    "category": "Possible brute-force attack",
                    "ip": ip,
                    "details": (
                        f"{len(window)} failed logins within "
                        f"{BRUTE_FORCE_WINDOW_MINUTES} minutes; "
                        f"usernames: {', '.join(sorted({x['username'] for x in window}))}"
                    ),
                    "local": all(item["local"] for item in window),
                })
                # One alert per qualifying window endpoint is noisy.
                # Skip ahead until this window has passed the threshold.
                break

    alerts.sort(
        key=lambda item: item["time"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return failed_logins, alerts


st.set_page_config(
    page_title="Cowrie Threat Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("Cowrie Suspicious Activity Monitor")
st.caption("Rule-based detection from Cowrie JSON events. Alerts require investigation.")

if st.button("Refresh logs"):
    st.rerun()

events, error = load_events()

if error:
    st.error(error)
    st.stop()

failed_logins, alerts = detect(events)

external_events = [
    event for event in events
    if event.get("src_ip") not in LOCAL_IPS
]
external_ips = {
    event.get("src_ip") for event in external_events if event.get("src_ip")
}
external_failed = [item for item in failed_logins if not item["local"]]
external_alerts = [item for item in alerts if not item["local"]]
external_commands = [
    event for event in external_events
    if event.get("eventid") == "cowrie.command.input"
]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events loaded", len(events))
col2.metric("External source IPs", len(external_ips))
col3.metric("External failed logins", len(external_failed))
col4.metric("External command events", len(external_commands))

st.subheader("Detection alerts")
st.caption(
    "Local test activity is excluded from the external alert list. "
    "Command rules are heuristic indicators and can produce false positives."
)

if external_alerts:
    rows = []
    for alert in external_alerts:
        rows.append({
            "Time (UTC)": (
                alert["time"].strftime("%Y-%m-%d %H:%M:%S")
                if alert["time"] else "Unknown"
            ),
            "Severity": alert["severity"],
            "Detection": alert["category"],
            "Source IP": alert["ip"],
            "Evidence": alert["details"],
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    st.info(
        "No external activity matched the current detection rules. "
        "This does not mean the server has received no external connections."
    )

st.subheader("Failed login activity by source IP")
if external_failed:
    counts = Counter(item["ip"] for item in external_failed)
    st.dataframe(
        [
            {"Source IP": ip, "Failed attempts": count}
            for ip, count in counts.most_common()
        ],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.write("No external failed-login events recorded in the loaded log.")

st.subheader("Recent external commands")
if external_commands:
    rows = []
    for event in reversed(external_commands[-100:]):
        timestamp = parse_timestamp(event.get("timestamp"))
        rows.append({
            "Time (UTC)": (
                timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if timestamp else "Unknown"
            ),
            "Source IP": event.get("src_ip", "Unknown"),
            "Session": event.get("session", "Unknown"),
            "Command": event.get("input", ""),
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    st.write("No external command events recorded in the loaded log.")

st.subheader("Event type summary")
event_counts = Counter(event.get("eventid", "unknown") for event in events)
st.dataframe(
    [
        {"Event type": name, "Count": count}
        for name, count in event_counts.most_common()
    ],
    use_container_width=True,
    hide_index=True,
)

st.caption(
    f"Reading {LOG_FILE}; up to the latest {MAX_LOG_LINES:,} lines. "
    "Timestamps are displayed in UTC. Refresh to load newer events."
)
