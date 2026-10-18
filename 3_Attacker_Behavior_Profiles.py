import json
import re
from pathlib import Path

import pandas as pd
import streamlit as st

LOG_FILE = Path("/opt/cowrie/var/log/cowrie/cowrie.json")
LOCAL_IPS = {"127.0.0.1", "::1"}
MAX_LOG_LINES = 50000

SUSPICIOUS_RULES = [
    ("Credential discovery", r"/etc/shadow|/etc/passwd|authorized_keys|id_rsa|credentials"),
    ("Download attempt", r"\bcurl\b|\bwget\b|\bftp\b"),
    ("Remote execution / networking", r"\bnc\b|\bncat\b|\bsocat\b"),
    ("Persistence attempt", r"\bcrontab\b|/etc/cron|systemctl\s+enable|useradd"),
    ("Privilege escalation", r"\bsudo\b|\bsu\s+-?\b"),
    ("Destructive activity", r"\brm\s+-rf\b|\bmkfs\b"),
    ("System reconnaissance", r"\bwhoami\b|\buname\b|\bhostname\b|\bifconfig\b|\bnetstat\b|\bps\b|\bid\b"),
]


def parse_time(value):
    try:
        return pd.to_datetime(value, utc=True)
    except (ValueError, TypeError):
        return pd.NaT


def classify(command):
    return [
        label for label, pattern in SUSPICIOUS_RULES
        if re.search(pattern, command, re.IGNORECASE)
    ]


st.set_page_config(
    page_title="Attacker Behavior Profiles",
    page_icon="🔎",
    layout="wide",
)
st.title("Attacker Behavior Profiles")
st.caption(
    "Investigate source IPs, individual sessions, login behavior, "
    "commands, and suspicious activity over time."
)

if st.button("Refresh logs"):
    st.rerun()

if not LOG_FILE.exists():
    st.error(f"Cowrie log not found: {LOG_FILE}")
    st.stop()

events = []
with LOG_FILE.open(encoding="utf-8", errors="replace") as file:
    for line in file.readlines()[-MAX_LOG_LINES:]:
        try:
            event = json.loads(line)
            if event.get("eventid"):
                events.append(event)
        except json.JSONDecodeError:
            continue

if not events:
    st.warning("No Cowrie events found.")
    st.stop()

df = pd.DataFrame(events)
df["time"] = df["timestamp"].apply(parse_time)
df["src_ip"] = df["src_ip"].fillna("Unknown")
df["session"] = df["session"].fillna("Unknown")
df["username"] = df.get("username", pd.Series(index=df.index, dtype=str)).fillna("")
df["input"] = df.get("input", pd.Series(index=df.index, dtype=str)).fillna("")

show_local = st.checkbox("Include my local test activity", value=False)
if not show_local:
    df = df[~df["src_ip"].isin(LOCAL_IPS)].copy()

if df.empty:
    st.info("No events match the current filters.")
    st.stop()

connections = df[df["eventid"] == "cowrie.session.connect"]
source_summary = []

for ip, group in df.groupby("src_ip"):
    sessions = group[group["session"] != "Unknown"]["session"].nunique()
    login_events = group[group["eventid"].isin([
        "cowrie.login.failed", "cowrie.login.success"
    ])]
    commands = group[group["eventid"] == "cowrie.command.input"]
    source_summary.append({
        "Source IP": ip,
        "Sessions": sessions,
        "Connections": int((group["eventid"] == "cowrie.session.connect").sum()),
        "Failed logins": int((group["eventid"] == "cowrie.login.failed").sum()),
        "Successful logins": int((group["eventid"] == "cowrie.login.success").sum()),
        "Commands": len(commands),
        "Usernames targeted": ", ".join(sorted(set(login_events["username"]) - {""})),
        "First observed (UTC)": (
            group["time"].min().strftime("%Y-%m-%d %H:%M:%S")
            if group["time"].notna().any() else "Unknown"
        ),
        "Last observed (UTC)": (
            group["time"].max().strftime("%Y-%m-%d %H:%M:%S")
            if group["time"].notna().any() else "Unknown"
        ),
    })

summary = pd.DataFrame(source_summary).sort_values(
    ["Sessions", "Connections"], ascending=False
)

st.subheader("Source IP profiles")
st.dataframe(summary, use_container_width=True, hide_index=True)

source_options = summary["Source IP"].tolist()
selected_ip = st.selectbox("Investigate source IP", source_options)

ip_events = df[df["src_ip"] == selected_ip].copy()
ip_sessions = sorted(
    ip_events.loc[ip_events["session"] != "Unknown", "session"].unique()
)

a, b, c, d = st.columns(4)
a.metric("Sessions", len(ip_sessions))
b.metric("Failed logins", int((ip_events["eventid"] == "cowrie.login.failed").sum()))
c.metric("Successful logins", int((ip_events["eventid"] == "cowrie.login.success").sum()))
d.metric("Commands", int((ip_events["eventid"] == "cowrie.command.input").sum()))

st.subheader("Session investigation")

if not ip_sessions:
    st.info("No session IDs are available for this source.")
    st.stop()

selected_session = st.selectbox("Select session", ip_sessions)
session_events = ip_events[ip_events["session"] == selected_session].copy()
session_events = session_events.sort_values("time", na_position="last")

start_events = session_events[
    session_events["eventid"] == "cowrie.session.connect"
]
close_events = session_events[
    session_events["eventid"] == "cowrie.session.closed"
]

if not close_events.empty and "duration_ms" in close_events.columns:
    duration = pd.to_numeric(
        close_events["duration_ms"], errors="coerce"
    ).dropna()
    if not duration.empty:
        st.metric("Session duration", f"{duration.iloc[-1] / 1000:.2f} seconds")
    else:
        st.metric("Session duration", "Unknown")
else:
    st.metric("Session duration", "Not recorded")

login_events = session_events[
    session_events["eventid"].isin([
        "cowrie.login.failed", "cowrie.login.success"
    ])
]
if not login_events.empty:
    st.write("**Login attempts and usernames**")
    login_columns = [
        c for c in ["time", "eventid", "username", "src_ip"]
        if c in login_events.columns
    ]
    st.dataframe(
        login_events[login_columns],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.write("No login events recorded for this session.")

command_events = session_events[
    session_events["eventid"] == "cowrie.command.input"
].copy()

st.write("**Commands and behavior indicators**")
if command_events.empty:
    st.info("No commands were recorded in this session.")
else:
    command_rows = []
    for _, event in command_events.iterrows():
        command = str(event.get("input", ""))
        indicators = classify(command)
        command_rows.append({
            "Time (UTC)": (
                event["time"].strftime("%Y-%m-%d %H:%M:%S")
                if pd.notna(event["time"]) else "Unknown"
            ),
            "Command": command,
            "Behavior indicators": ", ".join(indicators) if indicators else "No rule matched",
        })
    st.dataframe(
        pd.DataFrame(command_rows),
        use_container_width=True,
        hide_index=True,
    )

st.write("**Full session timeline**")
timeline_columns = [
    c for c in [
        "time", "eventid", "username", "input",
        "duration_ms", "message"
    ] if c in session_events.columns
]
st.dataframe(
    session_events[timeline_columns],
    use_container_width=True,
    hide_index=True,
)

st.caption(
    "Behavior labels are rule-based investigation leads, not proof of malicious intent. "
    "Session duration is shown only when Cowrie records it."
)
