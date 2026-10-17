import json
import pandas as pd
import streamlit as st
from collections import Counter

LOG_FILE = "/opt/cowrie/var/log/cowrie/cowrie.json"

st.set_page_config(page_title="Cowrie Attack Dashboard", layout="wide")
st.title("Cowrie Honeypot Attack Dashboard")

events = []
with open(LOG_FILE) as f:
    for line in f:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

df = pd.DataFrame(events)

if df.empty:
    st.warning("No events found in the Cowrie log.")
    st.stop()

counts = Counter(df["eventid"].dropna())

a, b, c, d = st.columns(4)
a.metric("Total Events", len(df))
b.metric("Failed Logins", counts["cowrie.login.failed"])
c.metric("Commands Entered", counts["cowrie.command.input"])
d.metric("File Downloads", counts["cowrie.session.file_download"])

st.subheader("Events by Type")
event_counts = df["eventid"].value_counts()
st.bar_chart(event_counts)

st.subheader("Most Active Source IPs")
if "src_ip" in df.columns:
    connections = df[df["eventid"] == "cowrie.session.connect"]
    st.bar_chart(connections["src_ip"].value_counts().head(10))

st.subheader("Most Attempted Usernames")
if "username" in df.columns:
    logins = df[df["eventid"].isin([
        "cowrie.login.failed",
        "cowrie.login.success"
    ])]
    st.bar_chart(logins["username"].value_counts().head(10))

st.subheader("Most Common Commands")
if "input" in df.columns:
    commands = df[df["eventid"] == "cowrie.command.input"]
    st.bar_chart(commands["input"].value_counts().head(10))

st.subheader("Recent Events")
columns = [
    col for col in ["timestamp", "eventid", "src_ip", "username", "input"]
    if col in df.columns
]
st.dataframe(df[columns].tail(20), use_container_width=True)

