import json
from collections import Counter

log_file = "/opt/cowrie/var/log/cowrie/cowrie.json"

events = []
with open(log_file) as f:
    for line in f:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

counts = Counter(e.get("eventid") for e in events)

print("\n=== Cowrie Honeypot Report ===")
print(f"Total events: {len(events)}")
print(f"Failed logins: {counts['cowrie.login.failed']}")
print(f"Successful logins: {counts['cowrie.login.success']}")
print(f"Commands entered: {counts['cowrie.command.input']}")
print(f"File downloads: {counts['cowrie.session.file_download']}")

usernames = Counter(
    e.get("username") for e in events
    if e.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")
    and e.get("username")
)

print("\nMost attempted usernames:")
for username, count in usernames.most_common(5):
    print(f"{username}: {count}")
ips = Counter(
    e.get("src_ip") for e in events
    if e.get("eventid") == "cowrie.session.connect" and e.get("src_ip")
)

print("\nMost Active Source IPs:")
for ip, count in ips.most_common(5):
    print(f"{ip}: {count} connections")
commands = Counter(
    e.get("input", "").strip()
    for e in events
    if e.get("eventid") == "cowrie.command.input" and e.get("input", "").strip()
)

print("\nMost Common Commands:")
for command, count in commands.most_common(10):
    print(f"{count}x  {command}")

