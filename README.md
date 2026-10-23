# Cowrie SSH Honeypot

## Overview

A cloud-hosted SSH honeypot deployed on AWS EC2 to observe, collect, and analyze unsolicited SSH activity. Built with Cowrie, Python, Pandas, and Streamlit, the project captures remote client interactions and provides an interactive interface for investigating connection patterns, login attempts, commands, and potentially suspicious behavior.

The deployment routes public TCP port `22` to Cowrie's listener on port `2223`, while administrative SSH access uses port `2222` and is restricted by AWS security group rules.

## Technologies

- **AWS EC2** — Cloud infrastructure and hosting
- **Ubuntu Server 24.04** — Operating system
- **Cowrie** — SSH honeypot for recording remote client interactions
- **Python** — Log processing and behavior analysis
- **Pandas** — Data organization and analysis
- **Streamlit** — Interactive dashboard and threat monitoring interface
- **iptables** — Redirects incoming TCP port `22` traffic to Cowrie on port `2223`
- **netfilter-persistent** — Persists firewall rules across reboots

## Features

- Captures SSH connection activity, login attempts, and commands entered by remote clients
- Records session events and file download activity when observed by Cowrie
- Parses Cowrie JSON logs to summarize honeypot activity
- Visualizes connection statistics, event types, targeted usernames, and common commands
- Identifies potentially suspicious command patterns using rule-based detection
- Profiles source IP addresses and individual sessions to investigate observed behavior
- Tracks repeat connections and recorded session durations when available
- Separates local testing activity from external source activity during investigation
- Separates public honeypot traffic from restricted administrative SSH access

## Dashboard Pages

### 1. Cowrie Attack Dashboard ([Screenshot](screenshots/cowrie-dashboard.png))

Provides an overview of recorded honeypot activity, including total events, failed logins, entered commands, file downloads, event distributions, active source IPs, and commonly attempted usernames and commands.

### 2. Threat Monitor ([Screenshot](screenshots/threat_monitor.png))

Highlights potentially suspicious activity using rule-based indicators, including credential discovery, download attempts, remote execution or networking utilities, persistence attempts, privilege escalation, destructive commands, system reconnaissance, and repeated failed login attempts.

### 3. Attacker Behavior Profiles ([Screenshot](screenshots/attacker_behavior_profiles.png))

Supports investigation of individual source IP addresses and sessions. Displays connection history, login attempts, targeted usernames, recorded commands, session duration when available, and command behavior indicators.

**Note:** Detection results are investigative leads, not definitive proof of malicious intent. Findings depend on the events Cowrie records.

## Network Architecture

| Port | Purpose | Exposure |
|---|---|---|
| `22/TCP` | Public entry point for SSH honeypot traffic | Public |
| `2222/TCP` | Administrative SSH access to the EC2 instance | Restricted to a trusted IP address |
| `2223/TCP` | Cowrie's SSH listener | Not directly exposed publicly |
| `8501/TCP` | Streamlit dashboard | Bound to localhost and accessed through SSH tunneling |

Incoming TCP connections to port `22` are redirected locally to port `2223` using an iptables `PREROUTING` rule. This allows Cowrie to handle public honeypot traffic without using the same port as administrative SSH access.

The redirect rule is persisted with `netfilter-persistent` so it can be restored after a reboot. Administrative access remains on port `2222`.

## Project Structure

```text
cowrie-ssh-honeypot-project/
├── analyze_logs.py
├── dashboard.py
├── README.md
├── screenshots/
│   ├── cowrie-dashboard.png
│   ├── threat_monitor.png
│   └── attacker_behavior_profiles.png
└── pages/
    ├── threat_monitor.py
    └── attacker_behavior_profiles.py
```

- `analyze_logs.py` — Parses Cowrie logs and summarizes observed activity.
- `dashboard.py` — Main dashboard with honeypot activity statistics.
- `pages/threat_monitor.py` — Rule-based suspicious activity monitoring.
- `pages/attacker_behavior_profiles.py` — Source IP and session-level investigation.
- `screenshots/` — Dashboard screenshots and project documentation images.

## Setup Overview

1. Deploy an Ubuntu EC2 instance on AWS.
2. Install and configure Cowrie in an isolated Python environment.
3. Configure administrative SSH access on port `2222`, restricted through AWS security group rules.
4. Configure Cowrie to listen on port `2223`.
5. Configure the host firewall to redirect incoming TCP port `22` traffic to port `2223`.
6. Persist the firewall rules using `netfilter-persistent`.
7. Configure the AWS security group to permit public honeypot traffic on port `22`, allow administrative access on port `2222` only from a trusted IP, and avoid exposing port `2223` directly.
8. Start Cowrie and collect JSON event logs.
9. Install the required Python dependencies, including Streamlit and Pandas.
10. Launch the dashboard from the project directory:

    ```bash
    streamlit run dashboard.py --server.address 127.0.0.1 --server.port 8501
    ```

11. Create an SSH tunnel from the local machine using administrative port `2222`:

    ```bash
    ssh -i "bart.pem" -N -L 8501:127.0.0.1:8501 -p 2222 ubuntu@<EC2_PUBLIC_IP>
    ```

12. Open `http://localhost:8501` in a local browser.

Replace `<EC2_PUBLIC_IP>` with the instance's current public IP address.

## Security Notes

- Restrict administrative SSH access to trusted IP addresses.
- Use port `2222` for administrative SSH connections; public port `22` is intended for honeypot traffic.
- Keep Cowrie's port `2223` inaccessible through direct public inbound rules.
- Keep the dashboard bound to `127.0.0.1` and access it through an SSH tunnel instead of exposing it publicly.
- Never commit AWS private keys, credentials, or other secrets to the repository.
- Review logs and screenshots before publication to prevent disclosure of sensitive information.
- Treat suspicious behavior indicators as investigative leads rather than conclusive attribution.

## Future Improvements

- Add alerting for newly observed or high-risk activity
- Expand command classification and behavioral detection rules
- Improve repeat-visitor tracking and source IP correlation
- Add richer visualizations of attack trends over time
- Support remote alert review without requiring an interactive SSH session

## Disclaimer

This project is intended for defensive security monitoring, research, and educational purposes. It observes activity directed at the deployed honeypot and is not intended to attack, access, or interfere with external systems.
