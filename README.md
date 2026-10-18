# Cowrie SSH Honeypot

## Overview

A cloud-hosted SSH honeypot deployed on AWS EC2 to observe, collect, and analyze SSH attack activity. Built with Cowrie, Python, and Streamlit, the project captures attacker interactions and provides an interactive interface for investigating connection patterns, login attempts, commands, and suspicious behavior.

## Technologies

- **AWS EC2** — Cloud infrastructure and hosting
- **Ubuntu Server 24.04** — Operating system
- **Cowrie** — SSH honeypot for recording attacker interactions
- **Python** — Log processing and behavior analysis
- **Pandas** — Data organization and analysis
- **Streamlit** — Interactive dashboard and threat monitoring interface

## Features

- Captures SSH connection activity, login attempts, and commands entered by remote clients
- Records session events and file download activity when observed by Cowrie
- Parses Cowrie JSON logs to summarize honeypot activity
- Visualizes connection statistics, event types, targeted usernames, and common commands
- Identifies suspicious command patterns using rule-based detection
- Profiles source IP addresses and individual sessions to investigate attacker behavior
- Tracks observed activity over time, including repeat connections and recorded session durations
- Separates local testing activity from external source activity during investigation

## Dashboard Pages

### 1. Cowrie Attack Dashboard ([Screenshot](screenshots/dashboard.png))

Provides an overview of recorded honeypot activity, including total events, failed logins, entered commands, file downloads, event distributions, active source IPs, and commonly attempted usernames and commands.

### 2. Threat Monitor ([Screenshot](screenshots/threat_monitor.png))

Highlights potentially suspicious activity using rule-based indicators, including credential discovery, download attempts, remote execution or networking utilities, persistence attempts, privilege escalation, destructive commands, system reconnaissance, and repeated failed login attempts.

### 3. Attacker Behavior Profiles ([Screenshot](screenshots/attacker_behavior_profiles.png))

Supports investigation of individual source IP addresses and sessions. Displays connection history, login attempts, targeted usernames, recorded commands, session duration when available, and command behavior indicators.

**Note:** Detection results are investigative leads, not definitive proof of malicious intent. Findings depend on the events Cowrie records.

## Project Structure

```text
cowrie-ssh-honeypot-project/
├── analyze_logs.py
├── dashboard.py
├── README.md
├── screenshots/
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
2. Install and configure Cowrie in an isolated environment.
3. Configure security group rules for administrative SSH access and the honeypot listener.
4. Start Cowrie and collect its JSON event logs.
5. Install the required Python dependencies, including Streamlit and Pandas.
6. Launch the dashboard from the project directory:

   ```bash
   streamlit run dashboard.py --server.address 127.0.0.1 --server.port 8501
   ```

7. Access the dashboard through a local browser using an SSH tunnel to the EC2 instance.

## Security Notes

- Restrict administrative SSH access to trusted IP addresses.
- Keep the dashboard bound to localhost and access it through an SSH tunnel rather than exposing it publicly.
- Never commit AWS private keys, credentials, or other secrets to the repository.
- Review logs and screenshots before publication to prevent disclosure of sensitive information.
- Treat suspicious behavior indicators as leads for further investigation rather than conclusive attribution.

## Future Improvements

- Add alerting for newly observed or high-risk activity
- Expand command classification and behavioral detection rules
- Improve repeat-visitor tracking and source IP correlation
- Add richer visualizations of attack trends over time
- Support remote alert review without requiring an interactive SSH session

## Disclaimer

This project is intended for defensive security monitoring, research, and educational purposes. It observes activity directed at the deployed honeypot and is not intended to attack, access, or interfere with external systems.
