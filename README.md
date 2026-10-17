# Cowrie SSH Honeypot

## Overview
A cloud-hosted SSH honeypot built with Cowrie on AWS EC2 to observe and analyze SSH attack activity. The project collects attacker interactions in a controlled environment and uses Python to summarize events and visualize activity through a Streamlit dashboard.

## Technologies
- **AWS EC2** — Cloud hosting
- **Ubuntu Server 24.04** — Operating system
- **Cowrie** — SSH honeypot
- **Python** — Log analysis
- **Streamlit** — Interactive dashboard

## Features
- Captures SSH login attempts and attacker commands
- Records connection activity and file download events
- Analyzes Cowrie JSON logs using a custom Python script
- Displays honeypot activity in a Streamlit dashboard

## Project Structure
- `analyze_logs.py` — Parses Cowrie logs and summarizes observed activity
- `dashboard.py` — Displays honeypot data in a Streamlit dashboard

## Setup Overview
1. Deploy an Ubuntu EC2 instance.
2. Install and configure Cowrie in an isolated environment.
3. Configure network access for SSH administration and the honeypot listener.
4. Run Cowrie and collect event logs.
5. Run the analysis script and launch the dashboard.

## Security Notes
This project is intended for defensive security monitoring and educational use. The dashboard should remain private, and logs should be reviewed before publication to avoid exposing sensitive information.

## Future Improvements
- Visualize attack activity over time
- Categorize observed commands and attacker behavior
- Improve detection of repeated login attempts
- Add deeper analysis of captured events

## Disclaimer
This honeypot is used to observe activity directed at the deployed service. It is not intended to interact with or attack external systems.
