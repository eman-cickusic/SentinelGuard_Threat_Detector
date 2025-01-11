# Basic Threat Detector 🚨

A Python-based network threat detection system designed to monitor traffic and identify suspicious activity in real-time. This project demonstrates my passion for cybersecurity and programming by combining packet analysis with database-driven alert systems.

---

## Features
- **Real-Time Monitoring:** Analyzes network packets and logs traffic.
- **Threat Detection:** Identifies:
  - Access to suspicious ports (e.g., SSH, RDP).
  - High connection rates from single IPs.
- **Custom Alerts:** Generates alerts and logs them in an SQLite database.
- **Configurable Thresholds:** Adjustable via `config.yaml`.
- **Persistent Logs:** Stores traffic and alerts for future analysis.

---

## My Contribution
I developed this project to enhance my skills in:
- Packet analysis (using Scapy).
- Database integration (SQLite).
- YAML-based configuration management.

This project taught me to handle real-world challenges like error handling, resource cleanup, and modular programming.

---

## How to Run
1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
