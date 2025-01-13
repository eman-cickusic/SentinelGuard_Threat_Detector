# 🛡️ SentinelGuard - Network Security Monitoring System

---

# Overview
The Enhanced Threat Detector is a Python-based project designed to analyze network traffic, detect potential threats, and log network activity. It uses Scapy for packet inspection, SQLite for data storage, and YAML for configuration management. This modular project is split into three main components:

1. **Core functionality (`basic_threat_detector.py`)**: Implements packet analysis and threat detection.
2. **Configuration file (`config.yaml`)**: Stores customizable settings.
3. **Main entry point (`main.py`)**: Initializes the detector and starts monitoring.

---

# Setup Instructions

## Prerequisites
1. Ensure Python 3.7 or later is installed on your system.
2. Install required Python libraries using the provided `requirements.txt` file:
   ```bash
   pip install -r requirements.txt
   ```
   **Contents of `requirements.txt`:**
   ```text
   scapy==2.5.0
   pyyaml==6.0.1
   requests==2.31.0
   ```

## Directory Structure
Ensure your project directory has the following structure:
```
project_directory/
├── basic_threat_detector.py
├── config.yaml
├── main.py
├── logs/ (create manually, if not present)
└── requirements.txt
```

---

# Usage Instructions

## Configuration
Edit the `config.yaml` file to customize the detector's behavior. Key sections include:
- **Logging**: Specify the log file path and logging level (e.g., `INFO`, `DEBUG`).
- **Database**: Define the SQLite database file path.
- **Thresholds**: Set thresholds for suspicious activity, such as maximum failed attempts and connection limits.
- **Threat Intelligence**: Configure the API URL for fetching threat intelligence data.

Example `config.yaml` file:
```yaml
logging:
    level: INFO
    file_path: logs/threat_detector.log

database:
    path: security.db

thresholds:
    max_failed_attempts: 5
    suspicious_ports:
        - 22
        - 3389
        - 445
    max_connections: 50

threat_intelligence:
    api_url: https://threatintel.example.com
```

## Running the Project
To start the Enhanced Threat Detector, execute the `main.py` file:
```bash
python main.py
```
This will:
- Load configurations from `config.yaml`.
- Initialize the detector.
- Start monitoring network traffic.

Press **Ctrl+C** to stop the detector.

---

# Functionality Details

## Core Features
1. **Packet Analysis**:
   - Inspects packets for IP, TCP, UDP, and DNS protocols.
   - Logs network traffic to the SQLite database.

2. **Threat Detection**:
   - Identifies suspicious ports based on predefined thresholds.
   - Detects high connection rates per IP.
   - Alerts for DNS and HTTP anomalies.

3. **Alert Logging**:
   - Generates alerts for detected threats.
   - Stores alert details in the SQLite database.

4. **Logging**:
   - Logs all activities to a file for auditing.

## Modular Components
- **`basic_threat_detector.py`**: Core detection logic.
- **`config.yaml`**: Customizable settings.
- **`main.py`**: Entry point for starting the program.

---

# Example Workflow
1. Update `config.yaml` with your desired thresholds and log settings.
2. Run `python main.py` to start monitoring.
3. Check `logs/threat_detector.log` for runtime logs.
4. Review `security.db` for traffic logs and alerts.

---

# Troubleshooting

1. **Missing Logs**:
   - Ensure the `logs/` directory exists and is writable.

2. **Database Errors**:
   - Verify the database path in `config.yaml` is correct.

3. **Missing Dependencies**:
   - Run `pip install -r requirements.txt` to reinstall dependencies.

---

