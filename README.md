# 🛡️ SentinelGuard - Network Security Monitoring System

---

## Features 

- Real-time network packet monitoring
- Detection of suspicious port access 
- Basic connection flood detection
- Packet logging and alert generation
- Configuration-based setup  

## Setup   

1. Create a Python virtual environment:  
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

2. Install requirements:
```bash
pip install -r requirements.txt 
```

3. Create required directories: 
```bash
mkdir -p logs
```

4. Run the detector: 
```bash
sudo python main.py  # sudo required for packet capture
```



https://github.com/user-attachments/assets/6c1f2e7f-a891-42cb-ac8e-4a0ef39dcbb4



## Configuration

Edit `config/config.yaml` to modify:
- Logging settings
- Database path
- Suspicious ports
- Connection thresholds

## Project Structure

- `config/`: Configuration files 
- `src/`: Source code
  - `detector.py`: Main threat detection logic
  - `database.py`: Database operations 
  - `utils.py`: Utility functions
- `logs/`: Log files   
- `main.py`: Application entry point 

## 🚨 Note 🚨 

This is a basic implementation intended for learning purposes. For production use, additional security measures and optimizations would be needed.

---

