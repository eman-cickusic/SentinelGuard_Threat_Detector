import yaml
from src.detector import ThreatDetector

if __name__ == "__main__":
    with open('config/config.yaml', 'r') as file:
        config = yaml.safe_load(file)

    detector = ThreatDetector(config)
    detector.start_monitoring()

