import yaml
from basic_threat_detector import EnhancedThreatDetector

if __name__ == "__main__":
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)

    detector = EnhancedThreatDetector(config)
    detector.start_monitoring()
