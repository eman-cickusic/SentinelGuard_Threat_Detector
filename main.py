#!/usr/bin/env python3

from basic_threat_detector import BasicThreatDetector
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description='Run the Basic Threat Detection System')
    parser.add_argument('-c', '--config', default='config.yaml',
                        help='Path to configuration file (default: config.yaml)')
    return parser.parse_args()

def main():
    args = parse_arguments()
    detector = BasicThreatDetector(config_path=args.config)
    detector.start_monitoring()

if __name__ == "__main__":
    main()
