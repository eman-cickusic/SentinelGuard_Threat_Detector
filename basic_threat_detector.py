import logging
import sqlite3
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
import yaml

class BasicThreatDetector:
    def __init__(self, config_path='config.yaml'):
        """Initialize the Basic Threat Detection System"""
        self.load_config(config_path)
        self.setup_logging()
        self.setup_database()
        self.running = False

    def load_config(self, config_path):
        """Load configuration from YAML file"""
        default_config = {
            'logging': {'file_path': 'logs/threat_detector.log'},
            'database': {'path': 'security.db'},
            'thresholds': {
                'max_failed_attempts': 5,
                'suspicious_ports': [22, 3389, 445],
                'max_connections': 50
            }
        }
        try:
            with open(config_path, 'r') as file:
                self.config = yaml.safe_load(file)
        except FileNotFoundError:
            print(f"Config file {config_path} not found. Using defaults.")
            self.config = default_config
        except Exception as e:
            print(f"Error loading config: {e}. Exiting.")
            exit(1)

    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=self.config['logging']['file_path']
        )
        self.logger = logging.getLogger(__name__)

    def setup_database(self):
        """Initialize SQLite database"""
        try:
            self.conn = sqlite3.connect(self.config['database']['path'])
            self.cursor = self.conn.cursor()
            self.create_tables()
        except Exception as e:
            self.logger.error(f"Database error: {e}")
            exit(1)

    def create_tables(self):
        """Create necessary database tables"""
        self.cursor.executescript('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                alert_type TEXT,
                source_ip TEXT,
                details TEXT
            );
        ''')
        self.conn.commit()

    def start_monitoring(self):
        """Start network monitoring"""
        self.logger.info("🚀 Basic Threat Detection System is running...")
        print("Press Ctrl+C to stop the system.")
        self.running = True
        try:
            sniff(prn=self.analyze_packet, store=0)
        except KeyboardInterrupt:
            print("\nSystem interrupted. Cleaning up...")
        except Exception as e:
            self.logger.error(f"Error during monitoring: {e}")
        finally:
            self.cleanup()

    def analyze_packet(self, packet):
        """Analyze network packets for basic threats"""
        if IP in packet:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': packet[IP].src,
                'destination_ip': packet[IP].dst,
                'protocol': self.get_protocol(packet),
                'source_port': self.get_source_port(packet),
                'destination_port': self.get_destination_port(packet)
            }

            self.store_traffic_log(packet_info)
            self.check_suspicious_ports(packet_info)
            self.check_connection_rate(packet_info)

    def get_protocol(self, packet):
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        return 'OTHER'

    def get_source_port(self, packet):
        if TCP in packet:
            return packet[TCP].sport
        elif UDP in packet:
            return packet[UDP].sport
        return None

    def get_destination_port(self, packet):
        if TCP in packet:
            return packet[TCP].dport
        elif UDP in packet:
            return packet[UDP].dport
        return None

    def store_traffic_log(self, packet_info):
        try:
            self.cursor.execute('''
                INSERT INTO traffic_logs 
                (timestamp, source_ip, destination_ip, source_port, destination_port, protocol)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                packet_info['timestamp'],
                packet_info['source_ip'],
                packet_info['destination_ip'],
                packet_info['source_port'],
                packet_info['destination_port'],
                packet_info['protocol']
            ))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Error storing traffic log: {e}")

    def check_suspicious_ports(self, packet_info):
        if packet_info['destination_port'] in self.config['thresholds']['suspicious_ports']:
            self.generate_alert(
                'SUSPICIOUS_PORT_ACCESS',
                packet_info['source_ip'],
                f"Access attempt to suspicious port {packet_info['destination_port']}"
            )

    def check_connection_rate(self, packet_info):
        try:
            self.cursor.execute('''
                SELECT COUNT(*) FROM traffic_logs
                WHERE source_ip = ?
                AND timestamp >= datetime('now', '-1 minute')
            ''', (packet_info['source_ip'],))
            
            count = self.cursor.fetchone()[0]
            if count > self.config['thresholds']['max_connections']:
                self.generate_alert(
                    'HIGH_CONNECTION_RATE',
                    packet_info['source_ip'],
                    f"High connection rate detected: {count} connections/minute"
                )
        except Exception as e:
            self.logger.error(f"Error checking connection rate: {e}")

    def generate_alert(self, alert_type, source_ip, details):
        try:
            self.cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, source_ip, details)
                VALUES (?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                alert_type,
                source_ip,
                details
            ))
            self.conn.commit()
            self.logger.warning(f"[ALERT] {alert_type}: {source_ip} - {details}")
        except Exception as e:
            self.logger.error(f"Error generating alert: {e}")

    def cleanup(self):
        self.logger.info("Shutting down Basic Threat Detection System")
        self.running = False
        self.conn.close()
