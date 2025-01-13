import logging
import sqlite3
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS

class EnhancedThreatDetector:
    def __init__(self, config):
        self.config = config
        self.setup_logging()
        self.setup_database()
        self.running = False

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=self.config['logging']['file_path']
        )
        self.logger = logging.getLogger(__name__)

    def setup_database(self):
        self.conn = sqlite3.connect(self.config['database']['path'])
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
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
        self.logger.info("Enhanced Threat Detection System is running...")
        try:
            sniff(prn=self.analyze_packet, store=0)
        except KeyboardInterrupt:
            self.cleanup()

    def analyze_packet(self, packet):
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

    def get_protocol(self, packet):
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif DNS in packet:
            return 'DNS'
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

    def cleanup(self):
        self.logger.info("Shutting down Enhanced Threat Detection System")
        self.conn.close()
