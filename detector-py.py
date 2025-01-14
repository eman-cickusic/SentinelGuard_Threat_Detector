import logging
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP
from .utils import get_protocol, get_source_port, get_destination_port
from .database import Database

class ThreatDetector:
    def __init__(self, config):
        self.config = config
        self.setup_logging()
        self.db = Database(config['database']['path'])
        
        # Simple connection tracking
        self.connection_counts = defaultdict(int)
        self.packet_buffer = []
        
        # Load thresholds from config
        self.suspicious_ports = set(config['thresholds']['suspicious_ports'])
        self.max_connections = config['thresholds']['max_connections']

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=self.config['logging']['file_path']
        )
        self.logger = logging.getLogger(__name__)

    def start_monitoring(self):
        self.logger.info("Starting Threat Detection System...")
        try:
            sniff(prn=self.analyze_packet, store=0)
        except KeyboardInterrupt:
            self.cleanup()

    def analyze_packet(self, packet):
        if IP not in packet:
            return

        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'protocol': get_protocol(packet),
            'source_port': get_source_port(packet),
            'destination_port': get_destination_port(packet),
            'packet_size': len(packet)
        }

        # Add to buffer
        self.packet_buffer.append(packet_info)
        
        # Save to database every 100 packets
        if len(self.packet_buffer) >= 100:
            self.db.save_packets(self.packet_buffer)
            self.packet_buffer = []

        # Basic threat detection
        self.check_suspicious_activity(packet_info)

    def check_suspicious_activity(self, packet_info):
        source_ip = packet_info['source_ip']
        dest_port = packet_info['destination_port']

        # Check suspicious ports
        if dest_port in self.suspicious_ports:
            self.generate_alert(
                "SUSPICIOUS_PORT_ACCESS",
                source_ip,
                f"Access attempt to suspicious port {dest_port}"
            )

        # Simple connection counting
        self.connection_counts[source_ip] += 1
        if self.connection_counts[source_ip] > self.max_connections:
            self.generate_alert(
                "MANY_CONNECTIONS",
                source_ip,
                "Too many connection attempts"
            )

    def generate_alert(self, alert_type, source_ip, details):
        self.db.save_alert(alert_type, source_ip, details)
        self.logger.warning(
            f"Alert: {alert_type} from {source_ip}. Details: {details}"
        )

    def cleanup(self):
        self.logger.info("Shutting down Threat Detection System")
        self.db.save_packets(self.packet_buffer)  # Save any remaining packets
        self.db.close()
