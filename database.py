import sqlite3
from datetime import datetime

class Database:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.setup_tables()

    def setup_tables(self):
        self.cursor.executescript('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                packet_size INTEGER
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

    def save_packets(self, packets):
        if not packets:
            return
            
        self.cursor.executemany('''
            INSERT INTO traffic_logs 
            (timestamp, source_ip, destination_ip, source_port, 
            destination_port, protocol, packet_size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', [
            (p['timestamp'], p['source_ip'], p['destination_ip'],
            p['source_port'], p['destination_port'], p['protocol'],
            p['packet_size'])
            for p in packets
        ])
        self.conn.commit()

    def save_alert(self, alert_type, source_ip, details):
        self.cursor.execute('''
            INSERT INTO alerts 
            (timestamp, alert_type, source_ip, details)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            alert_type,
            source_ip,
            details
        ))
        self.conn.commit()

    def close(self):
        self.conn.close()

