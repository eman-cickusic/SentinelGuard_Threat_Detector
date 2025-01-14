from scapy.all import TCP, UDP, DNS

def get_protocol(packet):
    if TCP in packet:
        return 'TCP'
    elif UDP in packet:
        return 'UDP'
    elif DNS in packet:
        return 'DNS'
    return 'OTHER'

def get_source_port(packet):
    if TCP in packet:
        return packet[TCP].sport
    elif UDP in packet:
        return packet[UDP].sport
    return None

def get_destination_port(packet):
    if TCP in packet:
        return packet[TCP].dport
    elif UDP in packet:
        return packet[UDP].dport
    return None

