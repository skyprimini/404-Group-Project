from scapy.all import IP, TCP
from collections import defaultdict

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        flow_duration = stats['last_time'] - stats['start_time']
        if flow_duration > 0:
            packet_rate = stats['packet_count'] / flow_duration
            byte_rate = stats['byte_count'] / flow_duration
        else:
            packet_rate = 0
            byte_rate = 0

        return {
            'src_ip': ip_src,  # Add source IP
            'dst_ip': ip_dst,  # Add destination IP
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            # Get integer value of flags
            'tcp_flags': packet[TCP].flags.value if TCP in packet else 0,
            'window_size': packet[TCP].window if TCP in packet else 0
        }
    
    def get_tcp_flags(flags_int):
        flags = []
        if flags_int & 0x02:
            flags.append('SYN')
        if flags_int & 0x10:
            flags.append('ACK')
        if flags_int & 0x01:
            flags.append('FIN')
        if flags_int & 0x08:
            flags.append('PSH')
        if flags_int & 0x20:
            flags.append('RST')
        if flags_int & 0x04:
            flags.append('URG')
        return flags
    
    def reset_inactive_flows(self, current_time, timeout=60):
        for flow_key, stats in list(self.flow_stats.items()):
            if stats['last_time'] and (current_time - stats['last_time']) > timeout:
                del self.flow_stats[flow_key]
                del self.connections[flow_key]
