import scapy.all as scapy
import psutil
import netifaces
from threading import Thread, Lock
import time
import json
from datetime import datetime

class RealTimeNetworkScanner:
    def __init__(self):
        self.is_scanning = False
        self.suspicious_activities = []
        self.packet_count = 0
        self.lock = Lock()
        self.scan_thread = None
        
    def get_network_interfaces(self):
        """Available network interfaces get karein"""
        interfaces = []
        for interface in netifaces.interfaces():
            try:
                if interface == 'lo':  # Loopback skip karein
                    continue
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    interfaces.append(interface)
            except:
                continue
        return interfaces
    
    def packet_handler(self, packet):
        """Packet capture and analysis"""
        if not self.is_scanning:
            return
            
        self.packet_count += 1
        
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            
            # Protocol mapping
            protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(protocol, f'Unknown({protocol})')
            
            # Suspicious activity detection
            threat_info = self.detect_suspicious_activity(packet, src_ip, dst_ip, protocol_name)
            
            if threat_info:
                with self.lock:
                    # ✅ FIXED: ISO format timestamp
                    self.suspicious_activities.append({
                        'timestamp': datetime.now().isoformat(),  # ✅ Ye line fixed hai
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': protocol_name,
                        'threat_type': threat_info['type'],
                        'severity': threat_info['severity'],
                        'description': threat_info['description'],
                        'packet_size': len(packet)
                    })
                
                print(f"🚨 THREAT DETECTED: {threat_info['type']} | {src_ip} -> {dst_ip} | {protocol_name}")
    
    def detect_suspicious_activity(self, packet, src_ip, dst_ip, protocol):
        """Suspicious network activity detect karein"""
        # Port scanning detection
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            if tcp_layer.flags == 2:  # SYN flag only (port scanning)
                return {
                    'type': 'Port Scanning',
                    'severity': 'high',
                    'description': f'SYN packet detected - possible port scanning from {src_ip}'
                }
            
            # Unusual port activity
            if tcp_layer.dport in [21, 22, 23, 25, 110, 143, 993, 995]:  # Common service ports
                if tcp_layer.flags == 2:  # SYN to service port
                    return {
                        'type': 'Service Port Access Attempt',
                        'severity': 'medium', 
                        'description': f'SYN packet to service port {tcp_layer.dport} from {src_ip}'
                    }
        
        # Large data transfer detection
        if packet.haslayer(scapy.IP):
            packet_size = len(packet)
            if packet_size > 2000:  # Very large packet
                return {
                    'type': 'Large Data Transfer',
                    'severity': 'low',
                    'description': f'Large packet ({packet_size} bytes) from {src_ip}'
                }
        
        # ICMP flood detection (basic)
        if packet.haslayer(scapy.ICMP):
            return {
                'type': 'ICMP Activity',
                'severity': 'low',
                'description': f'ICMP packet from {src_ip}'
            }
        
        return None
    
    def scan_network(self, interface='eth0'):
        """Network traffic capture karein"""
        print(f"🎯 Starting packet capture on {interface}...")
        try:
            scapy.sniff(iface=interface, prn=self.packet_handler, store=False, stop_filter=lambda x: not self.is_scanning)
        except Exception as e:
            print(f"❌ Scanning error on {interface}: {e}")
    
    def start_realtime_scan(self, interface='eth0'):
        """Real-time scanning start karein"""
        self.is_scanning = True
        self.suspicious_activities = []
        self.packet_count = 0
        
        self.scan_thread = Thread(target=self.scan_network, args=(interface,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        print(f"🚀 Real-time network scanning started on {interface}")
    
    def stop_scan(self):
        """Scanning stop karein"""
        self.is_scanning = False
        print("🛑 Network scanning stopped")
    
    def get_threats(self):
        """Detected threats get karein"""
        with self.lock:
            return self.suspicious_activities.copy()
    
    def get_packet_statistics(self):
        """Packet statistics get karein"""
        return {
            'total_packets_captured': self.packet_count,
            'total_threats_detected': len(self.suspicious_activities),
            'is_scanning': self.is_scanning,
            'high_severity_threats': len([t for t in self.suspicious_activities if t.get('severity') == 'high']),
            'scan_duration': 'N/A'
        }
