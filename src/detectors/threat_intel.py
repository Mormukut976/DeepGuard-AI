class ThreatIntel:
    def __init__(self):
        self.known_malicious_ips = [
            '192.168.1.100',
            '10.0.0.50'
        ]
    
    def check_ip_reputation(self, ip_address):
        """Check IP reputation"""
        is_malicious = ip_address in self.known_malicious_ips
        
        return {
            "ip_address": ip_address,
            "is_malicious": is_malicious,
            "reputation": "Malicious" if is_malicious else "Clean",
            "sources_checked": 1,
            "timestamp": "2024-01-01T00:00:00"
        }
