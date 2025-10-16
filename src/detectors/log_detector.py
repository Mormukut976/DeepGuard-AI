import re
from datetime import datetime

class LogDetector:
    def __init__(self):
        self.suspicious_patterns = [
            r'failed password',
            r'authentication failure',
            r'incorrect password',
            r'access denied',
            r'unauthorized',
            r'brute force',
            r'port scan',
            r'SQL injection',
            r'XSS',
            r'malware',
            r'ransomware',
            r'privilege escalation'
        ]
        self.stats = {'total_analyses': 0}

    def analyze_logs(self, log_data):
        """Analyze log data for suspicious activities"""
        self.stats['total_analyses'] += 1
        
        lines = log_data.split('\n')
        anomalies_detected = 0
        suspicious_entries = []

        for line in lines:
            if not line.strip():
                continue
                
            for pattern in self.suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    anomalies_detected += 1
                    suspicious_entries.append(line)
                    break

        # Threat level determine karein
        if anomalies_detected == 0:
            threat_level = "Low"
        elif anomalies_detected <= 3:
            threat_level = "Medium"
        else:
            threat_level = "High"

        return {
            "anomalies_detected": anomalies_detected > 0,
            "anomaly_count": anomalies_detected,
            "threat_level": threat_level,
            "suspicious_entries": suspicious_entries,
            "timestamp": datetime.now().isoformat()
        }

    def get_stats(self):
        return self.stats
