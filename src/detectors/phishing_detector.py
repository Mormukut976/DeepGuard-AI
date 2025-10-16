import re
from datetime import datetime

class PhishingDetector:
    def __init__(self):
        self.phishing_keywords = [
            'urgent', 'verify', 'suspended', 'security', 'login',
            'account', 'password', 'confirm', 'click', 'link',
            'winner', 'prize', 'free', 'money', 'bank',
            'paypal', 'amazon', 'ebay', 'facebook', 'google'
        ]
        self.suspicious_domains = [
            'verify-', 'security-', 'login-', 'account-',
            'free-', 'prize-', 'winner-'
        ]
        self.stats = {'total_checks': 0}

    def analyze_email(self, email_content):
        """Analyze email for phishing attempts"""
        self.stats['total_checks'] += 1
        
        score = 0
        details = []
        
        # Check for urgent language
        urgent_words = ['urgent', 'immediately', 'asap', 'important']
        for word in urgent_words:
            if word in email_content.lower():
                score += 1
                details.append(f"Urgent language detected: '{word}'")
        
        # Check for suspicious keywords
        for keyword in self.phishing_keywords:
            if keyword in email_content.lower():
                score += 0.5
                details.append(f"Suspicious keyword: '{keyword}'")
        
        # Check for suspicious links
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_content)
        
        for url in urls:
            score += 2
            details.append(f"Suspicious URL: {url}")
        
        # Determine threat level
        if score >= 5:
            is_phishing = True
            threat_level = "High"
            confidence = min(score / 10, 0.95)
        elif score >= 3:
            is_phishing = True
            threat_level = "Medium"
            confidence = min(score / 10, 0.85)
        elif score >= 1:
            is_phishing = False
            threat_level = "Low"
            confidence = 0.3
        else:
            is_phishing = False
            threat_level = "Very Low"
            confidence = 0.1

        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "threat_level": threat_level,
            "details": details,
            "score": score,
            "timestamp": datetime.now().isoformat()
        }

    def get_stats(self):
        return self.stats
