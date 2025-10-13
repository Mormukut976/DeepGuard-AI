import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import numpy as np
import os

class PhishingDetector:
    def __init__(self, model_path='./phishing_model'):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print(f"📧 Loading phishing model from {model_path}...")
        
        try:
            self.tokenizer = DistilBertTokenizer.from_pretrained(model_path)
            self.model = DistilBertForSequenceClassification.from_pretrained(model_path)
            self.model.to(self.device)
            self.model.eval()
            print("✅ Phishing detector loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading phishing model: {e}")
            raise e

    def predict(self, email_text):
        """Email analyze karein aur phishing probability return karein"""
        try:
            inputs = self.tokenizer(
                email_text,
                truncation=True,
                padding=True,
                max_length=128,
                return_tensors='pt'
            )

            inputs = {key: value.to(self.device) for key, value in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
            phishing_prob = predictions[0][1].item()
            legit_prob = predictions[0][0].item()
            
            return {
                'is_phishing': phishing_prob > 0.7,
                'phishing_probability': phishing_prob,
                'legitimate_probability': legit_prob,
                'confidence': max(phishing_prob, legit_prob),
                'risk_level': self._get_risk_level(phishing_prob),
                'verdict': '🚨 PHISHING' if phishing_prob > 0.7 else '✅ LEGITIMATE'
            }
        except Exception as e:
            return {
                'error': str(e),
                'is_phishing': False,
                'phishing_probability': 0.0,
                'risk_level': 'UNKNOWN'
            }

    def _get_risk_level(self, probability):
        if probability > 0.9:
            return "CRITICAL"
        elif probability > 0.7:
            return "HIGH"
        elif probability > 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def analyze_multiple_emails(self, email_list):
        """Multiple emails ko analyze karein"""
        results = []
        for i, email in enumerate(email_list):
            result = self.predict(email)
            result['email_id'] = i + 1
            result['email_preview'] = email[:80] + "..." if len(email) > 80 else email
            results.append(result)
        
        # Summary statistics
        phishing_count = sum(1 for r in results if r.get('is_phishing', False))
        total_emails = len(results)
        
        summary = {
            'total_emails': total_emails,
            'phishing_detected': phishing_count,
            'legitimate_count': total_emails - phishing_count,
            'phishing_percentage': (phishing_count / total_emails) * 100 if total_emails > 0 else 0
        }
        
        return {
            'summary': summary,
            'detailed_results': results
        }

# Test function
def test_phishing_detector():
    """Test the phishing detector"""
    print("🧪 Testing Phishing Detector...")
    
    try:
        detector = PhishingDetector()
        
        test_emails = [
            "Congratulations! You won $1000. Click here to claim your prize",
            "Hi John, meeting scheduled for tomorrow at 3 PM. Best regards",
            "URGENT: Your bank account will be suspended. Verify now!",
            "Your package has been delivered. Track your order here",
            "Free iPhone! Click now to claim your gift"
        ]
        
        results = detector.analyze_multiple_emails(test_emails)
        
        print(f"\n📊 Summary:")
        print(f"Total emails: {results['summary']['total_emails']}")
        print(f"Phishing detected: {results['summary']['phishing_detected']}")
        print(f"Legitimate: {results['summary']['legitimate_count']}")
        
        print(f"\n📧 Detailed Results:")
        for result in results['detailed_results']:
            print(f"Email {result['email_id']}: {result['verdict']}")
            print(f"  Phishing Probability: {result['phishing_probability']:.3f}")
            print(f"  Risk Level: {result['risk_level']}")
            print()
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_phishing_detector()
