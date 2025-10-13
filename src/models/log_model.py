import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
from datetime import datetime, timedelta
import random

class LogModelTrainer:
    def __init__(self):
        self.model = None
        self.encoders = {}
        self.scaler = StandardScaler()
    
    def generate_realistic_logs(self, num_logs=2000):
        """Realistic log data generate karte hain"""
        log_types = ["AUTH_SUCCESS", "AUTH_FAILED", "FILE_ACCESS", "NETWORK_CONNECTION", "USER_LOGIN", "USER_LOGOUT"]
        users = ["user1", "user2", "user3", "admin", "guest", "service_account"]
        ips = [f"192.168.1.{i}" for i in range(1, 101)]
        
        logs = []
        
        # Normal logs (90%)
        for i in range(int(num_logs * 0.9)):
            log_time = datetime.now() - timedelta(hours=random.randint(0, 720))  # 30 days
            
            # Normal patterns
            if random.random() < 0.8:  # 80% normal behavior
                log_type = random.choice(["AUTH_SUCCESS", "FILE_ACCESS", "NETWORK_CONNECTION", "USER_LOGIN"])
                user = random.choice(users)
                ip = random.choice(ips[:50])  # Internal IPs
                severity = "LOW"
            else:  # 20% some failures
                log_type = "AUTH_FAILED"
                user = random.choice(users)
                ip = random.choice(ips[:50])
                severity = "MEDIUM"
            
            logs.append({
                'timestamp': log_time,
                'log_type': log_type,
                'user': user,
                'source_ip': ip,
                'severity': severity,
                'is_anomaly': 0
            })
        
        # Anomalous logs (10%)
        anomalous_patterns = [
            # Brute force attack
            {"log_type": "AUTH_FAILED", "user": "admin", "count": 20, "ip": "192.168.1.99"},
            # Sensitive file access
            {"log_type": "FILE_ACCESS", "user": "guest", "files": ["/etc/passwd"], "ip": "192.168.1.77"},
            # External IP communication
            {"log_type": "NETWORK_CONNECTION", "user": "user1", "ip": "203.0.113.1"},
            # Off-hours activity
            {"log_type": "USER_LOGIN", "user": "service_account", "time": "03:00", "ip": "192.168.1.88"},
            # Multiple user failures
            {"log_type": "AUTH_FAILED", "user": "user2", "count": 15, "ip": "192.168.1.66"}
        ]
        
        for pattern in anomalous_patterns:
            for i in range(20):  # 20 logs per pattern
                log_time = datetime.now() - timedelta(minutes=random.randint(0, 60))
                
                logs.append({
                    'timestamp': log_time,
                    'log_type': pattern["log_type"],
                    'user': pattern["user"],
                    'source_ip': pattern["ip"],
                    'severity': "HIGH",
                    'is_anomaly': 1
                })
        
        return pd.DataFrame(logs)
    
    def extract_features(self, df):
        """Smart features extract karte hain"""
        # Copy dataframe
        df = df.copy()
        
        # Time features
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        
        # Encode categorical variables
        for col in ['log_type', 'user', 'source_ip', 'severity']:
            if col not in self.encoders:
                self.encoders[col] = LabelEncoder()
                self.encoders[col].fit(df[col])
            df[f'{col}_encoded'] = self.encoders[col].transform(df[col])
        
        # Behavioral features
        user_counts = df['user'].value_counts()
        ip_counts = df['source_ip'].value_counts()
        
        df['user_frequency'] = df['user'].map(user_counts)
        df['ip_frequency'] = df['source_ip'].map(ip_counts)
        
        # Recent activity (last hour simulation)
        df['recent_activity'] = np.random.randint(1, 50, len(df))
        
        # Select final features
        feature_columns = [
            'log_type_encoded', 'user_encoded', 'source_ip_encoded', 'severity_encoded',
            'hour', 'day_of_week', 'is_weekend', 'is_night',
            'user_frequency', 'ip_frequency', 'recent_activity'
        ]
        
        return df[feature_columns]
    
    def train(self):
        """Model train karte hain"""
        print("🔄 Generating log data...")
        df = self.generate_realistic_logs(3000)
        
        print("📊 Extracting features...")
        X = self.extract_features(df)
        y = df['is_anomaly']
        
        print("🤖 Training Isolation Forest...")
        self.model = IsolationForest(
            n_estimators=150,
            contamination=0.1,  # 10% anomalies expect karte hain
            random_state=42,
            verbose=1
        )
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        
        # Evaluate
        predictions = self.model.predict(X_scaled)
        df['predicted_anomaly'] = (predictions == -1).astype(int)
        
        accuracy = (df['predicted_anomaly'] == df['is_anomaly']).mean()
        print(f"✅ Training completed! Accuracy: {accuracy:.2%}")
        
        return df
    
    def save_model(self, model_path='log_anomaly_detector.joblib'):
        """Model save karte hain"""
        model_data = {
            'model': self.model,
            'encoders': self.encoders,
            'scaler': self.scaler,
            'feature_names': ['log_type', 'user', 'source_ip', 'severity', 'hour', 'day_of_week', 
                            'is_weekend', 'is_night', 'user_frequency', 'ip_frequency', 'recent_activity']
        }
        
        joblib.dump(model_data, model_path)
        print(f"✅ Log model saved to {model_path}")

def train_log_model():
    """Main training function"""
    trainer = LogModelTrainer()
    result_df = trainer.train()
    trainer.save_model()
    return trainer

if __name__ == "__main__":
    train_log_model()
