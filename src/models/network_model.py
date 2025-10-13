import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
from datetime import datetime, timedelta
import random

class NetworkModelTrainer:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.encoders = {}
    
    def generate_network_traffic(self, num_records=5000):
        """Realistic network traffic generate karte hain"""
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH']
        internal_ips = [f'192.168.1.{i}' for i in range(1, 101)]
        external_ips = ['8.8.8.8', '1.1.1.1', '151.101.1.69', '142.250.182.206']
        
        traffic_data = []
        
        # Normal traffic (90%)
        for i in range(int(num_records * 0.9)):
            timestamp = datetime.now() - timedelta(minutes=random.randint(0, 10080))
            
            # Normal traffic patterns
            src_ip = random.choice(internal_ips)
            
            if random.random() < 0.7:  # 70% internal to external
                dst_ip = random.choice(external_ips)
                protocol = random.choice(['HTTP', 'HTTPS', 'DNS'])
                dst_port = random.choice([80, 443, 53])
                duration = random.uniform(0.1, 30)
                bytes_sent = random.randint(100, 5000)
                bytes_received = random.randint(100, 10000)
            else:  # 30% internal to internal
                dst_ip = random.choice(internal_ips)
                protocol = random.choice(['TCP', 'UDP', 'SSH'])
                dst_port = random.choice([22, 3389, 5900])
                duration = random.uniform(0.1, 10)
                bytes_sent = random.randint(50, 2000)
                bytes_received = random.randint(50, 2000)
            
            traffic_data.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': random.randint(1000, 65535),
                'dst_port': dst_port,
                'duration': duration,
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packet_size': random.randint(64, 1500),
                'is_anomaly': 0
            })
        
        # Anomalous traffic (10%)
        anomalous_patterns = [
            # Port scanning
            {'type': 'port_scan', 'src_ip': '192.168.1.99', 'dst_ip': '8.8.8.8', 'ports': range(20, 30)},
            # DDoS attack
            {'type': 'ddos', 'src_ips': [f'10.0.1.{i}' for i in range(1, 21)], 'dst_ip': '192.168.1.10'},
            # Data exfiltration
            {'type': 'data_exfil', 'src_ip': '192.168.1.77', 'dst_ip': '45.33.32.156'},
            # Suspicious protocol
            {'type': 'suspicious', 'src_ip': '192.168.1.88', 'dst_ip': '203.0.113.1', 'port': 4444}
        ]
        
        for pattern in anomalous_patterns:
            if pattern['type'] == 'port_scan':
                for port in pattern['ports']:
                    traffic_data.append({
                        'timestamp': datetime.now(),
                        'src_ip': pattern['src_ip'],
                        'dst_ip': pattern['dst_ip'],
                        'protocol': 'TCP',
                        'src_port': random.randint(1000, 65535),
                        'dst_port': port,
                        'duration': 0.1,
                        'bytes_sent': 64,
                        'bytes_received': 0,
                        'packet_size': 64,
                        'is_anomaly': 1
                    })
            
            elif pattern['type'] == 'ddos':
                for src_ip in pattern['src_ips']:
                    for i in range(5):  # 5 requests per IP
                        traffic_data.append({
                            'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 10)),
                            'src_ip': src_ip,
                            'dst_ip': pattern['dst_ip'],
                            'protocol': 'TCP',
                            'src_port': random.randint(1000, 65535),
                            'dst_port': 80,
                            'duration': 0.5,
                            'bytes_sent': 1500,
                            'bytes_received': 0,
                            'packet_size': 1500,
                            'is_anomaly': 1
                        })
            
            elif pattern['type'] == 'data_exfil':
                traffic_data.append({
                    'timestamp': datetime.now(),
                    'src_ip': pattern['src_ip'],
                    'dst_ip': pattern['dst_ip'],
                    'protocol': 'HTTPS',
                    'src_port': random.randint(1000, 65535),
                    'dst_port': 443,
                    'duration': 300,
                    'bytes_sent': 5000000,  # 5MB - suspicious
                    'bytes_received': 1000,
                    'packet_size': 1500,
                    'is_anomaly': 1
                })
            
            else:  # suspicious
                traffic_data.append({
                    'timestamp': datetime.now(),
                    'src_ip': pattern['src_ip'],
                    'dst_ip': pattern['dst_ip'],
                    'protocol': 'TCP',
                    'src_port': random.randint(1000, 65535),
                    'dst_port': pattern['port'],
                    'duration': 60,
                    'bytes_sent': 50000,
                    'bytes_received': 50000,
                    'packet_size': 1500,
                    'is_anomaly': 1
                })
        
        return pd.DataFrame(traffic_data)
    
    def extract_features(self, df):
        """Network features extract karte hain"""
        df = df.copy()
        
        # Basic encoding
        df['src_ip_type'] = df['src_ip'].apply(lambda x: 0 if x.startswith('192.168.') else 1)
        df['dst_ip_type'] = df['dst_ip'].apply(lambda x: 0 if x.startswith('192.168.') else 1)
        
        # Protocol encoding
        if 'protocol' not in self.encoders:
            self.encoders['protocol'] = LabelEncoder()
            self.encoders['protocol'].fit(df['protocol'])
        df['protocol_encoded'] = self.encoders['protocol'].transform(df['protocol'])
        
        # Behavioral features
        df['bytes_per_second'] = df['bytes_sent'] / (df['duration'] + 0.001)
        df['packet_ratio'] = df['bytes_sent'] / (df['bytes_received'] + 0.001)
        
        # Port analysis
        df['is_well_known_port'] = df['dst_port'].apply(lambda x: 1 if x <= 1024 else 0)
        df['is_suspicious_port'] = df['dst_port'].apply(lambda x: 1 if x in [4444, 31337, 1337] else 0)
        
        # Time features
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        df['is_off_hours'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        
        # Feature selection
        features = [
            'src_ip_type', 'dst_ip_type', 'protocol_encoded', 'dst_port',
            'duration', 'bytes_sent', 'bytes_received', 'packet_size',
            'bytes_per_second', 'packet_ratio', 'is_well_known_port',
            'is_suspicious_port', 'hour', 'is_off_hours'
        ]
        
        return df[features]
    
    def train(self):
        """Network model train karte hain"""
        print("🔄 Generating network traffic data...")
        df = self.generate_network_traffic(6000)
        
        print("📊 Extracting network features...")
        X = self.extract_features(df)
        y = df['is_anomaly']
        
        print("🤖 Training Network Anomaly Detector...")
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=42,
            verbose=1
        )
        
        # Scale and train
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        
        # Evaluate
        predictions = self.model.predict(X_scaled)
        df['predicted_anomaly'] = (predictions == -1).astype(int)
        
        accuracy = (df['predicted_anomaly'] == df['is_anomaly']).mean()
        print(f"✅ Training completed! Accuracy: {accuracy:.2%}")
        
        # Show some results
        anomalies = df[df['predicted_anomaly'] == 1]
        print(f"Detected {len(anomalies)} anomalous connections")
        
        return df
    
    def save_model(self, model_path='network_anomaly_detector.joblib'):
        """Model save karte hain"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'encoders': self.encoders
        }
        
        joblib.dump(model_data, model_path)
        print(f"✅ Network model saved to {model_path}")

def train_network_model():
    """Main training function"""
    trainer = NetworkModelTrainer()
    result_df = trainer.train()
    trainer.save_model()
    return trainer

if __name__ == "__main__":
    train_network_model()
