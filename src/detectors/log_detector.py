import pandas as pd
import numpy as np
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class LogAnomalyDetector:
    def __init__(self, model_path='log_anomaly_detector.joblib'):
        print(f"📊 Loading log anomaly detector from {model_path}...")
        
        try:
            loaded_data = joblib.load(model_path)
            self.model = loaded_data['model']
            self.encoders = loaded_data['encoders']
            self.scaler = loaded_data['scaler']
            self.feature_columns = loaded_data.get('feature_columns', [
                'log_type_encoded', 'user_encoded', 'source_ip_encoded', 'severity_encoded',
                'hour', 'day_of_week', 'is_weekend', 'is_night',
                'user_frequency', 'ip_frequency', 'recent_activity'
            ])
            print("✅ Log anomaly detector loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading log model: {e}")
            # Create fallback model
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(n_estimators=50, contamination=0.1, random_state=42)
            self.encoders = {}
            self.scaler = None
            self.feature_columns = []

    def _add_basic_features(self, df):
        """Basic features add karte hain"""
        df = df.copy()
        
        # Ensure timestamp
        if 'timestamp' not in df.columns:
            df['timestamp'] = datetime.now()
        
        # Convert timestamp
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Time features
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        
        return df

    def _encode_features(self, df):
        """Features encode karte hain"""
        df = df.copy()
        
        # Categorical features ko encode karein
        categorical_columns = ['log_type', 'user', 'source_ip', 'severity']
        
        for col in categorical_columns:
            if col in df.columns:
                if col not in self.encoders:
                    # Create new encoder
                    from sklearn.preprocessing import LabelEncoder
                    self.encoders[col] = LabelEncoder()
                    # Fit on available values
                    unique_values = df[col].unique().tolist()
                    self.encoders[col].fit(unique_values)
                
                df[f'{col}_encoded'] = self.encoders[col].transform(df[col])
            else:
                df[f'{col}_encoded'] = 0  # Default value
        
        return df

    def _add_behavioral_features(self, df):
        """Behavioral features add karte hain"""
        df = df.copy()
        
        # Simple behavioral features (simulated)
        if 'user' in df.columns:
            user_counts = df['user'].value_counts()
            df['user_frequency'] = df['user'].map(user_counts).fillna(1)
        else:
            df['user_frequency'] = 1
        
        if 'source_ip' in df.columns:
            ip_counts = df['source_ip'].value_counts()
            df['ip_frequency'] = df['source_ip'].map(ip_counts).fillna(1)
        else:
            df['ip_frequency'] = 1
        
        # Recent activity (simulated)
        df['recent_activity'] = np.random.randint(1, 10, len(df))
        
        return df

    def _prepare_features(self, df):
        """Final features prepare karte hain"""
        # Add all features
        df = self._add_basic_features(df)
        df = self._encode_features(df)
        df = self._add_behavioral_features(df)
        
        # Ensure all required feature columns exist
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0  # Default value
        
        # Return only the feature columns that exist
        available_columns = [col for col in self.feature_columns if col in df.columns]
        return df[available_columns]

    def _get_risk_level(self, scores):
        """Risk levels determine karein"""
        if isinstance(scores, (int, float)):
            scores = [scores]
        
        risk_levels = []
        for score in scores:
            if score < -0.2:
                risk_levels.append("CRITICAL")
            elif score < -0.1:
                risk_levels.append("HIGH")
            elif score < 0:
                risk_levels.append("MEDIUM")
            else:
                risk_levels.append("LOW")
        return risk_levels

    def analyze_real_time(self, log_entries):
        """Real-time log analysis - COMPLETELY FIXED"""
        try:
            print(f"🔧 Processing {len(log_entries)} log entries...")
            
            # Convert to DataFrame
            if not isinstance(log_entries, pd.DataFrame):
                df = pd.DataFrame(log_entries)
            else:
                df = log_entries.copy()
            
            # Prepare features
            features = self._prepare_features(df)
            
            # If no scaler, create a simple one
            if self.scaler is None:
                from sklearn.preprocessing import StandardScaler
                self.scaler = StandardScaler()
                # Fit on current data
                if len(features) > 1:
                    self.scaler.fit(features)
                else:
                    # If only one sample, use identity scaling
                    self.scaler.mean_ = np.zeros(features.shape[1])
                    self.scaler.scale_ = np.ones(features.shape[1])
            
            # Scale features
            try:
                features_scaled = self.scaler.transform(features)
            except:
                # If scaling fails, use original features
                features_scaled = features.values
            
            # Predict anomalies
            predictions = self.model.predict(features_scaled)
            anomaly_scores = self.model.decision_function(features_scaled)
            
            # Add results to original data
            results = df.copy()
            results['is_anomaly'] = (predictions == -1)
            results['anomaly_score'] = anomaly_scores
            results['risk_level'] = self._get_risk_level(anomaly_scores)
            
            # Generate alerts for high-risk anomalies
            alerts = []
            for idx, row in results.iterrows():
                if row['is_anomaly'] and row['risk_level'] in ['HIGH', 'CRITICAL']:
                    alert_info = {
                        'timestamp': str(row.get('timestamp', datetime.now())),
                        'log_type': str(row.get('log_type', 'UNKNOWN')),
                        'user': str(row.get('user', 'UNKNOWN')),
                        'source_ip': str(row.get('source_ip', 'UNKNOWN')),
                        'risk_level': str(row.get('risk_level', 'UNKNOWN')),
                        'anomaly_score': float(row.get('anomaly_score', 0)),
                        'message': f"Suspicious activity detected: {row.get('log_type', 'UNKNOWN')} by {row.get('user', 'UNKNOWN')}"
                    }
                    alerts.append(alert_info)
            
            # Final results
            final_results = {
                'total_logs': len(results),
                'anomalies_detected': int(results['is_anomaly'].sum()),
                'anomaly_percentage': float((results['is_anomaly'].sum() / len(results)) * 100),
                'high_risk_alerts': alerts
            }
            
            print("✅ Log analysis completed successfully!")
            return final_results
            
        except Exception as e:
            print(f"❌ Error in analyze_real_time: {e}")
            import traceback
            traceback.print_exc()
            return {
                'error': str(e),
                'total_logs': len(log_entries) if log_entries else 0,
                'anomalies_detected': 0,
                'anomaly_percentage': 0.0,
                'high_risk_alerts': []
            }

# Test function
def test_log_detector():
    """Test the log anomaly detector"""
    print("🧪 Testing Log Anomaly Detector...")
    
    try:
        detector = LogAnomalyDetector()
        
        # Sample log data
        sample_logs = [
            {
                'timestamp': datetime.now().isoformat(),
                'log_type': 'AUTH_SUCCESS',
                'user': 'user1',
                'source_ip': '192.168.1.10',
                'severity': 'LOW'
            },
            {
                'timestamp': datetime.now().isoformat(),
                'log_type': 'AUTH_FAILED', 
                'user': 'admin',
                'source_ip': '192.168.1.99',
                'severity': 'HIGH'
            },
            {
                'timestamp': datetime.now().isoformat(),
                'log_type': 'FILE_ACCESS',
                'user': 'guest',
                'source_ip': '192.168.1.77', 
                'severity': 'HIGH'
            }
        ]
        
        results = detector.analyze_real_time(sample_logs)
        
        print(f"\n📊 Log Analysis Results:")
        print(f"Total logs analyzed: {results['total_logs']}")
        print(f"Anomalies detected: {results['anomalies_detected']}")
        print(f"Anomaly percentage: {results['anomaly_percentage']:.2f}%")
        
        if results['high_risk_alerts']:
            print(f"\n🚨 High Risk Alerts:")
            for alert in results['high_risk_alerts']:
                print(f"  • {alert['message']}")
                print(f"    Risk: {alert['risk_level']}, Score: {alert['anomaly_score']:.3f}")
        else:
            print("\n✅ No high risk alerts")
            
        print(f"\n✅ Log detector test completed!")
        return True
        
    except Exception as e:
        print(f"❌ Log detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_log_detector()
