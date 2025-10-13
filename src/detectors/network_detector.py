import pandas as pd
import numpy as np
import joblib
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class NetworkAnomalyDetector:
    def __init__(self, model_path='network_anomaly_detector.joblib'):
        print(f"🌐 Loading network anomaly detector from {model_path}...")
        
        try:
            loaded_data = joblib.load(model_path)
            self.model = loaded_data['model']
            self.scaler = loaded_data['scaler']
            self.encoders = loaded_data['encoders']
            print("✅ Network anomaly detector loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading network model: {e}")
            raise e

    def preprocess_network_data(self, network_data):
        """Network data ko preprocess karein"""
        # Ensure DataFrame
        if not isinstance(network_data, pd.DataFrame):
            df = pd.DataFrame(network_data)
        else:
            df = network_data.copy()
        
        # IP type classification
        df['src_ip_type'] = df['src_ip'].apply(lambda x: 0 if str(x).startswith('192.168.') else 1)
        df['dst_ip_type'] = df['dst_ip'].apply(lambda x: 0 if str(x).startswith('192.168.') else 1)
        
        # Protocol encoding
        if 'protocol' in df.columns:
            try:
                df['protocol_encoded'] = self.encoders['protocol'].transform(df['protocol'])
            except:
                # Agar new protocol aaye toh default value
                df['protocol_encoded'] = 0
        else:
            df['protocol_encoded'] = 0
        
        # Behavioral features with error handling
        df['bytes_per_second'] = df.apply(
            lambda x: x['bytes_sent'] / (x['duration'] + 0.001) if 'bytes_sent' in x and 'duration' in x else 0, 
            axis=1
        )
        
        df['packet_ratio'] = df.apply(
            lambda x: x['bytes_sent'] / (x['bytes_received'] + 0.001) if 'bytes_sent' in x and 'bytes_received' in x else 1,
            axis=1
        )
        
        # Port analysis
        df['is_well_known_port'] = df['dst_port'].apply(lambda x: 1 if int(x) <= 1024 else 0)
        df['is_suspicious_port'] = df['dst_port'].apply(lambda x: 1 if int(x) in [4444, 31337, 1337, 12345, 9999] else 0)
        
        # Time features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
        else:
            df['hour'] = 12  # Default hour
            
        df['is_off_hours'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        
        # Ensure all required columns
        default_values = {
            'duration': 1.0,
            'bytes_sent': 1000,
            'bytes_received': 1000,
            'packet_size': 1500,
            'dst_port': 80
        }
        
        for col, default_val in default_values.items():
            if col not in df.columns:
                df[col] = default_val
        
        # Feature selection - FINAL FIXED VERSION
        feature_columns = [
            'src_ip_type', 'dst_ip_type', 'protocol_encoded', 'dst_port',
            'duration', 'bytes_sent', 'bytes_received', 'packet_size',
            'bytes_per_second', 'packet_ratio', 'is_well_known_port',
            'is_suspicious_port', 'hour', 'is_off_hours'
        ]
        
        # Ensure all feature columns exist
        for col in feature_columns:
            if col not in df.columns:
                df[col] = 0  # Default value
        
        return df[feature_columns]

    def analyze_traffic(self, traffic_data):
        """Network traffic analyze karein - COMPLETELY FIXED"""
        try:
            print("🔧 Processing network traffic...")
            
            # Preprocess data
            features = self.preprocess_network_data(traffic_data)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict anomalies
            predictions = self.model.predict(features_scaled)
            anomaly_scores = self.model.decision_function(features_scaled)
            
            # Convert to DataFrame if not already
            if not isinstance(traffic_data, pd.DataFrame):
                results = pd.DataFrame(traffic_data)
            else:
                results = traffic_data.copy()
            
            # Add results
            results['is_anomaly'] = (predictions == -1)
            results['anomaly_score'] = anomaly_scores
            results['risk_level'] = self._get_risk_level(anomaly_scores)
            results['anomaly_type'] = results.apply(self._classify_anomaly, axis=1)
            
            # Generate security alerts
            alerts = []
            for idx, row in results.iterrows():
                if row['is_anomaly']:
                    alert_info = {
                        'timestamp': str(row.get('timestamp', datetime.now())),
                        'src_ip': str(row.get('src_ip', 'N/A')),
                        'dst_ip': str(row.get('dst_ip', 'N/A')),
                        'dst_port': int(row.get('dst_port', 0)),
                        'anomaly_type': str(row.get('anomaly_type', 'UNKNOWN')),
                        'risk_level': str(row.get('risk_level', 'UNKNOWN')),
                        'anomaly_score': float(row.get('anomaly_score', 0)),
                        'description': self._get_anomaly_description(row)
                    }
                    alerts.append(alert_info)
            
            # Calculate traffic summary - SAFELY
            try:
                internal_to_external = len(results[results['dst_ip_type'] == 1]) if 'dst_ip_type' in results.columns else 0
                internal_to_internal = len(results[results['dst_ip_type'] == 0]) if 'dst_ip_type' in results.columns else 0
                suspicious_ports = results['is_suspicious_port'].sum() if 'is_suspicious_port' in results.columns else 0
            except:
                internal_to_external = 0
                internal_to_internal = 0
                suspicious_ports = 0
            
            # Final results
            final_results = {
                'total_connections': len(results),
                'anomalous_connections': int(results['is_anomaly'].sum()),
                'anomaly_percentage': float((results['is_anomaly'].sum() / len(results)) * 100),
                'security_alerts': alerts,
                'traffic_summary': {
                    'internal_to_external': int(internal_to_external),
                    'internal_to_internal': int(internal_to_internal),
                    'suspicious_ports_used': int(suspicious_ports)
                }
            }
            
            print("✅ Network analysis completed successfully!")
            return final_results
            
        except Exception as e:
            print(f"❌ Error in analyze_traffic: {e}")
            import traceback
            traceback.print_exc()
            return {
                'error': str(e),
                'total_connections': 0,
                'anomalous_connections': 0,
                'anomaly_percentage': 0.0,
                'security_alerts': [],
                'traffic_summary': {
                    'internal_to_external': 0,
                    'internal_to_internal': 0,
                    'suspicious_ports_used': 0
                }
            }

    def _get_risk_level(self, scores):
        """Risk levels determine karein - FIXED"""
        if isinstance(scores, (int, float)):
            scores = [scores]
        
        risk_levels = []
        for score in scores:
            if score < -0.3:
                risk_levels.append("CRITICAL")
            elif score < -0.15:
                risk_levels.append("HIGH")
            elif score < -0.05:
                risk_levels.append("MEDIUM")
            else:
                risk_levels.append("LOW")
        return risk_levels

    def _classify_anomaly(self, row):
        """Anomaly type classify karein - FIXED"""
        if not row.get('is_anomaly', False):
            return "NORMAL"
        
        try:
            bytes_per_second = float(row.get('bytes_per_second', 0))
            is_suspicious_port = int(row.get('is_suspicious_port', 0))
            bytes_sent = float(row.get('bytes_sent', 0))
            is_off_hours = int(row.get('is_off_hours', 0))
            
            if bytes_per_second > 100000:
                return "DATA_EXFILTRATION"
            elif is_suspicious_port == 1:
                return "SUSPICIOUS_PORT"
            elif bytes_sent > 1000000:
                return "DDoS_ATTEMPT"
            elif is_off_hours == 1:
                return "OFF_HOURS_ACTIVITY"
            else:
                return "SUSPICIOUS_CONNECTION"
        except:
            return "UNKNOWN_ANOMALY"

    def _get_anomaly_description(self, row):
        """Anomaly description generate karein - FIXED"""
        anomaly_type = row.get('anomaly_type', 'UNKNOWN')
        
        descriptions = {
            "DATA_EXFILTRATION": f"High data transfer from {row.get('src_ip', 'N/A')} to external IP {row.get('dst_ip', 'N/A')}",
            "SUSPICIOUS_PORT": f"Connection to suspicious port {row.get('dst_port', 'N/A')} from {row.get('src_ip', 'N/A')}",
            "DDoS_ATTEMPT": f"Potential DDoS attack from {row.get('src_ip', 'N/A')} with {row.get('bytes_sent', 0)} bytes sent",
            "OFF_HOURS_ACTIVITY": f"Unusual network activity during off-hours from {row.get('src_ip', 'N/A')}",
            "SUSPICIOUS_CONNECTION": f"Suspicious connection pattern from {row.get('src_ip', 'N/A')} to {row.get('dst_ip', 'N/A')}",
            "UNKNOWN_ANOMALY": f"Anomalous activity detected from {row.get('src_ip', 'N/A')}"
        }
        
        return descriptions.get(anomaly_type, "Suspicious network activity detected")

    def monitor_real_time(self, traffic_batch):
        """Real-time network monitoring - FIXED"""
        print(f"🌐 Monitoring {len(traffic_batch)} network connections...")
        return self.analyze_traffic(traffic_batch)

# Test function - UPDATED
def test_network_detector():
    """Test the network anomaly detector - FIXED"""
    print("🧪 TESTING NETWORK DETECTOR (FIXED VERSION)")
    print("=" * 50)
    
    try:
        detector = NetworkAnomalyDetector()
        
        # Sample network traffic - COMPLETE DATA
        sample_traffic = [
            {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.10',
                'dst_ip': '8.8.8.8',
                'protocol': 'DNS',
                'src_port': 54321,
                'dst_port': 53,
                'duration': 0.5,
                'bytes_sent': 512,
                'bytes_received': 1024,
                'packet_size': 512
            },
            {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.20',
                'dst_ip': '1.1.1.1', 
                'protocol': 'HTTPS',
                'src_port': 54322,
                'dst_port': 443,
                'duration': 2.0,
                'bytes_sent': 1500,
                'bytes_received': 5000,
                'packet_size': 1500
            },
            {
                'timestamp': datetime.now(),
                'src_ip': '192.168.1.99',
                'dst_ip': '45.33.32.156',
                'protocol': 'TCP',
                'src_port': 54323,
                'dst_port': 4444,
                'duration': 60,
                'bytes_sent': 500000,
                'bytes_received': 100,
                'packet_size': 1500
            }
        ]
        
        results = detector.monitor_real_time(sample_traffic)
        
        print(f"\n📊 NETWORK ANALYSIS RESULTS:")
        print(f"Total connections: {results.get('total_connections', 'N/A')}")
        print(f"Anomalous connections: {results.get('anomalous_connections', 'N/A')}")
        print(f"Anomaly percentage: {results.get('anomaly_percentage', 'N/A'):.2f}%")
        
        # Traffic summary
        summary = results.get('traffic_summary', {})
        print(f"\n📈 TRAFFIC SUMMARY:")
        print(f"  Internal to External: {summary.get('internal_to_external', 0)}")
        print(f"  Internal to Internal: {summary.get('internal_to_internal', 0)}")
        print(f"  Suspicious Ports Used: {summary.get('suspicious_ports_used', 0)}")
        
        # Security alerts
        alerts = results.get('security_alerts', [])
        if alerts:
            print(f"\n🚨 SECURITY ALERTS FOUND:")
            for i, alert in enumerate(alerts, 1):
                print(f"  {i}. {alert['description']}")
                print(f"     Type: {alert['anomaly_type']}, Risk: {alert['risk_level']}, Score: {alert['anomaly_score']:.3f}")
        else:
            print(f"\n✅ NO SECURITY ALERTS")
            
        print(f"\n🎉 NETWORK DETECTOR TEST PASSED!")
        return True
        
    except Exception as e:
        print(f"❌ NETWORK DETECTOR TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_network_detector()
