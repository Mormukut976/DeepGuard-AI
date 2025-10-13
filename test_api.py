import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"

def wait_for_server(max_retries=10, delay=3):
    """Wait for server to start"""
    print("⏳ Waiting for API server to start...")
    for i in range(max_retries):
        try:
            response = requests.get(f"{BASE_URL}/", timeout=5)
            if response.status_code == 200:
                print("✅ API server is ready!")
                return True
        except:
            print(f"Attempt {i+1}/{max_retries}: Server not ready yet...")
            time.sleep(delay)
    print("❌ Server did not start in time")
    return False

def test_health():
    print("\n🔧 Testing API Health...")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print("✅ API is healthy!")
            print(f"Status: {data['status']}")
            print(f"Version: {data['version']}")
            print("Components Status:")
            for component, status in data['components'].items():
                status_icon = "✅" if status else "❌"
                print(f"  {status_icon} {component}: {'Ready' if status else 'Not Ready'}")
            return True
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Could not connect to API: {e}")
        return False

def test_phishing_endpoint():
    print("\n📧 Testing Phishing Detection...")
    
    test_emails = [
        "Congratulations! You won $1000. Click here to claim your prize",
        "Hi John, meeting scheduled for tomorrow at 3 PM. Best regards",
        "URGENT: Your bank account will be suspended. Verify now!",
        "Your package has been delivered. Track your order here",
        "Free iPhone! Click now to claim your gift"
    ]
    
    payload = {"emails": test_emails}
    
    try:
        response = requests.post(f"{BASE_URL}/analyze/phishing", json=payload, timeout=30)
        if response.status_code == 200:
            results = response.json()
            summary = results['results']['summary']
            print("✅ Phishing detection working!")
            print(f"📊 Results:")
            print(f"  Total emails: {summary['total_emails']}")
            print(f"  Phishing detected: {summary['phishing_detected']}")
            print(f"  Legitimate: {summary['legitimate_count']}")
            print(f"  Phishing percentage: {summary['phishing_percentage']:.1f}%")
            
            # Show individual results
            print(f"\n📧 Email Analysis:")
            for i, result in enumerate(results['results']['detailed_results'][:3]):  # Show first 3
                status = "🚨 PHISHING" if result['is_phishing'] else "✅ LEGITIMATE"
                print(f"  Email {i+1}: {status} (Confidence: {result['confidence']:.2%})")
            
            return True
        else:
            print(f"❌ Phishing endpoint failed: {response.status_code}")
            print(f"Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Phishing test error: {e}")
        return False

def test_log_endpoint():
    print("\n📊 Testing Log Analysis...")
    
    test_logs = [
        {
            "timestamp": datetime.now().isoformat(),
            "log_type": "AUTH_SUCCESS",
            "user": "user1",
            "source_ip": "192.168.1.10",
            "severity": "LOW"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "log_type": "AUTH_FAILED",
            "user": "admin",
            "source_ip": "192.168.1.99",
            "severity": "HIGH"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "log_type": "FILE_ACCESS",
            "user": "guest",
            "source_ip": "192.168.1.77",
            "severity": "HIGH"
        }
    ]
    
    payload = {"logs": test_logs}
    
    try:
        response = requests.post(f"{BASE_URL}/analyze/logs", json=payload, timeout=30)
        if response.status_code == 200:
            results = response.json()
            print("✅ Log analysis working!")
            print(f"📊 Results:")
            print(f"  Total logs: {results['results']['total_logs']}")
            print(f"  Anomalies detected: {results['results']['anomalies_detected']}")
            print(f"  Anomaly percentage: {results['results']['anomaly_percentage']:.1f}%")
            
            # Show alerts if any
            alerts = results['results']['high_risk_alerts']
            if alerts:
                print(f"🚨 High Risk Alerts:")
                for alert in alerts:
                    print(f"  • {alert['message']} (Risk: {alert['risk_level']})")
            else:
                print("✅ No high risk alerts")
            
            return True
        else:
            print(f"❌ Log endpoint failed: {response.status_code}")
            print(f"Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Log test error: {e}")
        return False

def test_network_endpoint():
    print("\n🌐 Testing Network Analysis...")
    
    test_traffic = [
        {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "protocol": "DNS",
            "src_port": 54321,
            "dst_port": 53,
            "duration": 0.5,
            "bytes_sent": 512,
            "bytes_received": 1024,
            "packet_size": 512
        },
        {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "192.168.1.20",
            "dst_ip": "1.1.1.1",
            "protocol": "HTTPS",
            "src_port": 54322,
            "dst_port": 443,
            "duration": 2.0,
            "bytes_sent": 1500,
            "bytes_received": 5000,
            "packet_size": 1500
        },
        {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "192.168.1.99",
            "dst_ip": "45.33.32.156",
            "protocol": "TCP",
            "src_port": 54323,
            "dst_port": 4444,
            "duration": 60,
            "bytes_sent": 500000,
            "bytes_received": 100,
            "packet_size": 1500
        }
    ]
    
    payload = {"traffic": test_traffic}
    
    try:
        response = requests.post(f"{BASE_URL}/analyze/network", json=payload, timeout=30)
        if response.status_code == 200:
            results = response.json()
            print("✅ Network analysis working!")
            print(f"📊 Results:")
            print(f"  Total connections: {results['results']['total_connections']}")
            print(f"  Anomalous connections: {results['results']['anomalous_connections']}")
            print(f"  Anomaly percentage: {results['results']['anomaly_percentage']:.1f}%")
            
            # Show traffic summary
            summary = results['results']['traffic_summary']
            print(f"📈 Traffic Summary:")
            print(f"  Internal to External: {summary['internal_to_external']}")
            print(f"  Internal to Internal: {summary['internal_to_internal']}")
            print(f"  Suspicious Ports: {summary['suspicious_ports_used']}")
            
            # Show security alerts
            alerts = results['results']['security_alerts']
            if alerts:
                print(f"🚨 Security Alerts:")
                for alert in alerts:
                    print(f"  • {alert['description']}")
                    print(f"    Type: {alert['anomaly_type']}, Risk: {alert['risk_level']}")
            else:
                print("✅ No security alerts")
            
            return True
        else:
            print(f"❌ Network endpoint failed: {response.status_code}")
            print(f"Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Network test error: {e}")
        return False

def test_comprehensive_endpoint():
    print("\n🛡️ Testing Comprehensive Analysis...")
    
    payload = {
        "emails": [
            "Congratulations! You won $1000. Click here to claim",
            "Meeting reminder: Tomorrow at 2 PM",
            "URGENT: Verify your account at http://secure-bank.com"
        ],
        "logs": [
            {
                "timestamp": datetime.now().isoformat(),
                "log_type": "AUTH_FAILED",
                "user": "admin",
                "source_ip": "192.168.1.99",
                "severity": "HIGH"
            }
        ],
        "network_traffic": [
            {
                "timestamp": datetime.now().isoformat(),
                "src_ip": "192.168.1.99",
                "dst_ip": "45.33.32.156",
                "protocol": "TCP",
                "src_port": 54323,
                "dst_port": 4444,
                "duration": 60,
                "bytes_sent": 500000,
                "bytes_received": 100,
                "packet_size": 1500
            }
        ]
    }
    
    try:
        response = requests.post(f"{BASE_URL}/analyze/comprehensive", json=payload, timeout=45)
        if response.status_code == 200:
            results = response.json()
            print("✅ Comprehensive analysis working!")
            print(f"📊 Results:")
            print(f"  Components analyzed: {', '.join(results['components_analyzed'])}")
            print(f"  Security Score: {results['security_score']}/100")
            print(f"  Security Status: {results['security_status']}")
            print(f"  Threats Detected: {results['threats_detected']}")
            
            return True
        else:
            print(f"❌ Comprehensive endpoint failed: {response.status_code}")
            print(f"Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Comprehensive test error: {e}")
        return False

def test_system_status():
    print("\n📊 Testing System Status...")
    try:
        response = requests.get(f"{BASE_URL}/system/status", timeout=10)
        if response.status_code == 200:
            status = response.json()
            print("✅ System status working!")
            print("🔧 Component Details:")
            for component, info in status['components'].items():
                status_icon = "✅" if info['status'] == 'active' else "❌"
                print(f"  {status_icon} {component}: {info['description']}")
            return True
        else:
            print(f"❌ Status endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Status test error: {e}")
        return False

def test_models_info():
    print("\n🤖 Testing Models Info...")
    try:
        response = requests.get(f"{BASE_URL}/models/info", timeout=10)
        if response.status_code == 200:
            models = response.json()
            print("✅ Models info working!")
            print("🧠 Loaded Models:")
            for model_name, info in models.items():
                status = "✅ Loaded" if info['status'] == 'loaded' else "❌ Not Loaded"
                print(f"  {model_name}: {info['type']} - {status}")
            return True
        else:
            print(f"❌ Models info endpoint failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Models info test error: {e}")
        return False

def main():
    print("🚀 DEEP GUARD AI - COMPLETE API TEST SUITE")
    print("=" * 70)
    
    # First wait for server
    if not wait_for_server():
        print("\n❌ Cannot proceed with tests. Please start the API server first.")
        print("💡 Run: python run_api.py")
        return
    
    # Run all tests
    tests = [
        test_health,
        test_phishing_endpoint,
        test_log_endpoint, 
        test_network_endpoint,
        test_comprehensive_endpoint,
        test_system_status,
        test_models_info
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"❌ Test crashed: {e}")
            results.append(False)
        print("-" * 50)
    
    # Print summary
    print("\n" + "=" * 70)
    print("📋 FINAL TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    test_names = [
        "API Health",
        "Phishing Detection", 
        "Log Analysis",
        "Network Analysis",
        "Comprehensive Analysis",
        "System Status",
        "Models Info"
    ]
    
    for i, (test_name, result) in enumerate(zip(test_names, results)):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! DEEP GUARD AI IS FULLY OPERATIONAL! 🎉")
        print("\n📍 Access Points:")
        print("  • API Documentation: http://localhost:8000/docs")
        print("  • API Base URL: http://localhost:8000/")
        print("  • Frontend: http://localhost:8501")
        print("\n🚀 Your cybersecurity system is ready for production!")
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Check the logs above.")

if __name__ == "__main__":
    main()
