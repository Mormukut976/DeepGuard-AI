import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def test_all_detectors():
    print("🧪 TESTING ALL DEEP GUARD AI DETECTORS")
    print("=" * 50)
    
    try:
        # Test Phishing Detector
        print("\n1. 📧 Testing Phishing Detector...")
        from src.detectors.phishing_detector import test_phishing_detector
        test_phishing_detector()
        
        # Test Log Detector
        print("\n2. 📊 Testing Log Anomaly Detector...")
        from src.detectors.log_detector import test_log_detector
        test_log_detector()
        
        # Test Network Detector
        print("\n3. 🌐 Testing Network Anomaly Detector...")
        from src.detectors.network_detector import test_network_detector
        test_network_detector()
        
        print("\n🎉 ALL DETECTORS WORKING PERFECTLY!")
        print("🚀 Now you can run the API server!")
        
    except Exception as e:
        print(f"❌ Testing failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_all_detectors()
