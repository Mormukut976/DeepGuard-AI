import sys
import os
import time

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def main():
    print("🚀 DEEP GUARD AI - MODEL TRAINING")
    print("=" * 50)
    
    try:
        # 1. Phishing Model
        print("\n📧 1. Training Phishing Detection Model...")
        from src.models.phishing_model import train_phishing_model
        train_phishing_model()
        time.sleep(2)
        
        # 2. Log Model
        print("\n📊 2. Training Log Anomaly Detection Model...")
        from src.models.log_model import train_log_model
        train_log_model()
        time.sleep(2)
        
        # 3. Network Model
        print("\n🌐 3. Training Network Anomaly Detection Model...")
        from src.models.network_model import train_network_model
        train_network_model()
        
        print("\n" + "=" * 50)
        print("🎉 ALL MODELS TRAINED SUCCESSFULLY!")
        print("=" * 50)
        print("📁 Generated Models:")
        print("  • ./phishing_model/ - Phishing email detector")
        print("  • ./log_anomaly_detector.joblib - Log anomaly detector") 
        print("  • ./network_anomaly_detector.joblib - Network anomaly detector")
        print("\n🚀 Next step: python run_api.py")
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
