import uvicorn
import os
import sys
from dotenv import load_dotenv

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

load_dotenv()

def main():
    print("🚀 STARTING DEEP GUARD AI API SERVER")
    print("=" * 60)
    print("📧 Loading Phishing Detector...")
    print("📊 Loading Log Analyzer...")
    print("🌐 Loading Network Analyzer...")
    print("⏳ Please wait while models are loading...")
    
    try:
        uvicorn.run(
            "src.api.main:app",
            host=os.getenv("API_HOST", "0.0.0.0"),
            port=int(os.getenv("API_PORT", 8000)),
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

if __name__ == "__main__":
    main()
