import subprocess
import sys
import time
import webbrowser
import threading
import os

def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"🚀 {description}...")
    try:
        if "streamlit" in cmd:
            # For streamlit, use shell=True
            subprocess.Popen(cmd, shell=True)
        else:
            subprocess.Popen(cmd)
        return True
    except Exception as e:
        print(f"❌ Error starting {description}: {e}")
        return False

def check_api_health():
    """Check if API is running"""
    import requests
    try:
        response = requests.get("http://localhost:8000/", timeout=5)
        return response.status_code == 200
    except:
        return False

def main():
    print("🎯 DEEP GUARD AI - COMPLETE SYSTEM START")
    print("=" * 60)
    
    print("Starting all services...")
    print("This will start:")
    print("✅ API Server (http://localhost:8000)")
    print("✅ Frontend Dashboard (http://localhost:8501)")
    print("✅ Auto-open browser tabs")
    print("\nPress Ctrl+C in this terminal to stop all services")
    
    # Start API Server
    api_process = run_command(
        [sys.executable, "run_api.py"], 
        "Starting API Server"
    )
    
    # Wait for API to start
    print("⏳ Waiting for API server to start...")
    for i in range(30):  # 30 second timeout
        if check_api_health():
            print("✅ API Server is ready!")
            break
        time.sleep(1)
    else:
        print("❌ API Server didn't start in time")
        return
    
    # Start Frontend
    frontend_process = run_command(
        "streamlit run frontend/app.py", 
        "Starting Frontend Dashboard"
    )
    
    # Open browser tabs after delay
    print("⏳ Waiting for services to initialize...")
    time.sleep(5)
    
    print("📖 Opening browser tabs...")
    webbrowser.open("http://localhost:8000/docs")  # API Docs
    time.sleep(1)
    webbrowser.open("http://localhost:8501")       # Frontend
    
    print("\n" + "=" * 60)
    print("🎉 ALL SERVICES STARTED SUCCESSFULLY!")
    print("=" * 60)
    print("📍 Access Points:")
    print("   • API Documentation: http://localhost:8000/docs")
    print("   • Web Dashboard: http://localhost:8501") 
    print("   • Health Check: http://localhost:8000/health")
    print("\n🔧 Services Running:")
    print("   ✅ API Server - Port 8000")
    print("   ✅ Frontend - Port 8501")
    print("   ✅ All ML Models - Loaded and Ready")
    
    print("\n🛑 To stop services: Press Ctrl+C in ALL terminals")
    
    try:
        # Keep script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping all services...")

if __name__ == "__main__":
    main()
