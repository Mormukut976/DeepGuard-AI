import subprocess
import sys
import time
import webbrowser
import threading
import os
import requests
import signal
import psutil

class DeepGuardLauncher:
    def __init__(self):
        self.processes = []
        
    def run_command(self, cmd, description):
        """Run a command and handle errors"""
        print(f"🚀 {description}...")
        try:
            if "streamlit" in cmd or "python" in cmd:
                # Use shell=True for streamlit and python commands
                process = subprocess.Popen(cmd, shell=True)
            else:
                process = subprocess.Popen(cmd, shell=True)
            
            self.processes.append(process)
            return process
        except Exception as e:
            print(f"❌ Error starting {description}: {e}")
            return None

    def check_api_health(self):
        """Check if API is running"""
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            return response.status_code == 200
        except:
            return False

    def check_dashboard_health(self):
        """Check if dashboard is running"""
        try:
            response = requests.get("http://localhost:8501", timeout=5)
            return response.status_code == 200
        except:
            return False

    def kill_existing_services(self):
        """Kill any existing services on same ports"""
        try:
            # Kill processes using port 8000
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    connections = proc.connections()
                    for conn in connections:
                        if conn.laddr.port == 8000 or conn.laddr.port == 8501:
                            print(f"🛑 Killing existing process on port {conn.laddr.port}: {proc.pid}")
                            proc.kill()
                except:
                    pass
            time.sleep(2)
        except Exception as e:
            print(f"⚠️ Error killing existing services: {e}")

    def start_services(self):
        """Start all DeepGuard-AI services"""
        print("🎯 DEEP GUARD AI - COMPLETE SYSTEM START")
        print("=" * 60)
        
        # Kill existing services first
        self.kill_existing_services()
        
        print("Starting all services...")
        print("This will start:")
        print("✅ API Server (http://localhost:8000)")
        print("✅ Dashboard (http://localhost:8501)") 
        print("✅ Real-time Network Monitoring")
        print("✅ Auto-open browser tabs")
        print("\nPress Ctrl+C to stop all services")

        # Start API Server
        api_success = self.run_command(
            "python run_api.py", 
            "Starting API Server"
        )
        
        if not api_success:
            print("❌ Failed to start API Server")
            return False

        # Wait for API to start
        print("⏳ Waiting for API server to start...")
        for i in range(30):
            if self.check_api_health():
                print("✅ API Server is ready!")
                break
            time.sleep(1)
            if i % 5 == 0:
                print(f"   Still waiting... ({i+1}/30 seconds)")
        else:
            print("❌ API Server didn't start in time")
            return False

        # Start Dashboard
        dashboard_success = self.run_command(
            "streamlit run dashboard.py --server.port 8501 --server.address 0.0.0.0", 
            "Starting Dashboard"
        )
        
        if not dashboard_success:
            print("❌ Failed to start Dashboard")
            return False

        # Wait for dashboard to start
        print("⏳ Waiting for dashboard to start...")
        for i in range(20):
            if self.check_dashboard_health():
                print("✅ Dashboard is ready!")
                break
            time.sleep(1)
        else:
            print("⚠️ Dashboard taking longer to start...")

        # Open browser tabs
        print("📖 Opening browser tabs...")
        time.sleep(3)
        
        webbrowser.open("http://localhost:8501")       # Dashboard
        time.sleep(2)
        webbrowser.open("http://localhost:8000/docs")  # API Docs
        
        return True

    def show_status(self):
        """Show current system status"""
        print("\n" + "=" * 60)
        print("🎉 DEEP GUARD AI - SYSTEM STATUS")
        print("=" * 60)
        print("📍 Access Points:")
        print("   • 🌐 Web Dashboard: http://localhost:8501")
        print("   • 📖 API Documentation: http://localhost:8000/docs")
        print("   • 💚 Health Check: http://localhost:8000/health")
        
        print("\n🔧 Services Status:")
        api_status = "✅ Running" if self.check_api_health() else "❌ Stopped"
        dashboard_status = "✅ Running" if self.check_dashboard_health() else "❌ Stopped"
        
        print(f"   • API Server (Port 8000): {api_status}")
        print(f"   • Dashboard (Port 8501): {dashboard_status}")
        
        print("\n🛡️ Features Available:")
        print("   ✅ Real-time Network Scanning")
        print("   ✅ Phishing Email Detection") 
        print("   ✅ Log Analysis")
        print("   ✅ Threat Intelligence")
        
        print("\n🛑 To stop: Press Ctrl+C in THIS terminal")
        print("=" * 60)

    def stop_services(self):
        """Stop all services"""
        print("\n🛑 Stopping all DeepGuard-AI services...")
        
        for process in self.processes:
            try:
                # Kill process and its children
                parent = psutil.Process(process.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except:
                pass
        
        # Additional cleanup - kill any remaining processes
        try:
            os.system("pkill -f 'python run_api.py'")
            os.system("pkill -f 'streamlit run dashboard.py'")
            os.system("pkill -f 'uvicorn'")
        except:
            pass
            
        print("✅ All services stopped successfully!")
        print("👋 Thank you for using DeepGuard-AI!")

    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.stop_services()
        sys.exit(0)

def main():
    launcher = DeepGuardLauncher()
    
    # Setup signal handler for Ctrl+C
    signal.signal(signal.SIGINT, launcher.signal_handler)
    
    try:
        # Start all services
        success = launcher.start_services()
        
        if success:
            # Show status
            launcher.show_status()
            
            # Keep the script running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                launcher.stop_services()
        else:
            print("❌ Failed to start some services. Check the logs above.")
            launcher.stop_services()
            
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        launcher.stop_services()

if __name__ == "__main__":
    main()
