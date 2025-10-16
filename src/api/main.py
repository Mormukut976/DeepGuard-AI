from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import threading
import time
from datetime import datetime
from src.detectors.phishing_detector import PhishingDetector
from src.detectors.log_detector import LogDetector
from src.detectors.network_detector import NetworkDetector
from src.detectors.threat_intel import ThreatIntel
from src.detectors.network_scanner import RealTimeNetworkScanner

# FastAPI app initialization
app = FastAPI(
    title="DeepGuard-AI API",
    description="AI-powered Real-time Cybersecurity Threat Detection System",
    version="2.0.0"
)

# Initialize detectors
phishing_detector = PhishingDetector()
log_detector = LogDetector()
network_detector = NetworkDetector()
threat_intel = ThreatIntel()

# Real-time Network Scanner
network_scanner = RealTimeNetworkScanner()
scanning_status = {"is_scanning": False, "interface": None}

# Request Models
class PhishingRequest(BaseModel):
    email_content: str
    url: str = None

class LogRequest(BaseModel):
    log_data: str

class NetworkRequest(BaseModel):
    interface: str = "eth0"

# Real-time scanning thread
scan_thread = None

def background_network_scan(interface: str):
    """Background me network scanning run karega"""
    global scanning_status
    try:
        network_scanner.start_realtime_scan(interface)
    except Exception as e:
        scanning_status["is_scanning"] = False
        scanning_status["error"] = str(e)

# Health Check
@app.get("/")
async def root():
    return {
        "message": "🛡️ DeepGuard-AI API Server",
        "status": "running",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "phishing_detector": "active",
            "log_detector": "active", 
            "network_detector": "active",
            "threat_intel": "active",
            "real_time_scanner": "ready"
        }
    }

# Phishing Detection
@app.post("/detect/phishing")
async def detect_phishing(request: PhishingRequest):
    try:
        result = phishing_detector.analyze_email(request.email_content)
        return {
            "is_phishing": result["is_phishing"],
            "confidence": result["confidence"],
            "threat_level": result["threat_level"],
            "details": result["details"],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Phishing detection error: {str(e)}")

# Log Analysis
@app.post("/analyze/logs")
async def analyze_logs(request: LogRequest):
    try:
        result = log_detector.analyze_logs(request.log_data)
        return {
            "anomalies_detected": result["anomalies_detected"],
            "anomaly_count": result["anomaly_count"],
            "threat_level": result["threat_level"],
            "suspicious_entries": result["suspicious_entries"],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log analysis error: {str(e)}")

# REAL-TIME NETWORK SCANNING ENDPOINTS

@app.post("/network/start_scan")
async def start_network_scan(request: NetworkRequest):
    global scanning_status, scan_thread
    
    if scanning_status["is_scanning"]:
        raise HTTPException(status_code=400, detail="Scanning already in progress")
    
    try:
        # Background thread me scanning start karein
        scan_thread = threading.Thread(target=background_network_scan, args=(request.interface,))
        scan_thread.daemon = True
        scan_thread.start()
        
        scanning_status = {
            "is_scanning": True,
            "interface": request.interface,
            "started_at": datetime.now().isoformat()
        }
        
        return {
            "status": "scanning_started",
            "interface": request.interface,
            "message": f"Real-time network scanning started on {request.interface}",
            "started_at": scanning_status["started_at"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scanning: {str(e)}")

@app.post("/network/stop_scan")
async def stop_network_scan():
    global scanning_status
    
    if not scanning_status["is_scanning"]:
        raise HTTPException(status_code=400, detail="No active scanning session")
    
    try:
        network_scanner.stop_scan()
        scanning_status = {
            "is_scanning": False,
            "interface": None,
            "stopped_at": datetime.now().isoformat()
        }
        
        return {
            "status": "scanning_stopped",
            "message": "Real-time network scanning stopped",
            "stopped_at": scanning_status["stopped_at"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop scanning: {str(e)}")

@app.get("/network/status")
async def get_network_status():
    """Get network scanning status"""
    try:
        threats = network_scanner.get_threats()
        
        # Active threats (last 5 minutes)
        current_time = time.time()
        active_threats = []
        
        for threat in threats:
            # Agar timestamp ISO format me hai
            if isinstance(threat.get('timestamp'), str) and 'T' in threat['timestamp']:
                try:
                    from datetime import datetime
                    threat_time = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00')).timestamp()
                    if current_time - threat_time < 300:  # 5 minutes
                        active_threats.append(threat)
                except:
                    active_threats.append(threat)
            else:
                # Agar numeric timestamp hai
                threat_time = threat.get('timestamp', 0)
                if current_time - threat_time < 300:  # 5 minutes
                    active_threats.append(threat)
        
        return {
            "scanning_status": scanning_status,
            "threats_detected": len(threats),
            "active_threats": active_threats,
            "total_threats": len(threats)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Network status error: {str(e)}")

@app.get("/network/threats")
async def get_network_threats():
    try:
        threats = network_scanner.get_threats()
        return {
            "threats": threats[-50:],  # Last 50 threats
            "total_threats": len(threats),
            "high_severity_threats": len([t for t in threats if t.get('severity') == 'high']),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get threats: {str(e)}")

@app.get("/network/interfaces")
async def get_network_interfaces():
    try:
        interfaces = network_scanner.get_network_interfaces()
        return {
            "available_interfaces": interfaces,
            "default_interface": interfaces[0] if interfaces else None,
            "total_interfaces": len(interfaces)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get interfaces: {str(e)}")

# System Statistics - YE ADD KAREIN
@app.get("/system/stats")
async def get_system_stats():
    """Get system statistics"""
    try:
        return {
            "uptime": time.time(),
            "total_phishing_checks": phishing_detector.get_stats().get('total_checks', 0),
            "total_log_analyses": log_detector.get_stats().get('total_analyses', 0),
            "network_threats_detected": len(network_scanner.get_threats()),
            "real_time_scanning": scanning_status["is_scanning"],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"System stats error: {str(e)}")

# Network Packet Analysis
@app.get("/network/packet_stats")
async def get_packet_stats():
    try:
        stats = network_scanner.get_packet_statistics()
        return {
            "packet_statistics": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get packet stats: {str(e)}")

# Threat Intelligence
@app.get("/threat/intel/{ip_address}")
async def get_threat_intel(ip_address: str):
    try:
        intel_data = threat_intel.check_ip_reputation(ip_address)
        return {
            "ip_address": ip_address,
            "threat_intel": intel_data,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intelligence error: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
