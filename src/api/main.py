from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn
from datetime import datetime
import logging
import sys
import os
from fastapi.responses import JSONResponse

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import our detectors
from src.detectors.phishing_detector import PhishingDetector
from src.detectors.log_detector import LogAnomalyDetector
from src.detectors.network_detector import NetworkAnomalyDetector

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="DeepGuard AI API",
    description="Intelligent Multi-Modal Cyber Threat Detection System",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global detector instances
phishing_detector = None
log_detector = None
network_detector = None

# Request models
class EmailRequest(BaseModel):
    emails: List[str]

class LogRequest(BaseModel):
    logs: List[Dict[str, Any]]

class NetworkRequest(BaseModel):
    traffic: List[Dict[str, Any]]

class ComprehensiveRequest(BaseModel):
    emails: Optional[List[str]] = None
    logs: Optional[List[Dict[str, Any]]] = None
    network_traffic: Optional[List[Dict[str, Any]]] = None

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    components: Dict[str, bool]

@app.on_event("startup")
async def startup_event():
    """Initialize detectors on startup"""
    global phishing_detector, log_detector, network_detector
    
    logger.info("🚀 Initializing DeepGuard AI Components...")
    
    try:
        # Initialize Phishing Detector
        logger.info("📧 Loading Phishing Detector...")
        phishing_detector = PhishingDetector()
        logger.info("✅ Phishing Detector initialized")
        
        # Initialize Log Anomaly Detector
        logger.info("📊 Loading Log Anomaly Detector...")
        log_detector = LogAnomalyDetector()
        logger.info("✅ Log Anomaly Detector initialized")
        
        # Initialize Network Anomaly Detector
        logger.info("🌐 Loading Network Anomaly Detector...")
        network_detector = NetworkAnomalyDetector()
        logger.info("✅ Network Anomaly Detector initialized")
        
        logger.info("🎉 All DeepGuard AI components initialized successfully!")
        
    except Exception as e:
        logger.error(f"❌ Error initializing components: {e}")
        # Don't raise exception, let the server start with partial functionality

@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint - System health check"""
    return HealthResponse(
        status="operational",
        timestamp=datetime.now().isoformat(),
        version="1.0.0",
        components={
            "phishing_detector": phishing_detector is not None,
            "log_detector": log_detector is not None,
            "network_detector": network_detector is not None
        }
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "DeepGuard AI API",
        "components": {
            "phishing_detector": "active" if phishing_detector else "inactive",
            "log_detector": "active" if log_detector else "inactive",
            "network_detector": "active" if network_detector else "inactive"
        }
    }

@app.post("/analyze/phishing")
async def analyze_phishing(request: EmailRequest):
    """
    Analyze emails for phishing attempts
    """
    if not phishing_detector:
        raise HTTPException(status_code=503, detail="Phishing detector not available")
    
    if not request.emails:
        raise HTTPException(status_code=400, detail="No emails provided")
    
    try:
        logger.info(f"Analyzing {len(request.emails)} emails for phishing...")
        
        results = phishing_detector.analyze_multiple_emails(request.emails)
        
        return {
            "analysis_type": "phishing_detection",
            "timestamp": datetime.now().isoformat(),
            "total_emails_analyzed": len(request.emails),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Phishing analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Phishing analysis failed: {str(e)}")

@app.post("/analyze/logs")
async def analyze_logs(request: LogRequest):
    """
    Analyze system logs for anomalies
    """
    if not log_detector:
        raise HTTPException(status_code=503, detail="Log detector not available")
    
    if not request.logs:
        raise HTTPException(status_code=400, detail="No logs provided")
    
    try:
        logger.info(f"Analyzing {len(request.logs)} log entries...")
        
        results = log_detector.analyze_real_time(request.logs)
        
        # Check if analysis returned an error
        if 'error' in results:
            logger.error(f"Log analysis returned error: {results['error']}")
            return {
                "analysis_type": "log_anomaly_detection",
                "timestamp": datetime.now().isoformat(),
                "total_logs_analyzed": len(request.logs),
                "results": results
            }
        
        return {
            "analysis_type": "log_anomaly_detection",
            "timestamp": datetime.now().isoformat(),
            "total_logs_analyzed": len(request.logs),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Log analysis error: {e}")
        # Return error in response instead of raising exception
        return JSONResponse(
            status_code=200,
            content={
                "analysis_type": "log_anomaly_detection",
                "timestamp": datetime.now().isoformat(),
                "total_logs_analyzed": len(request.logs),
                "results": {
                    "error": str(e),
                    "total_logs": 0,
                    "anomalies_detected": 0,
                    "anomaly_percentage": 0.0,
                    "high_risk_alerts": []
                }
            }
        )

@app.post("/analyze/network")
async def analyze_network(request: NetworkRequest):
    """
    Analyze network traffic for anomalies
    """
    if not network_detector:
        raise HTTPException(status_code=503, detail="Network detector not available")
    
    if not request.traffic:
        raise HTTPException(status_code=400, detail="No network traffic data provided")
    
    try:
        logger.info(f"Analyzing {len(request.traffic)} network connections...")
        
        results = network_detector.monitor_real_time(request.traffic)
        
        return {
            "analysis_type": "network_anomaly_detection",
            "timestamp": datetime.now().isoformat(),
            "total_connections_analyzed": len(request.traffic),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Network analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Network analysis failed: {str(e)}")

@app.post("/analyze/comprehensive")
async def comprehensive_analysis(request: ComprehensiveRequest):
    """
    Comprehensive multi-modal security analysis
    """
    results = {
        "analysis_type": "comprehensive_multi_modal",
        "timestamp": datetime.now().isoformat(),
        "components_analyzed": [],
        "results": {},
        "security_score": 100,
        "threats_detected": 0,
        "security_status": "SECURE"
    }
    
    threats_detected = 0
    
    # Phishing Analysis
    if request.emails and phishing_detector:
        try:
            logger.info(f"Comprehensive analysis - Phishing: {len(request.emails)} emails")
            phishing_results = phishing_detector.analyze_multiple_emails(request.emails)
            results["results"]["phishing"] = phishing_results
            results["components_analyzed"].append("phishing")
            
            # Update security score
            phishing_count = phishing_results['summary']['phishing_detected']
            threats_detected += phishing_count
            results["security_score"] -= phishing_count * 10
            
        except Exception as e:
            results["results"]["phishing"] = {"error": str(e)}
            logger.error(f"Phishing analysis in comprehensive failed: {e}")
    
    # Log Analysis
    if request.logs and log_detector:
        try:
            logger.info(f"Comprehensive analysis - Logs: {len(request.logs)} entries")
            log_results = log_detector.analyze_real_time(request.logs)
            results["results"]["logs"] = log_results
            results["components_analyzed"].append("logs")
            
            # Update security score only if no error
            if 'error' not in log_results:
                log_anomalies = log_results.get('anomalies_detected', 0)
                threats_detected += log_anomalies
                results["security_score"] -= log_anomalies * 5
            
        except Exception as e:
            results["results"]["logs"] = {"error": str(e)}
            logger.error(f"Log analysis in comprehensive failed: {e}")
    
    # Network Analysis
    if request.network_traffic and network_detector:
        try:
            logger.info(f"Comprehensive analysis - Network: {len(request.network_traffic)} connections")
            network_results = network_detector.monitor_real_time(request.network_traffic)
            results["results"]["network"] = network_results
            results["components_analyzed"].append("network")
            
            # Update security score
            network_anomalies = network_results.get('anomalous_connections', 0)
            threats_detected += network_anomalies
            results["security_score"] -= network_anomalies * 7
            
        except Exception as e:
            results["results"]["network"] = {"error": str(e)}
            logger.error(f"Network analysis in comprehensive failed: {e}")
    
    # Ensure security score doesn't go below 0
    results["security_score"] = max(0, results["security_score"])
    results["threats_detected"] = threats_detected
    
    # Determine overall security status
    if results["security_score"] >= 80:
        results["security_status"] = "SECURE"
    elif results["security_score"] >= 60:
        results["security_status"] = "MODERATE"
    else:
        results["security_status"] = "CRITICAL"
    
    return results

@app.get("/system/status")
async def system_status():
    """Get detailed system status"""
    return {
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "components": {
            "phishing_detector": {
                "status": "active" if phishing_detector else "inactive",
                "description": "AI-powered phishing email detection"
            },
            "log_analyzer": {
                "status": "active" if log_detector else "inactive", 
                "description": "Anomaly detection in system logs"
            },
            "network_analyzer": {
                "status": "active" if network_detector else "inactive",
                "description": "Network traffic anomaly detection"
            }
        }
    }

@app.get("/models/info")
async def models_info():
    """Get information about loaded ML models"""
    return {
        "phishing_model": {
            "type": "DistilBERT",
            "task": "Text Classification",
            "labels": ["legitimate", "phishing"],
            "status": "loaded" if phishing_detector else "not loaded"
        },
        "log_anomaly_model": {
            "type": "Isolation Forest", 
            "task": "Anomaly Detection",
            "status": "loaded" if log_detector else "not loaded"
        },
        "network_anomaly_model": {
            "type": "Isolation Forest",
            "task": "Anomaly Detection", 
            "status": "loaded" if network_detector else "not loaded"
        }
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_type": "HTTPException"}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global error handler: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error_type": "Exception"}
    )

# For direct execution
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0", 
        port=8000,
        reload=True,
        log_level="info"
        )
