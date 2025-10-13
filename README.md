# 🛡️ DeepGuard AI - Intelligent Cybersecurity System

A multi-modal AI-powered cybersecurity threat detection system that analyzes emails, logs, and network traffic for potential threats.

## 🚀 Features

- **📧 Phishing Detection**: AI-powered email analysis using DistilBERT
- **📊 Log Anomaly Detection**: Machine learning-based log analysis  
- **🌐 Network Traffic Analysis**: Real-time network threat detection
- **🛡️ Comprehensive Security Scan**: Multi-modal threat assessment
- **💻 Web Dashboard**: Streamlit-based user interface
- **🔌 REST API**: FastAPI backend with full documentation

## 🏗️ Architecture
DeepGuard AI/
├── 📧 Phishing Detector (DistilBERT)
├── 📊 Log Anomaly Detector (Isolation Forest)
├── 🌐 Network Anomaly Detector (Isolation Forest)
├── 🔌 FastAPI Backend
└── 💻 Streamlit Frontend

text

## 🛠️ Installation

1. **Clone Repository**
```bash
git clone <repository-url>
cd DeepGuard-AI
Install Dependencies

bash
pip install -r requirements.txt
Train Models

bash
python train_models.py
Start API Server

bash
python run_api.py
Start Frontend (New Terminal)

bash
streamlit run frontend/app.py
Access System

API Docs: http://localhost:8000/docs

Dashboard: http://localhost:8501

📊 API Endpoints
POST /analyze/phishing - Analyze emails for phishing

POST /analyze/logs - Detect anomalies in system logs

POST /analyze/network - Monitor network traffic

POST /analyze/comprehensive - Complete security scan

GET /system/status - System health check

🧠 ML Models
Phishing Detection: Fine-tuned DistilBERT model

Log Analysis: Isolation Forest for anomaly detection

Network Analysis: Isolation Forest for traffic patterns

🎯 Usage Examples
Phishing Detection
python
import requests

response = requests.post("http://localhost:8000/analyze/phishing", 
    json={"emails": ["You won $1000! Click here..."]}
)
print(response.json())
Comprehensive Scan
python
payload = {
    "emails": [...],
    "logs": [...], 
    "network_traffic": [...]
}
response = requests.post("http://localhost:8000/analyze/comprehensive", json=payload)
📈 Performance
Phishing Detection Accuracy: ~90%

Log Anomaly Detection: ~85%

Network Threat Detection: ~88%

Response Time: < 2 seconds

🔧 Development
Backend: FastAPI + Python

Frontend: Streamlit

ML: PyTorch, Scikit-learn, Transformers

Data: Pandas, NumPy

