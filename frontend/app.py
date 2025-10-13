import streamlit as st
import requests
import json
import pandas as pd
from datetime import datetime

# Page config
st.set_page_config(
    page_title="DeepGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Base URL
API_BASE = "http://localhost:8000"

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .success-box {
        background-color: #d4edda;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #c3e6cb;
    }
    .warning-box {
        background-color: #fff3cd;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #ffeaa7;
    }
    .danger-box {
        background-color: #f8d7da;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #f5c6cb;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1.5rem;
        border-radius: 0.5rem;
        border: 1px solid #dee2e6;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

def check_api_health():
    """API health check"""
    try:
        response = requests.get(f"{API_BASE}/", timeout=5)
        return response.status_code == 200
    except:
        return False

def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ DeepGuard AI</h1>', unsafe_allow_html=True)
    st.markdown("### Intelligent Cyber Threat Detection System")
    
    # Sidebar - Navigation
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.selectbox(
        "Choose Analysis Mode",
        ["Dashboard", "Phishing Detection", "Log Analysis", "Network Analysis", "Comprehensive Scan"]
    )
    
    # API Health Check
    if not check_api_health():
        st.error("❌ API Server is not running. Please start the API server first.")
        st.info("Run: `python run_api.py` in your terminal")
        st.stop()
    
    st.sidebar.success("✅ API Connected")
    
    # Show selected page
    if app_mode == "Dashboard":
        show_dashboard()
    elif app_mode == "Phishing Detection":
        show_phishing_detection()
    elif app_mode == "Log Analysis":
        show_log_analysis()
    elif app_mode == "Network Analysis":
        show_network_analysis()
    elif app_mode == "Comprehensive Scan":
        show_comprehensive_scan()

def show_dashboard():
    st.header("📊 System Dashboard")
    
    # System Status
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Phishing Detector", "✅ Active", "Ready")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Log Analyzer", "✅ Active", "Ready")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Network Monitor", "✅ Active", "Ready")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("API Status", "✅ Online", "Port 8000")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Quick Actions
    st.subheader("🚀 Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("📧 Test Phishing", use_container_width=True):
            st.session_state.current_page = "Phishing Detection"
            st.rerun()
    
    with col2:
        if st.button("📊 Analyze Logs", use_container_width=True):
            st.session_state.current_page = "Log Analysis"
            st.rerun()
    
    with col3:
        if st.button("🌐 Monitor Network", use_container_width=True):
            st.session_state.current_page = "Network Analysis"
            st.rerun()
    
    with col4:
        if st.button("🛡️ Full Scan", use_container_width=True):
            st.session_state.current_page = "Comprehensive Scan"
            st.rerun()
    
    # Recent Activity
    st.subheader("📈 System Information")
    
    try:
        # Get system status
        response = requests.get(f"{API_BASE}/system/status", timeout=5)
        if response.status_code == 200:
            status = response.json()
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.info("🔧 Component Status")
                for component, info in status['components'].items():
                    st.write(f"**{component.replace('_', ' ').title()}**: {info['status']}")
            
            with col2:
                st.info("🤖 Loaded Models")
                models_response = requests.get(f"{API_BASE}/models/info", timeout=5)
                if models_response.status_code == 200:
                    models = models_response.json()
                    for model_name, info in models.items():
                        status_icon = "✅" if info['status'] == 'loaded' else '❌'
                        st.write(f"{status_icon} **{model_name}**: {info['type']}")
    except Exception as e:
        st.warning(f"Could not fetch system status: {e}")

def show_phishing_detection():
    st.header("📧 Phishing Email Detection")
    
    st.info("Analyze emails for potential phishing attempts using AI")
    
    # Input methods
    input_method = st.radio(
        "Choose input method:",
        ["Single Email", "Multiple Emails"],
        horizontal=True
    )
    
    if input_method == "Single Email":
        email_text = st.text_area("Enter email text:", height=150, 
                                 placeholder="Paste email content here...")
        
        if st.button("🔍 Analyze Email", type="primary") and email_text:
            with st.spinner("Analyzing email for phishing..."):
                try:
                    response = requests.post(f"{API_BASE}/analyze/phishing", 
                                           json={"emails": [email_text]},
                                           timeout=30)
                    
                    if response.status_code == 200:
                        results = response.json()
                        result = results['results']['detailed_results'][0]
                        
                        # Display results
                        st.subheader("📊 Analysis Results")
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            if result['is_phishing']:
                                st.error(f"## 🚨 PHISHING DETECTED")
                            else:
                                st.success(f"## ✅ LEGITIMATE EMAIL")
                        
                        with col2:
                            st.metric("Confidence", f"{result['confidence']:.2%}")
                            st.metric("Risk Level", result['risk_level'])
                        
                        # Progress bar
                        st.progress(result['phishing_probability'])
                        st.caption(f"Phishing Probability: {result['phishing_probability']:.2%}")
                        
                    else:
                        st.error(f"Analysis failed: {response.text}")
                        
                except Exception as e:
                    st.error(f"Error analyzing email: {e}")
    
    else:  # Multiple Emails
        emails_input = st.text_area(
            "Enter emails (one per line):", 
            height=200,
            placeholder="Enter each email on a new line...\n\nExample:\nCongratulations! You won $1000\nMeeting reminder for tomorrow"
        )
        
        if st.button("🔍 Analyze All Emails", type="primary") and emails_input:
            emails = [email.strip() for email in emails_input.split('\n') if email.strip()]
            
            with st.spinner(f"Analyzing {len(emails)} emails..."):
                try:
                    response = requests.post(f"{API_BASE}/analyze/phishing", 
                                           json={"emails": emails},
                                           timeout=30)
                    
                    if response.status_code == 200:
                        results = response.json()
                        summary = results['results']['summary']
                        
                        # Summary
                        st.subheader("📈 Summary")
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total Emails", summary['total_emails'])
                        with col2:
                            st.metric("Phishing Detected", summary['phishing_detected'])
                        with col3:
                            st.metric("Legitimate", summary['legitimate_count'])
                        
                        # Detailed results
                        st.subheader("📋 Detailed Results")
                        for i, result in enumerate(results['results']['detailed_results']):
                            with st.expander(f"Email {i+1}: {result['email_preview']}", expanded=i<3):
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    if result['is_phishing']:
                                        st.error("🚨 PHISHING")
                                    else:
                                        st.success("✅ LEGITIMATE")
                                with col2:
                                    st.metric("Score", f"{result['phishing_probability']:.2%}")
                                
                                st.write(f"**Risk Level:** {result['risk_level']}")
                                st.write(f"**Confidence:** {result['confidence']:.2%}")
                                
                    else:
                        st.error(f"Analysis failed: {response.text}")
                        
                except Exception as e:
                    st.error(f"Error analyzing emails: {e}")

def show_log_analysis():
    st.header("📊 Log Anomaly Detection")
    
    st.info("Analyze system logs for suspicious activities and anomalies")
    
    # Sample logs
    sample_logs = [
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
    
    log_input = st.text_area(
        "Enter log entries (JSON format):",
        height=300,
        value=json.dumps(sample_logs, indent=2)
    )
    
    if st.button("🔍 Analyze Logs", type="primary") and log_input:
        try:
            logs = json.loads(log_input)
            
            with st.spinner("Analyzing logs for anomalies..."):
                response = requests.post(f"{API_BASE}/analyze/logs", 
                                       json={"logs": logs},
                                       timeout=30)
                
                if response.status_code == 200:
                    results = response.json()['results']
                    
                    # Check for errors
                    if 'error' in results:
                        st.error(f"Analysis error: {results['error']}")
                        return
                    
                    # Summary
                    st.subheader("📈 Analysis Summary")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Logs", results['total_logs'])
                    with col2:
                        st.metric("Anomalies", results['anomalies_detected'])
                    with col3:
                        st.metric("Anomaly %", f"{results['anomaly_percentage']:.1f}%")
                    
                    # Alerts
                    if results['high_risk_alerts']:
                        st.subheader("🚨 High Risk Alerts")
                        for alert in results['high_risk_alerts']:
                            with st.container():
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    st.write(f"**{alert['message']}**")
                                    st.write(f"Timestamp: {alert['timestamp']}")
                                with col2:
                                    st.metric("Risk", alert['risk_level'])
                                    st.metric("Score", f"{alert['anomaly_score']:.3f}")
                                st.divider()
                    else:
                        st.success("✅ No high risk alerts detected")
                        
                else:
                    st.error(f"Analysis failed: {response.text}")
                    
        except json.JSONDecodeError:
            st.error("❌ Invalid JSON format. Please check your input.")
        except Exception as e:
            st.error(f"Error analyzing logs: {e}")

def show_network_analysis():
    st.header("🌐 Network Traffic Analysis")
    
    st.info("Monitor network traffic for suspicious connections and anomalies")
    
    # Sample network traffic - FIXED SYNTAX
    sample_traffic = [
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
    
    traffic_input = st.text_area(
        "Enter network traffic data (JSON format):",
        height=300,
        value=json.dumps(sample_traffic, indent=2)
    )
    
    if st.button("🔍 Analyze Network Traffic", type="primary") and traffic_input:
        try:
            traffic = json.loads(traffic_input)
            
            with st.spinner("Analyzing network traffic..."):
                response = requests.post(f"{API_BASE}/analyze/network", 
                                       json={"traffic": traffic},
                                       timeout=30)
                
                if response.status_code == 200:
                    results = response.json()['results']
                    
                    # Summary
                    st.subheader("📈 Traffic Summary")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Connections", results['total_connections'])
                    with col2:
                        st.metric("Anomalous", results['anomalous_connections'])
                    with col3:
                        st.metric("Anomaly %", f"{results['anomaly_percentage']:.1f}%")
                    
                    # Traffic details
                    st.subheader("📊 Traffic Details")
                    summary = results['traffic_summary']
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Internal → External", summary['internal_to_external'])
                    with col2:
                        st.metric("Internal → Internal", summary['internal_to_internal'])
                    with col3:
                        st.metric("Suspicious Ports", summary['suspicious_ports_used'])
                    
                    # Security alerts
                    if results['security_alerts']:
                        st.subheader("🚨 Security Alerts")
                        for alert in results['security_alerts']:
                            with st.container():
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    st.write(f"**{alert['description']}**")
                                    st.write(f"Type: {alert['anomaly_type']} | Source: {alert['src_ip']} → {alert['dst_ip']}:{alert['dst_port']}")
                                with col2:
                                    st.metric("Risk", alert['risk_level'])
                                    st.metric("Score", f"{alert['anomaly_score']:.3f}")
                                st.divider()
                    else:
                        st.success("✅ No security alerts detected")
                        
                else:
                    st.error(f"Analysis failed: {response.text}")
                    
        except json.JSONDecodeError:
            st.error("❌ Invalid JSON format. Please check your input.")
        except Exception as e:
            st.error(f"Error analyzing network traffic: {e}")

def show_comprehensive_scan():
    st.header("🛡️ Comprehensive Security Scan")
    
    st.warning("This will analyze all security aspects simultaneously for complete threat assessment")
    
    # Sample data for comprehensive scan
    sample_data = {
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
    
    st.subheader("📋 Scan Configuration")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        include_emails = st.checkbox("Include Email Analysis", value=True)
    with col2:
        include_logs = st.checkbox("Include Log Analysis", value=True)
    with col3:
        include_network = st.checkbox("Include Network Analysis", value=True)
    
    # Data input sections
    scan_data = {}
    
    if include_emails:
        st.subheader("📧 Email Data")
        email_input = st.text_area(
            "Enter emails for analysis (one per line):",
            height=100,
            value="\n".join(sample_data["emails"])
        )
        if email_input:
            scan_data["emails"] = [email.strip() for email in email_input.split('\n') if email.strip()]
    
    if include_logs:
        st.subheader("📊 Log Data")
        log_input = st.text_area(
            "Enter log data (JSON format):",
            height=150,
            value=json.dumps(sample_data["logs"], indent=2)
        )
        if log_input:
            try:
                scan_data["logs"] = json.loads(log_input)
            except:
                st.error("Invalid log JSON")
    
    if include_network:
        st.subheader("🌐 Network Data")
        network_input = st.text_area(
            "Enter network traffic (JSON format):",
            height=150,
            value=json.dumps(sample_data["network_traffic"], indent=2)
        )
        if network_input:
            try:
                scan_data["network_traffic"] = json.loads(network_input)
            except:
                st.error("Invalid network JSON")
    
    if st.button("🚀 Run Comprehensive Scan", type="primary") and scan_data:
        with st.spinner("Running comprehensive security analysis..."):
            try:
                response = requests.post(f"{API_BASE}/analyze/comprehensive", 
                                       json=scan_data,
                                       timeout=60)
                
                if response.status_code == 200:
                    results = response.json()
                    
                    st.success("✅ Comprehensive Scan Completed")
                    
                    # Overall security status
                    st.subheader("🛡️ Security Overview")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Security Score", f"{results['security_score']}/100")
                    with col2:
                        st.metric("Threats Detected", results['threats_detected'])
                    with col3:
                        status_color = {
                            "SECURE": "🟢",
                            "MODERATE": "🟡", 
                            "CRITICAL": "🔴"
                        }
                        st.metric("Status", f"{status_color.get(results['security_status'], '⚪')} {results['security_status']}")
                    
                    # Progress bar for security score
                    st.progress(results['security_score'] / 100)
                    
                    # Component results
                    st.subheader("📊 Component Results")
                    
                    for component in results['components_analyzed']:
                        with st.expander(f"{component.upper()} Analysis", expanded=True):
                            component_results = results['results'][component]
                            
                            if 'error' in component_results:
                                st.error(f"Error: {component_results['error']}")
                            else:
                                if component == 'phishing':
                                    summary = component_results['summary']
                                    st.write(f"**Emails Analyzed:** {summary['total_emails']}")
                                    st.write(f"**Phishing Detected:** {summary['phishing_detected']}")
                                    st.write(f"**Phishing Percentage:** {summary['phishing_percentage']:.1f}%")
                                
                                elif component == 'logs':
                                    st.write(f"**Logs Analyzed:** {component_results['total_logs']}")
                                    st.write(f"**Anomalies:** {component_results['anomalies_detected']}")
                                    st.write(f"**Anomaly %:** {component_results['anomaly_percentage']:.1f}%")
                                
                                elif component == 'network':
                                    st.write(f"**Connections:** {component_results['total_connections']}")
                                    st.write(f"**Anomalous:** {component_results['anomalous_connections']}")
                                    st.write(f"**Anomaly %:** {component_results['anomaly_percentage']:.1f}%")
                    
                    # Recommendations
                    st.subheader("💡 Security Recommendations")
                    
                    if results['security_score'] >= 80:
                        st.success("**Excellent!** Your system appears to be well-secured.")
                    elif results['security_score'] >= 60:
                        st.warning("**Moderate Risk.** Consider reviewing security policies.")
                    else:
                        st.error("**Critical Risk!** Immediate security review recommended.")
                        
                else:
                    st.error(f"Scan failed: {response.text}")
                    
            except Exception as e:
                st.error(f"Error running comprehensive scan: {e}")

# Initialize session state
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Dashboard"

if __name__ == "__main__":
    main()
