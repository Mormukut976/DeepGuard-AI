import streamlit as st
import requests
import time
import pandas as pd
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="DeepGuard-AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    .threat-alert {
        background-color: #ffcccc;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #ff0000;
        margin: 0.5rem 0;
    }
    .success-alert {
        background-color: #ccffcc;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #00ff00;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<h1 class="main-header">🛡️ DeepGuard-AI Dashboard</h1>', unsafe_allow_html=True)
st.markdown("### Real-time Cybersecurity Threat Monitoring System")

# Helper functions
def check_api():
    """Check if API is running"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def format_timestamp(timestamp):
    """Convert timestamp to readable format"""
    try:
        # If it's already ISO format string
        if isinstance(timestamp, str) and 'T' in timestamp:
            return timestamp.replace('T', ' ').split('.')[0]
        # If it's numeric timestamp
        elif isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        else:
            return str(timestamp)
    except:
        return str(timestamp)

def format_threats(threats):
    """Format threats for display - handle different timestamp formats"""
    formatted_threats = []
    for threat in threats:
        formatted_threat = threat.copy()
        # Format timestamp
        formatted_threat['timestamp'] = format_timestamp(threat.get('timestamp', ''))
        formatted_threats.append(formatted_threat)
    return formatted_threats

# Initialize session state
if 'scanning' not in st.session_state:
    st.session_state.scanning = False
if 'threats' not in st.session_state:
    st.session_state.threats = []
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = False

# Sidebar Navigation
st.sidebar.title("🔍 Navigation")
page = st.sidebar.radio("Go to", [
    "📊 Dashboard Overview", 
    "🔍 Phishing Detection", 
    "📜 Log Analysis", 
    "🌐 Real-time Network Scan",
    "⚙️ System Health"
])

# Dashboard Overview Page
if page == "📊 Dashboard Overview":
    st.header("📊 System Overview")
    
    if not check_api():
        st.error("❌ API Server is not running. Please start the API server first.")
        st.stop()
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    try:
        # Get system stats
        stats_response = requests.get("http://localhost:8000/system/stats")
        stats = stats_response.json()
        
        # Get network status
        status_response = requests.get("http://localhost:8000/network/status")
        status_data = status_response.json()
        
        with col1:
            st.metric("API Status", "✅ Online")
        
        with col2:
            st.metric("Network Threats", status_data.get("total_threats", 0))
        
        with col3:
            scan_status = "✅ Active" if status_data.get('scanning_status', {}).get('is_scanning') else "❌ Inactive"
            st.metric("Real-time Scan", scan_status)
        
        with col4:
            st.metric("Active Threats", len(status_data.get("active_threats", [])))
    
    except Exception as e:
        st.error(f"Error fetching system stats: {e}")
    
    # Quick actions
    st.subheader("🚀 Quick Actions")
    quick_col1, quick_col2, quick_col3 = st.columns(3)
    
    with quick_col1:
        if st.button("🌐 Start Network Scan", type="primary"):
            try:
                interfaces_response = requests.get("http://localhost:8000/network/interfaces")
                interfaces = interfaces_response.json().get('available_interfaces', ['eth0'])
                
                scan_response = requests.post("http://localhost:8000/network/start_scan", 
                                            json={"interface": interfaces[0]})
                if scan_response.status_code == 200:
                    st.success("Network scanning started!")
                    st.rerun()
                else:
                    st.error("Failed to start scanning")
            except Exception as e:
                st.error(f"Error: {e}")
    
    with quick_col2:
        if st.button("🛑 Stop Scan"):
            try:
                stop_response = requests.post("http://localhost:8000/network/stop_scan")
                if stop_response.status_code == 200:
                    st.warning("Scanning stopped!")
                    st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")
    
    with quick_col3:
        if st.button("🔄 Refresh Data"):
            st.rerun()
    
    # Recent threats
    st.subheader("🚨 Recent Threat Alerts")
    try:
        threats_response = requests.get("http://localhost:8000/network/threats")
        threats_data = threats_response.json()
        raw_threats = threats_data.get('threats', [])
        
        # ✅ Format threats properly
        threats = format_threats(raw_threats)
        
        if threats:
            # Show latest 5 threats
            recent_threats = threats[-5:]
            for threat in reversed(recent_threats):
                severity_color = {
                    'high': '🔴',
                    'medium': '🟡', 
                    'low': '🟢'
                }
                severity_icon = severity_color.get(threat.get('severity', 'low'), '⚪')
                
                with st.container():
                    st.markdown(f"""
                    <div class="threat-alert">
                        <strong>{severity_icon} {threat.get('threat_type', 'Unknown Threat')}</strong><br>
                        <strong>From:</strong> {threat.get('src_ip', 'N/A')} → <strong>To:</strong> {threat.get('dst_ip', 'N/A')}<br>
                        <strong>Protocol:</strong> {threat.get('protocol', 'N/A')} | <strong>Severity:</strong> {threat.get('severity', 'N/A')}<br>
                        <strong>Time:</strong> {threat.get('timestamp', 'N/A')}
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.info("📊 No threats detected yet. Start network scanning to monitor threats.")
            
    except Exception as e:
        st.error(f"Error fetching threats: {e}")

# Phishing Detection Page
elif page == "🔍 Phishing Detection":
    st.header("🔍 Phishing Email Detection")
    
    if not check_api():
        st.error("❌ API Server is not running. Please start the API server first.")
        st.stop()
    
    tab1, tab2 = st.tabs(["📧 Analyze Email", "📋 Sample Analysis"])
    
    with tab1:
        email_text = st.text_area(
            "Enter email content to analyze:",
            placeholder="Paste email content here...\nExample: 'Urgent: Your account will be suspended. Click here to verify: http://fake-bank.com/verify'",
            height=200
        )
        
        col1, col2 = st.columns([1, 4])
        
        with col1:
            analyze_btn = st.button("🔍 Analyze Email", type="primary")
        
        if analyze_btn and email_text:
            with st.spinner("Analyzing email for phishing attempts..."):
                try:
                    response = requests.post(
                        "http://localhost:8000/detect/phishing",
                        json={"email_content": email_text},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        # Display results
                        confidence_percent = result.get("confidence", 0) * 100
                        
                        if result.get("is_phishing"):
                            st.error(f"🚨 PHISHING DETECTED! (Confidence: {confidence_percent:.1f}%)")
                            st.markdown(f"**Threat Level:** {result.get('threat_level', 'Unknown')}")
                            st.markdown(f"**Details:** {result.get('details', 'No details available')}")
                        else:
                            st.success(f"✅ Legitimate Email (Confidence: {confidence_percent:.1f}%)")
                            st.markdown(f"**Threat Level:** {result.get('threat_level', 'Safe')}")
                        
                        # Show raw JSON in expander
                        with st.expander("View Raw Analysis Data"):
                            st.json(result)
                    else:
                        st.error("Error analyzing email")
                        
                except Exception as e:
                    st.error(f"Error: {e}")
        
        elif analyze_btn and not email_text:
            st.warning("Please enter email content to analyze")
    
    with tab2:
        st.subheader("Sample Phishing Emails for Testing")
        
        sample_emails = {
            "Phishing Example 1": "Urgent: Your bank account will be suspended. Click here to verify: http://fake-bank-security.com/verify?user=123",
            "Phishing Example 2": "Congratulations! You won $50,000. Claim your prize now: http://free-prize-win.com/claim",
            "Legitimate Example": "Hi John, your monthly statement is ready. Please log in to your account at https://yourbank.com to view it."
        }
        
        selected_sample = st.selectbox("Choose a sample email:", list(sample_emails.keys()))
        
        if st.button("Test Selected Sample"):
            email_text = sample_emails[selected_sample]
            st.text_area("Sample Email Content:", value=email_text, height=150, key="sample_display")
            
            with st.spinner("Testing sample email..."):
                try:
                    response = requests.post(
                        "http://localhost:8000/detect/phishing",
                        json={"email_content": email_text},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        confidence_percent = result.get("confidence", 0) * 100
                        
                        if result.get("is_phishing"):
                            st.error(f"🚨 PHISHING DETECTED! (Confidence: {confidence_percent:.1f}%)")
                        else:
                            st.success(f"✅ Legitimate Email (Confidence: {confidence_percent:.1f}%)")
                        
                        st.json(result)
                        
                except Exception as e:
                    st.error(f"Error: {e}")

# Log Analysis Page
elif page == "📜 Log Analysis":
    st.header("📜 Log Analysis & Monitoring")
    
    if not check_api():
        st.error("❌ API Server is not running. Please start the API server first.")
        st.stop()
    
    log_data = st.text_area(
        "Enter log data to analyze:",
        placeholder="Paste log entries here...\nExample:\n2024-01-15 10:30:15 ERROR Authentication failed for user admin\n2024-01-15 10:30:20 INFO User login successful",
        height=200
    )
    
    if st.button("Analyze Logs", type="primary"):
        if log_data:
            with st.spinner("Analyzing log data for anomalies..."):
                try:
                    response = requests.post(
                        "http://localhost:8000/analyze/logs",
                        json={"log_data": log_data},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        st.subheader("Analysis Results")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.metric("Anomalies Detected", result.get("anomaly_count", 0))
                        
                        with col2:
                            threat_level = result.get("threat_level", "Low")
                            st.metric("Threat Level", threat_level)
                        
                        # Show suspicious entries
                        suspicious_entries = result.get("suspicious_entries", [])
                        if suspicious_entries:
                            st.subheader("🚨 Suspicious Entries")
                            for entry in suspicious_entries:
                                st.warning(entry)
                        else:
                            st.success("No suspicious entries found!")
                        
                        # Raw data
                        with st.expander("View Raw Analysis Data"):
                            st.json(result)
                    else:
                        st.error("Error analyzing logs")
                        
                except Exception as e:
                    st.error(f"Error: {e}")
        else:
            st.warning("Please enter log data to analyze")

# Real-time Network Scan Page
elif page == "🌐 Real-time Network Scan":
    st.header("🌐 Real-time Network Monitoring")
    
    if not check_api():
        st.error("❌ API Server is not running. Please start the API server first.")
        st.stop()
    
    try:
        # Get network interfaces
        interfaces_response = requests.get("http://localhost:8000/network/interfaces")
        interfaces_data = interfaces_response.json()
        interfaces = interfaces_data.get('available_interfaces', [])
        
        if not interfaces:
            st.error("No network interfaces found. Make sure you're running with appropriate permissions.")
            st.stop()
        
        st.info(f"🔍 Found {len(interfaces)} network interface(s)")
        
        # Interface selection and controls
        col1, col2 = st.columns([1, 2])
        
        with col1:
            selected_interface = st.selectbox("Select Network Interface", interfaces)
            st.session_state.auto_refresh = st.checkbox("🔄 Auto-refresh threats every 5 seconds", value=False)
        
        with col2:
            st.subheader("Scan Controls")
            control_col1, control_col2, control_col3 = st.columns(3)
            
            with control_col1:
                if st.button("🚀 Start Scan", type="primary", width='stretch'):
                    try:
                        response = requests.post(
                            "http://localhost:8000/network/start_scan",
                            json={"interface": selected_interface}
                        )
                        if response.status_code == 200:
                            st.success("Real-time network scanning started!")
                            st.rerun()
                        else:
                            st.error("Failed to start scanning")
                    except Exception as e:
                        st.error(f"Error: {e}")
            
            with control_col2:
                if st.button("🛑 Stop Scan", width='stretch'):
                    try:
                        response = requests.post("http://localhost:8000/network/stop_scan")
                        if response.status_code == 200:
                            st.warning("Scanning stopped!")
                            st.rerun()
                    except Exception as e:
                        st.error(f"Error: {e}")
            
            with control_col3:
                if st.button("🔄 Refresh", width='stretch'):
                    st.rerun()
        
        # Current scan status
        status_response = requests.get("http://localhost:8000/network/status")
        status_data = status_response.json()
        
        scanning_active = status_data.get('scanning_status', {}).get('is_scanning', False)
        
        if scanning_active:
            st.markdown('<div class="success-alert">🟢 <strong>Real-time Scanning ACTIVE</strong> - Monitoring network traffic for threats</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="threat-alert">🔴 <strong>Real-time Scanning INACTIVE</strong> - Click "Start Scan" to begin monitoring</div>', unsafe_allow_html=True)
        
        # Threats display
        st.subheader("🚨 Detected Threats")
        
        try:
            threats_response = requests.get("http://localhost:8000/network/threats")
            threats_data = threats_response.json()
            raw_threats = threats_data.get('threats', [])
            
            # ✅ FIXED: Format threats properly
            threats = format_threats(raw_threats)
            
            if threats:
                st.success(f"Found {len(threats)} total threats")
                
                # Convert to DataFrame for better display
                df = pd.DataFrame(threats)
                
                # Display statistics
                stat_col1, stat_col2, stat_col3 = st.columns(3)
                with stat_col1:
                    high_severity = len([t for t in threats if t.get('severity') == 'high'])
                    st.metric("High Severity", high_severity)
                with stat_col2:
                    medium_severity = len([t for t in threats if t.get('severity') == 'medium'])
                    st.metric("Medium Severity", medium_severity)
                with stat_col3:
                    low_severity = len([t for t in threats if t.get('severity') == 'low'])
                    st.metric("Low Severity", low_severity)
                
                # Display threats table
                st.dataframe(df[['timestamp', 'threat_type', 'src_ip', 'dst_ip', 'protocol', 'severity']].tail(20), 
                           width='stretch')
                
                # Download option
                csv = df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Threats as CSV",
                    data=csv,
                    file_name=f"deepguard_threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                st.info("No threats detected yet. Start network scanning to monitor threats.")
                
        except Exception as e:
            st.error(f"Error fetching threats: {e}")
        
        # Auto-refresh logic
        if st.session_state.auto_refresh and scanning_active:
            time.sleep(5)
            st.rerun()
    
    except Exception as e:
        st.error(f"Error initializing network monitoring: {e}")

# System Health Page
elif page == "⚙️ System Health":
    st.header("⚙️ System Health & Status")
    
    if not check_api():
        st.error("❌ API Server is not running. Please start the API server first.")
        st.stop()
    
    try:
        # Health check
        health_response = requests.get("http://localhost:8000/health")
        health_data = health_response.json()
        
        st.subheader("🩺 Service Health")
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("API Status", "✅ Healthy" if health_response.status_code == 200 else "❌ Unhealthy")
            st.metric("Timestamp", health_data.get('timestamp', 'Unknown'))
        
        with col2:
            services = health_data.get('services', {})
            for service, status in services.items():
                st.metric(service.replace('_', ' ').title(), "✅ Active" if status == "active" else "❌ Inactive")
        
        # System statistics
        st.subheader("📈 System Statistics")
        stats_response = requests.get("http://localhost:8000/system/stats")
        stats_data = stats_response.json()
        
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
        
        with stat_col1:
            st.metric("Uptime", f"{stats_data.get('uptime', 0):.0f} seconds")
        
        with stat_col2:
            st.metric("Network Threats", stats_data.get('network_threats_detected', 0))
        
        with stat_col3:
            st.metric("Phishing Checks", stats_data.get('total_phishing_checks', 0))
        
        with stat_col4:
            st.metric("Log Analyses", stats_data.get('total_log_analyses', 0))
        
        # Network interfaces
        st.subheader("🔌 Network Interfaces")
        try:
            interfaces_response = requests.get("http://localhost:8000/network/interfaces")
            interfaces_data = interfaces_response.json()
            interfaces = interfaces_data.get('available_interfaces', [])
            
            for interface in interfaces:
                st.code(f"Interface: {interface}")
        except Exception as e:
            st.error(f"Error fetching interfaces: {e}")
        
        # Quick diagnostics
        st.subheader("🔧 Quick Diagnostics")
        if st.button("Run Diagnostics"):
            with st.spinner("Running system diagnostics..."):
                try:
                    # Test all endpoints
                    endpoints = {
                        "API Health": "/health",
                        "Network Status": "/network/status",
                        "System Stats": "/system/stats",
                        "Network Interfaces": "/network/interfaces"
                    }
                    
                    for name, endpoint in endpoints.items():
                        try:
                            response = requests.get(f"http://localhost:8000{endpoint}", timeout=5)
                            if response.status_code == 200:
                                st.success(f"✅ {name}: OK")
                            else:
                                st.error(f"❌ {name}: Failed (Status {response.status_code})")
                        except Exception as e:
                            st.error(f"❌ {name}: Error ({str(e)})")
                            
                except Exception as e:
                    st.error(f"Diagnostics failed: {e}")
    
    except Exception as e:
        st.error(f"Error checking system health: {e}")

# Footer
st.markdown("---")
st.markdown("🛡️ **DeepGuard-AI** - AI-Powered Cybersecurity System | Made with ❤️ for Security")
