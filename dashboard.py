import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import time
from datetime import datetime, timedelta
import json

class DDoSDashboard:
    def __init__(self):
        st.set_page_config(
            page_title="DDoS Detection System",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        self.setup_styling()
    
    def setup_styling(self):
        st.markdown("""
        <style>
        .main-header {
            font-size: 3rem;
            color: #FF4B4B;
            text-align: center;
            font-weight: bold;
            margin-bottom: 2rem;
        }
        .metric-card {
            background-color: #f0f2f6;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .alert-box {
            padding: 20px;
            border-radius: 10px;
            margin: 10px 0;
        }
        .alert-critical {
            background-color: #ff4444;
            color: white;
        }
        .alert-warning {
            background-color: #ffaa00;
            color: white;
        }
        .alert-normal {
            background-color: #00C851;
            color: white;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def render_header(self):
        st.markdown('<h1 class="main-header">🛡️ DDoS Detection & Monitoring System</h1>', 
                   unsafe_allow_html=True)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("System Status", "🟢 Active", delta="Monitoring")
        with col2:
            st.metric("Total Requests", "1,234,567", delta="↑ 12.5%")
        with col3:
            st.metric("Threats Detected", "23", delta="↓ 5", delta_color="inverse")
        with col4:
            st.metric("Response Time", "45ms", delta="↓ 8ms", delta_color="inverse")
    
    def render_realtime_traffic(self):
        st.subheader("📊 Real-Time Traffic Analysis")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Real-time traffic graph
            fig = go.Figure()
            
            # Simulate real-time data
            time_points = pd.date_range(end=datetime.now(), periods=60, freq='1min')
            normal_traffic = np.random.normal(1000, 200, 60)
            suspicious_traffic = np.random.normal(100, 50, 60)
            
            fig.add_trace(go.Scatter(
                x=time_points, y=normal_traffic,
                mode='lines', name='Normal Traffic',
                line=dict(color='#00C851', width=2),
                fill='tozeroy'
            ))
            
            fig.add_trace(go.Scatter(
                x=time_points, y=suspicious_traffic,
                mode='lines', name='Suspicious Traffic',
                line=dict(color='#ff4444', width=2),
                fill='tozeroy'
            ))
            
            fig.update_layout(
                title="Traffic Volume (Last Hour)",
                xaxis_title="Time",
                yaxis_title="Requests/min",
                hovermode='x unified',
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Traffic distribution
            labels = ['Normal', 'Suspicious', 'Blocked']
            values = [85, 10, 5]
            colors = ['#00C851', '#ffaa00', '#ff4444']
            
            fig_pie = go.Figure(data=[go.Pie(
                labels=labels, values=values,
                marker=dict(colors=colors),
                hole=0.4
            )])
            
            fig_pie.update_layout(
                title="Traffic Distribution",
                height=400
            )
            
            st.plotly_chart(fig_pie, use_container_width=True)
    
    def render_attack_heatmap(self):
        st.subheader("🗺️ Attack Source Heatmap")
        
        # Simulate geographic data
        attack_data = pd.DataFrame({
            'lat': np.random.uniform(-60, 70, 100),
            'lon': np.random.uniform(-180, 180, 100),
            'intensity': np.random.randint(1, 100, 100)
        })
        
        fig = px.scatter_geo(
            attack_data,
            lat='lat', lon='lon',
            size='intensity',
            color='intensity',
            color_continuous_scale='Reds',
            title='Global Attack Sources',
            projection='natural earth'
        )
        
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
    
    def render_attack_timeline(self):
        st.subheader("⏱️ Attack Timeline")
        
        # Simulate attack events
        attack_types = ['SYN Flood', 'UDP Flood', 'HTTP Flood', 'DNS Amplification']
        severities = ['Low', 'Medium', 'High', 'Critical']
        
        attacks = []
        for i in range(20):
            attacks.append({
                'timestamp': datetime.now() - timedelta(hours=np.random.randint(0, 24)),
                'type': np.random.choice(attack_types),
                'severity': np.random.choice(severities),
                'source_ip': f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'packets': np.random.randint(1000, 100000)
            })
        
        df_attacks = pd.DataFrame(attacks).sort_values('timestamp', ascending=False)
        
        # Color code by severity
        def get_severity_color(severity):
            colors = {
                'Low': '🟢',
                'Medium': '🟡',
                'High': '🟠',
                'Critical': '🔴'
            }
            return colors.get(severity, '⚪')
        
        df_attacks['severity_icon'] = df_attacks['severity'].apply(get_severity_color)
        
        st.dataframe(
            df_attacks[['timestamp', 'severity_icon', 'type', 'source_ip', 'packets']],
            use_container_width=True,
            height=400
        )
    
    def render_statistics(self):
        st.subheader("📈 Detailed Statistics")
        
        tab1, tab2, tab3, tab4 = st.tabs([
            "Protocol Analysis", "Port Analysis", "IP Statistics", "Performance Metrics"
        ])
        
        with tab1:
            col1, col2 = st.columns(2)
            
            with col1:
                # Protocol distribution
                protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
                counts = [45000, 23000, 5000, 15000, 12000]
                
                fig = go.Figure(data=[go.Bar(
                    x=protocols, y=counts,
                    marker_color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
                )])
                fig.update_layout(title="Traffic by Protocol", height=300)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Packet size distribution
                sizes = np.random.lognormal(6, 1.5, 1000)
                fig = go.Figure(data=[go.Histogram(x=sizes, nbinsx=50)])
                fig.update_layout(title="Packet Size Distribution", height=300)
                st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            # Top destination ports
            ports = [80, 443, 22, 25, 53, 3389, 8080, 21, 3306, 5432]
            port_counts = np.random.randint(1000, 50000, 10)
            
            fig = go.Figure(data=[go.Bar(
                x=[str(p) for p in ports], y=port_counts,
                orientation='v'
            )])
            fig.update_layout(title="Top Destination Ports", height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with tab3:
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Unique Source IPs", "1,245", delta="↑ 123")
                st.metric("Unique Destination IPs", "89", delta="↑ 5")
                st.metric("IP Concentration", "15.3%", delta="↑ 2.1%", delta_color="inverse")
            
            with col2:
                st.metric("Average Requests/IP", "456", delta="↑ 45")
                st.metric("Max Requests/IP", "12,345", delta="↑ 1,234", delta_color="inverse")
                st.metric("Blacklisted IPs", "23", delta="↑ 3", delta_color="inverse")
        
        with tab4:
            # Model performance metrics
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Model Accuracy", "98.5%", delta="↑ 0.3%")
                st.metric("Precision", "97.2%", delta="↑ 0.5%")
            
            with col2:
                st.metric("Recall", "96.8%", delta="↑ 0.2%")
                st.metric("F1 Score", "97.0%", delta="↑ 0.4%")
            
            with col3:
                st.metric("False Positives", "2.3%", delta="↓ 0.5%", delta_color="inverse")
                st.metric("Detection Time", "12ms", delta="↓ 2ms", delta_color="inverse")
    
    def render_alerts(self):
        st.subheader("🚨 Active Alerts")
        
        alerts = [
            {
                'level': 'critical',
                'title': 'SYN Flood Attack Detected',
                'message': 'High volume SYN packets from 192.168.1.100',
                'time': '2 minutes ago'
            },
            {
                'level': 'warning',
                'title': 'Unusual Traffic Pattern',
                'message': 'Spike in UDP traffic to port 53',
                'time': '15 minutes ago'
            },
            {
                'level': 'normal',
                'title': 'System Update',
                'message': 'Model retrained with new data',
                'time': '1 hour ago'
            }
        ]
        
        for alert in alerts:
            alert_class = f"alert-{alert['level']}"
            st.markdown(f"""
            <div class="alert-box {alert_class}">
                <h4>{alert['title']}</h4>
                <p>{alert['message']}</p>
                <small>{alert['time']}</small>
            </div>
            """, unsafe_allow_html=True)
    
    def render_controls(self):
        st.sidebar.header("⚙️ Control Panel")
        
        st.sidebar.subheader("Detection Settings")
        sensitivity = st.sidebar.slider("Detection Sensitivity", 0, 100, 75)
        auto_block = st.sidebar.checkbox("Auto-block suspicious IPs", value=True)
        alert_threshold = st.sidebar.number_input("Alert Threshold (req/min)", 
                                                  value=1000, step=100)
        
        st.sidebar.subheader("Monitoring")
        refresh_rate = st.sidebar.selectbox("Refresh Rate", 
                                           ["1 second", "5 seconds", "10 seconds", "30 seconds"])
        
        if st.sidebar.button("🔄 Refresh Data"):
            st.rerun()
        
        if st.sidebar.button("⬇️ Export Report"):
            st.sidebar.success("Report exported successfully!")
        
        st.sidebar.subheader("Quick Actions")
        if st.sidebar.button("🛑 Block IP"):
            ip = st.sidebar.text_input("Enter IP to block")
            if ip:
                st.sidebar.warning(f"Blocked IP: {ip}")
        
        if st.sidebar.button("🔓 Unblock IP"):
            ip = st.sidebar.text_input("Enter IP to unblock")
            if ip:
                st.sidebar.info(f"Unblocked IP: {ip}")
    
    def run(self):
        """Main dashboard runner"""
        self.render_controls()
        self.render_header()
        self.render_alerts()
        self.render_realtime_traffic()
        self.render_attack_heatmap()
        self.render_attack_timeline()
        self.render_statistics()
        
        # Auto-refresh
        time.sleep(1)

if __name__ == "__main__":
    dashboard = DDoSDashboard()
    dashboard.run()