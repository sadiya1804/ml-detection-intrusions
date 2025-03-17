# frontend/app.py
import streamlit as st
import pandas as pd
import numpy as np
import requests
import time
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime

# API endpoint
API_URL = "http://localhost:8000"

# Page config
st.set_page_config(
    page_title="Network Intrusion Detection",
    page_icon="🔒",
    layout="wide"
)

# Title and description
st.title("Network Intrusion Detection System")
st.markdown("""
This application simulates network connections and detects potential intrusions using 
machine learning models trained on the KDD Cup 99 dataset.
""")

# Sidebar controls
st.sidebar.header("Simulation Controls")

# Simulation mode
sim_mode = st.sidebar.radio(
    "Simulation Mode",
    ["Real-time", "Replay"]
)

# Speed control
if sim_mode == "Replay":
    speed = st.sidebar.slider("Replay Speed", 1, 10, 2)
else:
    speed = 1

# Data filtering
st.sidebar.header("Data Filters")
protocols = ["All", "tcp", "udp", "icmp"]
selected_protocol = st.sidebar.selectbox("Protocol", protocols)

# Load sample data
@st.cache_data
def load_sample_data():
    # This would be replaced with your actual data loading logic
    columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
              'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 
              'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 
              'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 
              'num_access_files', 'num_outbound_cmds', 'is_host_login', 
              'is_guest_login', 'count', 'srv_count', 'serror_rate', 
              'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 
              'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 
              'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
              'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
              'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
              'dst_host_srv_rerror_rate', 'label']
    
    try:
        df = pd.read_csv("../data/kddcup.data_10_percent", names=columns, nrows=1000)
        return df
    except:
        st.error("Error loading data. Please make sure the dataset is available.")
        return pd.DataFrame()

data = load_sample_data()

# Filter data based on selection
if selected_protocol != "All" and not data.empty:
    filtered_data = data[data['protocol_type'] == selected_protocol]
else:
    filtered_data = data

# Function to predict if a connection is an intrusion
def predict_intrusion(connection):
    try:
        response = requests.post(f"{API_URL}/predict", json=connection)
        return response.json()
    except:
        st.error("Error connecting to the API. Make sure the backend is running.")
        return {"prediction": "unknown", "anomaly_score": 0}

# Main dashboard
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Network Traffic Visualization")
    
    # Create a placeholder for the chart
    chart_placeholder = st.empty()
    
    # Create a placeholder for connection details
    details_placeholder = st.empty()

with col2:
    st.subheader("Alerts")
    alerts_placeholder = st.empty()
    
    st.subheader("Statistics")
    stats_placeholder = st.empty()

# Start simulation button
start_button = st.button("Start Simulation")

if start_button and not filtered_data.empty:
    # Initialize containers for storing simulation data
    connections = []
    anomalies = []
    alerts = []
    
    # Create a progress bar
    progress_bar = st.progress(0)
    
    # Simulate connections
    for i, row in enumerate(filtered_data.iterrows()):
        # Update progress
        progress = min(i / len(filtered_data), 1.0)
        progress_bar.progress(progress)
        
        # Get connection data
        _, connection = row
        connection_dict = connection.to_dict()
        
        # Remove label for prediction
        label = connection_dict.pop('label')
        
        # Predict if connection is an intrusion
        result = predict_intrusion(connection_dict)
        
        # Add to connections list
        connections.append(connection_dict)
        
        # Check if anomaly
        is_anomaly = result['prediction'] != 'normal.'
        anomalies.append(is_anomaly)
        
        # Add to alerts if anomaly
        if is_anomaly:
            alerts.append({
                'time': datetime.now().strftime("%H:%M:%S"),
                'type': result['prediction'],
                'score': result['anomaly_score'],
                'details': f"Protocol: {connection_dict['protocol_type']}, Service: {connection_dict['service']}"
            })
        
        # Update visualizations
        with chart_placeholder:
            # Create time series of src_bytes and dst_bytes
            df_vis = pd.DataFrame({
                'id': range(len(connections)),
                'src_bytes': [c['src_bytes'] for c in connections],
                'dst_bytes': [c['dst_bytes'] for c in connections],
                'anomaly': anomalies
            })
            
            fig = px.scatter(df_vis, x='id', y=['src_bytes', 'dst_bytes'], 
                           color='anomaly', size='src_bytes',
                           labels={'id': 'Connection ID', 'value': 'Bytes'},
                           title='Network Traffic')
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Update connection details
        with details_placeholder:
            st.dataframe(pd.DataFrame(connections[-10:]))
        
        # Update alerts
        with alerts_placeholder:
            if alerts:
                alert_df = pd.DataFrame(alerts)
                st.dataframe(alert_df, height=300)
            else:
                st.info("No alerts detected yet")
        
       # Update statistics
        with stats_placeholder:
            total = len(connections)
            anomaly_count = sum(anomalies)
            
            # Calculate percentage of anomalies
            anomaly_percentage = (anomaly_count/total*100) if total > 0 else 0
            
            # Create metrics in columns
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Connections", total)
            col2.metric("Anomalies Detected", anomaly_count)
            col3.metric("Anomaly Percentage", f"{anomaly_percentage:.2f}%")
            
            # Add a pie chart to visualize normal vs abnormal distribution
            if connections:
                # Create data for pie chart
                labels = ['Normal', 'Anomaly']
                values = [total - anomaly_count, anomaly_count]
                
                # Create pie chart with Plotly
                fig = px.pie(
                    values=values, 
                    names=labels,
                    title='Connection Types Distribution',
                    color=labels,
                    color_discrete_map={'Normal': 'green', 'Anomaly': 'red'}
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Protocol distribution - FIXED VERSION
            if connections:
                # Create a Series of protocol types
                protocol_series = pd.Series([c['protocol_type'] for c in connections])
                # Convert to DataFrame with proper columns
                protocol_df = protocol_series.value_counts().reset_index()
                protocol_df.columns = ['Protocol', 'Count']
                # Create the bar chart
                st.bar_chart(protocol_df, x='Protocol', y='Count')
            else:
                st.info("No connection data available for protocol distribution")

        
        # Pause for simulation speed
        time.sleep(1.0 / speed)
    
    # Simulation complete
    st.success("Simulation complete!")
else:
    if not start_button:
        st.info("Click 'Start Simulation' to begin")
    elif filtered_data.empty:
        st.error("No data available for the selected filters")
