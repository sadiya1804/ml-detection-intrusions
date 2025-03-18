import streamlit as st
import pandas as pd
import numpy as np
import requests
import time
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from datetime import datetime, timedelta
import plotly.graph_objects as go

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

# Time range selector
st.sidebar.header("Time Range")
time_range = st.sidebar.slider(
    "Select Time Window (minutes)",
    min_value=1,
    max_value=60,
    value=10,
    help="Filter data to show only the last X minutes"
)

# Search functionality
st.sidebar.header("Search")
search_term = st.sidebar.text_input("Search for specific events", 
                                   help="Enter protocol, service, or attack type")

# Load sample data
@st.cache_data
def load_sample_data():
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
    timestamps = []  # track when each connection occurred
    
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
        
        # Add timestamp
        current_time = datetime.now()
        timestamps.append(current_time)
        
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
                'time': current_time.strftime("%H:%M:%S"),
                'type': result['prediction'],
                'score': result['anomaly_score'],
                'details': f"Protocol: {connection_dict['protocol_type']}, Service: {connection_dict['service']}"
            })
        
        # Filter data based on time range
        time_threshold = datetime.now() - timedelta(minutes=time_range)
        time_filtered_indices = [i for i, t in enumerate(timestamps) if t >= time_threshold]
        
        # Filter data based on search term
        if search_term:
            search_filtered_indices = [
                i for i in time_filtered_indices 
                if (search_term.lower() in connections[i]['protocol_type'].lower() or
                    search_term.lower() in connections[i]['service'].lower() or
                    (i < len(anomalies) and anomalies[i] and 
                     any(search_term.lower() in alert['type'].lower() for alert in alerts)))
            ]
        else:
            search_filtered_indices = time_filtered_indices
        
        # Get filtered data
        filtered_connections = [connections[i] for i in search_filtered_indices]
        filtered_anomalies = [anomalies[i] for i in search_filtered_indices]
        filtered_timestamps = [timestamps[i] for i in search_filtered_indices]
        
        # Update visualizations with filtered data
        with chart_placeholder:
            if filtered_connections:
                # Create time series visualization with zoom capability
                df_vis = pd.DataFrame({
                    'timestamp': filtered_timestamps,
                    'src_bytes': [c['src_bytes'] for c in filtered_connections],
                    'dst_bytes': [c['dst_bytes'] for c in filtered_connections],
                    'anomaly': filtered_anomalies
                })
                
                # Create interactive plot with Plotly
                fig = go.Figure()
                
                # Add normal traffic
                normal_df = df_vis[~df_vis['anomaly']]
                if not normal_df.empty:
                    fig.add_trace(go.Scatter(
                        x=normal_df['timestamp'],
                        y=normal_df['src_bytes'],
                        mode='markers',
                        name='Normal Traffic (src)',
                        marker=dict(color='green', size=8)
                    ))
                
                # Add anomalous traffic
                anomaly_df = df_vis[df_vis['anomaly']]
                if not anomaly_df.empty:
                    fig.add_trace(go.Scatter(
                        x=anomaly_df['timestamp'],
                        y=anomaly_df['src_bytes'],
                        mode='markers',
                        name='Anomalous Traffic (src)',
                        marker=dict(color='red', size=12, symbol='x')
                    ))
                
                # Update layout for better interactivity
                fig.update_layout(
                    title='Network Traffic Over Time',
                    xaxis_title='Time',
                    yaxis_title='Bytes',
                    hovermode='closest',
                    # Add range slider and selector for time-based zooming
                    xaxis=dict(
                        rangeselector=dict(
                            buttons=list([
                                dict(count=1, label="1m", step="minute", stepmode="backward"),
                                dict(count=5, label="5m", step="minute", stepmode="backward"),
                                dict(count=10, label="10m", step="minute", stepmode="backward"),
                                dict(step="all")
                            ])
                        ),
                        rangeslider=dict(visible=True),
                        type="date"
                    )
                )
                
                st.plotly_chart(fig, use_container_width=True,key=f"traffic_chart_{i}")
            else:
                st.info("No data available for the selected filters")
        
        # Update connection details with search highlighting
        with details_placeholder:
            if filtered_connections:
                # Convert to DataFrame for display
                df_details = pd.DataFrame(filtered_connections[-10:])
                
                # Add timestamp and anomaly columns
                df_details['timestamp'] = [t.strftime("%H:%M:%S") for t in filtered_timestamps[-10:]]
                df_details['anomaly'] = filtered_anomalies[-10:]
                
                # Move timestamp to first column
                cols = df_details.columns.tolist()
                cols = ['timestamp'] + [c for c in cols if c != 'timestamp']
                df_details = df_details[cols]
                
                # Display with conditional formatting
                st.dataframe(
                    df_details.style.apply(
                        lambda x: ['background-color: #ffcccc' if x['anomaly'] else '' for _ in x],
                        axis=1
                    ),
                    height=300,
                    key=f"connection_details_{i}"
                )
            else:
                st.info("No connections match your filters")
        
        # Update alerts
        with alerts_placeholder:
            if alerts:
                # Filter alerts based on time range
                time_filtered_alerts = [
                    alert for alert in alerts
                    if datetime.strptime(alert['time'], "%H:%M:%S") >= 
                       (datetime.now() - timedelta(minutes=time_range)).time()
                ]
                
                # Filter alerts based on search term
                if search_term:
                    filtered_alerts = [
                        alert for alert in time_filtered_alerts
                        if (search_term.lower() in alert['type'].lower() or
                            search_term.lower() in alert['details'].lower())
                    ]
                else:
                    filtered_alerts = time_filtered_alerts
                
                if filtered_alerts:
                    alert_df = pd.DataFrame(filtered_alerts)
                    st.dataframe(alert_df, height=300,  key=f"alerts_{i}")
                else:
                    st.info("No alerts match your filters")
            else:
                st.info("No alerts detected yet")
        
        # Update statistics
        with stats_placeholder:
            total = len(filtered_connections)
            anomaly_count = sum(filtered_anomalies)
            
            # Calculate percentage of anomalies
            anomaly_percentage = (anomaly_count/total*100) if total > 0 else 0
            
            # Create metrics in columns
            col1, col2 = st.columns(2)
            col1.metric("Total Connections", total)
            col2.metric("Anomalies Detected", anomaly_count, 
                      f"{anomaly_percentage:.1f}%" if total > 0 else "0%")
            
            # Add progress bar to show anomaly percentage
            st.subheader(f"Anomaly Percentage: {anomaly_percentage:.2f}%")
            st.progress(anomaly_percentage/100)
            
            # Protocol distribution
            if filtered_connections:
                # Create a Series of protocol types
                protocol_series = pd.Series([c['protocol_type'] for c in filtered_connections])
                # Convert to DataFrame with proper columns
                protocol_df = protocol_series.value_counts().reset_index()
                protocol_df.columns = ['Protocol', 'Count']
                # Create the bar chart
                st.bar_chart(protocol_df, x='Protocol', y='Count',  key=f"protocol_chart_{i}")
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