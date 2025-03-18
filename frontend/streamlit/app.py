import streamlit as st
import pandas as pd
import requests

# Import the refactored modules
from simulation import run_simulation
from test_mode import run_test_mode

# API endpoint
API_URL = "http://localhost:8000"

# Page config
st.set_page_config(
    page_title="Network Intrusion Detection",
    page_icon="🔒",
    layout="wide"
)

# Function to predict if a connection is an intrusion
def predict_intrusion(connection):
    try:
        response = requests.post(f"{API_URL}/predict", json=connection)
        return response.json()
    except:
        st.error("Error connecting to the API. Make sure the backend is running.")
        return {"prediction": "unknown", "anomaly_score": 0}

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

# Test mode toggle
st.sidebar.header("Model Testing")
test_mode = st.sidebar.checkbox("Enable Test Mode", help="Test the model with custom data")

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

# Main dashboard layout
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

# Run either test mode or simulation mode
if test_mode:
    run_test_mode(predict_intrusion)
else:
    run_simulation(filtered_data, predict_intrusion, speed, time_range, search_term)
