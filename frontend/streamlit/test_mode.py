import streamlit as st
import pandas as pd

def run_test_mode(predict_intrusion):
    """
    Run the test mode interface for testing the model with custom data
    
    Args:
        predict_intrusion: Function to predict intrusions
    """
    st.header("Test Model with Custom Connection Data")
    
    # Create tabs for different testing methods
    test_tab1, test_tab2 = st.tabs(["Custom Input", "Predefined Scenarios"])
    
    with test_tab1:
        st.subheader("Enter Connection Details")
        
        # Create columns for input fields
        col1, col2, col3 = st.columns(3)
        
        with col1:
            protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
            service = st.selectbox("Service", ["http", "ftp_data", "smtp", "ssh", "telnet", "other"])
            src_bytes = st.number_input("Source Bytes", min_value=0, value=200)
            dst_bytes = st.number_input("Destination Bytes", min_value=0, value=500)
        
        with col2:
            duration = st.number_input("Duration (seconds)", min_value=0, value=0)
            flag = st.selectbox("Flag", ["SF", "REJ", "S0", "RSTO", "RSTR", "SH", "S1", "S2", "S3", "OTH"])
            logged_in = st.selectbox("Logged In", [0, 1])
            count = st.number_input("Count", min_value=0, value=1)
        
        with col3:
            srv_count = st.number_input("Service Count", min_value=0, value=1)
            serror_rate = st.slider("SError Rate", min_value=0.0, max_value=1.0, value=0.0)
            srv_serror_rate = st.slider("Service SError Rate", min_value=0.0, max_value=1.0, value=0.0)
            same_srv_rate = st.slider("Same Service Rate", min_value=0.0, max_value=1.0, value=1.0)
        
        # Create a connection dictionary with default values for all fields
        connection_data = {
            'duration': duration,
            'protocol_type': protocol,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': logged_in,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': count,
            'srv_count': srv_count,
            'serror_rate': serror_rate,
            'srv_serror_rate': srv_serror_rate,
            'rerror_rate': 0.5,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        
        # Test button
        if st.button("Test Connection"):
            with st.spinner("Analyzing connection..."):
                # Call the prediction API
                result = predict_intrusion(connection_data)
                
                # Display results
                st.subheader("Prediction Results")
                
                # Create columns for results
                res_col1, res_col2 = st.columns(2)
                
                with res_col1:
                    # Determine if it's an anomaly
                    is_anomaly = result['prediction'] != 'normal.'
                    
                    # Display prediction with appropriate color
                    if is_anomaly:
                        st.error(f"⚠️ Attack Detected: {result['prediction']}")
                    else:
                        st.success("✅ Normal Connection")
                
                with res_col2:
                    # Display anomaly score
                    st.metric("Anomaly Score", f"{result['anomaly_score']:.4f}")
                
                # Show detailed connection information
                with st.expander("Connection Details"):
                    st.json(connection_data)
    
    with test_tab2:
        st.subheader("Predefined Test Scenarios")
        
        # Define some test scenarios
        test_scenarios = get_test_scenarios()
        
        # Select a scenario
        selected_scenario = st.selectbox("Select a Test Scenario", list(test_scenarios.keys()))
        
        # Show the selected scenario details
        with st.expander("Scenario Details", expanded=False):
            st.json(test_scenarios[selected_scenario])
        
        # Test button
        if st.button("Run Test Scenario"):
            with st.spinner("Analyzing connection..."):
                # Get the selected scenario data
                scenario_data = test_scenarios[selected_scenario]
                
                # Call the prediction API
                result = predict_intrusion(scenario_data)
                
                # Display results
                st.subheader("Prediction Results")
                
                # Create columns for results
                res_col1, res_col2 = st.columns(2)
                
                with res_col1:
                    # Determine if it's an anomaly
                    is_anomaly = result['prediction'] != 'normal.'
                    
                    # Display prediction with appropriate color
                    if is_anomaly:
                        st.error(f"⚠️ Attack Detected: {result['prediction']}")
                    else:
                        st.success("✅ Normal Connection")
                
                with res_col2:
                    # Display anomaly score
                    st.metric("Anomaly Score", f"{result['anomaly_score']:.4f}")
                
                # Show detailed connection information
                with st.expander("Connection Details"):
                    st.json(scenario_data)

def get_test_scenarios():
    """
    Get predefined test scenarios for different types of network connections
    
    Returns:
        Dictionary of test scenarios
    """
    return {
        "Normal HTTP Connection": {
            'duration': 0,
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'SF',
            'src_bytes': 215,
            'dst_bytes': 45076,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 1,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        },
        "Port Scan (Nmap)": {
            'duration': 0,
            'protocol_type': 'tcp',
            'service': 'private',
            'flag': 'S0',
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 50,
            'srv_count': 50,
            'serror_rate': 1.0,
            'srv_serror_rate': 1.0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 255,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0.04,
            'dst_host_diff_srv_rate': 0.06,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 1.0,
            'dst_host_srv_serror_rate': 1.0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        },
        "DoS Attack (Neptune)": {
            'duration': 0,
            'protocol_type': 'tcp',
            'service': 'http',
            'flag': 'S0',
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 500,
            'srv_count': 500,
            'serror_rate': 1.0,
            'srv_serror_rate': 1.0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 255,
            'dst_host_srv_count': 255,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 1.0,
            'dst_host_srv_serror_rate': 1.0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        },
        "Smurf Attack": {
            'duration': 0,
            'protocol_type': 'icmp',
            'service': 'ecr_i',
            'flag': 'SF',
            'src_bytes': 1032,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 511,
            'srv_count': 511,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 255,
            'dst_host_srv_count': 255,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 1.0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        },
        "Buffer Overflow Attack": {
            'duration': 1,
            'protocol_type': 'tcp',
            'service': 'ftp_data',
            'flag': 'SF',
            'src_bytes': 983,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 3,
            'num_failed_logins': 0,
            'logged_in': 1,
            'num_compromised': 1,
            'root_shell': 1,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 4,
            'dst_host_srv_count': 4,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 0.25,
            'dst_host_srv_diff_host_rate': 0.25,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        },
        "Satan Probe": {
            'duration': 0,
            'protocol_type': 'tcp',
            'service': 'private',
            'flag': 'REJ',
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 200,
            'srv_count': 200,
            'serror_rate': 0.5,
            'srv_serror_rate': 0.5,
            'rerror_rate': 0.5,
            'srv_rerror_rate': 0.5,
            'same_srv_rate': 0.1,
            'diff_srv_rate': 0.9,
            'srv_diff_host_rate': 0.5,
            'dst_host_count': 255,
            'dst_host_srv_count': 20,
            'dst_host_same_srv_rate': 0.1,
            'dst_host_diff_srv_rate': 0.9,
            'dst_host_same_src_port_rate': 0.1,
            'dst_host_srv_diff_host_rate': 0.5,
            'dst_host_serror_rate': 0.5,
            'dst_host_srv_serror_rate': 0.5,
            'dst_host_rerror_rate': 0.5,
            'dst_host_srv_rerror_rate': 0.5
        }
    }
 