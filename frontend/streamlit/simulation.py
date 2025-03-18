import streamlit as st
import pandas as pd
import time
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta

def run_simulation(filtered_data, predict_intrusion, speed, time_range, search_term):
    """
    Run the simulation mode
    
    Args:
        filtered_data: DataFrame with filtered connection data
        predict_intrusion: Function to predict intrusions
        speed: Simulation speed
        time_range: Time window in minutes
        search_term: Search term for filtering
    """
    # Start simulation button
    start_button = st.button("Start Simulation")
    
    if start_button and not filtered_data.empty:
        # Initialize containers for storing simulation data
        connections = []
        anomalies = []
        alerts = []
        timestamps = []  # Track when each connection occurred
        
        # Create a progress bar
        progress_bar = st.progress(0)
        
        # Create placeholders for visualizations
        chart_placeholder = st.empty()
        details_placeholder = st.empty()
        alerts_placeholder = st.empty()
        stats_placeholder = st.empty()
        
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
            
            # Update visualizations
            update_visualizations(
                chart_placeholder, details_placeholder, alerts_placeholder, stats_placeholder,
                filtered_connections, filtered_anomalies, filtered_timestamps, alerts,
                time_range, search_term, i
            )
            
            # Pause for simulation speed
            time.sleep(1.0 / speed)
        
        # Simulation complete
        st.success("Simulation complete!")
    else:
        if not start_button:
            st.info("Click 'Start Simulation' to begin")
        elif filtered_data.empty:
            st.error("No data available for the selected filters")

def update_visualizations(chart_placeholder, details_placeholder, alerts_placeholder, stats_placeholder,
                         filtered_connections, filtered_anomalies, filtered_timestamps, alerts,
                         time_range, search_term, i):
    """Update all visualizations with the current data"""
    # Update chart
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
            
            st.plotly_chart(fig, use_container_width=True, key=f"traffic_chart_{i}")
        else:
            st.info("No data available for the selected filters")
    
    # Update connection details
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
                st.dataframe(alert_df, height=300, key=f"alerts_{i}")
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
            st.bar_chart(protocol_df, x='Protocol', y='Count')
        else:
            st.info("No connection data available for protocol distribution")
