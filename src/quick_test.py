import requests
import json
import time

# API endpoint
API_URL = "http://localhost:8000/predict"  # Adjust port if needed

# Test cases for different attack types
test_cases = {
    "normal": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 215,
        "dst_bytes": 45076,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 1,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 9,
        "dst_host_srv_count": 9,
        "dst_host_same_srv_rate": 1,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 0.11,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    },
    "dos": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "S0",  # Connection attempt seen, no reply
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 100,  # High count of connections
        "srv_count": 100,  # High count of connections to same service
        "serror_rate": 1.0,  # High error rate
        "srv_serror_rate": 1.0,  # High service error rate
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 255,  # High destination host count
        "dst_host_srv_count": 255,  # High destination host service count
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 1.0,  # High destination host error rate
        "dst_host_srv_serror_rate": 1.0,  # High destination host service error rate
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    },
    "probe": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",  # Unusual service
        "flag": "REJ",  # Connection rejected
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "rerror_rate": 1.0,  # High reject error rate
        "srv_rerror_rate": 1.0,  # High service reject error rate
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 20,
        "dst_host_srv_count": 20,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 0.05,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 1.0,  # High destination host reject error rate
        "dst_host_srv_rerror_rate": 1.0  # High destination host service reject error rate
    },
    "r2l": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "ftp",
        "flag": "SF",  # Normal connection
        "src_bytes": 1032,  # Higher bytes from source
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 3,  # Some hot indicators
        "num_failed_logins": 5,  # Failed login attempts
        "logged_in": 1,  # Successfully logged in
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 1,  # File creation
        "num_shells": 0,
        "num_access_files": 1,  # Accessing sensitive files
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 1,  # Guest login
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 2,
        "dst_host_srv_count": 2,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 0.5,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    },
    "u2r": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "telnet",
        "flag": "SF",  # Normal connection
        "src_bytes": 1250,
        "dst_bytes": 2048,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 10,  # High number of hot indicators
        "num_failed_logins": 0,
        "logged_in": 1,  # Logged in
        "num_compromised": 2,  # Compromised conditions
        "root_shell": 1,  # Root shell obtained
        "su_attempted": 1,  # Attempted to use su
        "num_root": 2,  # Root accesses
        "num_file_creations": 8,  # Many file creations
        "num_shells": 1,  # Shell obtained
        "num_access_files": 5,  # Accessing sensitive files
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0,
        "srv_serror_rate": 0,
        "rerror_rate": 0,
        "srv_rerror_rate": 0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0,
        "srv_diff_host_rate": 0,
        "dst_host_count": 1,
        "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0,
        "dst_host_serror_rate": 0,
        "dst_host_srv_serror_rate": 0,
        "dst_host_rerror_rate": 0,
        "dst_host_srv_rerror_rate": 0
    }
}

def test_api():
    """Test the API with different attack scenarios"""
    print("Testing API with different attack scenarios...")
    
    results = {}
    
    for attack_type, payload in test_cases.items():
        print(f"\nTesting {attack_type} scenario...")
        
        try:
            # Send request to API
            response = requests.post(API_URL, json=payload)
            
            # Check if request was successful
            if response.status_code == 200:
                result = response.json()
                results[attack_type] = result
                
                # Print prediction and probability
                print(f"Prediction: {result['prediction']}")
                print(f"Probability: {result['probability']:.4f}")
                print(f"Alert: {result['alert']}")
                
                # Print top features if available
                if 'details' in result and 'top_features' in result['details']:
                    print("Top features:")
                    for feature, importance in list(result['details']['top_features'].items())[:5]:
                        print(f"  - {feature}: {importance:.4f}")
            else:
                print(f"Error: {response.status_code} - {response.text}")
        
        except Exception as e:
            print(f"Error testing {attack_type} scenario: {str(e)}")
        
        # Wait a bit between requests
        time.sleep(0.5)
    
    # Print summary
    print("\n=== Summary ===")
    for attack_type, result in results.items():
        print(f"{attack_type}: Predicted as {result['prediction']} with {result['probability']:.4f} probability")

if __name__ == "__main__":
    test_api()
