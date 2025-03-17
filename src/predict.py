import pandas as pd
import numpy as np
import os
import joblib
import logging
from typing import Tuple, Dict, Any, List, Union
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('logs', 'predict.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Path to the trained model
MODEL_PATH = os.path.join('models', 'intrusion_detection_model.pkl')

def load_model():
    """Load the trained model"""
    try:
        if not os.path.exists(MODEL_PATH):
            logger.error(f"Model not found at {MODEL_PATH}")
            raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
        
        logger.info(f"Loading model from {MODEL_PATH}")
        model = joblib.load(MODEL_PATH)
        return model
    
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        raise

def predict_intrusion(data: pd.DataFrame) -> Tuple[str, float, Dict[str, Any]]:
    """
    Predict if a network connection is an intrusion
    
    Args:
        data: Preprocessed DataFrame containing the connection data
        
    Returns:
        Tuple containing:
        - prediction: The predicted class (normal, dos, probe, r2l, u2r)
        - probability: The probability of the prediction
        - details: Additional details about the prediction
    """
    try:
        start_time = time.time()
        
        # Load the model
        model = load_model()
        
        # Make prediction
        prediction_proba = model.predict_proba(data)
        prediction = model.predict(data)[0]
        
        # Get the probability of the predicted class
        class_idx = list(model.classes_).index(prediction)
        probability = prediction_proba[0][class_idx]
        
        # Calculate prediction time
        prediction_time = time.time() - start_time
        
        # Create details dictionary
        details = {
            "prediction_time_ms": round(prediction_time * 1000, 2),
            "all_probabilities": {
                cls: float(prediction_proba[0][i]) 
                for i, cls in enumerate(model.classes_)
            },
            "model_type": type(model).__name__,
            "confidence_level": get_confidence_level(probability),
            "severity": get_severity_level(prediction, probability)
        }
        
        # Add feature importance if available
        if hasattr(model, 'feature_importances_'):
            # Get top 10 most important features
            feature_importance = {
                data.columns[i]: float(importance)
                for i, importance in enumerate(model.feature_importances_)
            }
            
            # Sort by importance and get top 10
            sorted_importance = sorted(
                feature_importance.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
            
            details["top_features"] = dict(sorted_importance)
        
        logger.info(f"Prediction: {prediction}, Probability: {probability:.4f}, Time: {prediction_time:.4f}s")
        
        return prediction, probability, details
    
    except Exception as e:
        logger.error(f"Error making prediction: {str(e)}")
        # Return a default prediction in case of error
        return "error", 0.0, {"error": str(e)}

def get_confidence_level(probability: float) -> str:
    """Get confidence level based on probability"""
    if probability >= 0.9:
        return "very high"
    elif probability >= 0.75:
        return "high"
    elif probability >= 0.5:
        return "medium"
    elif probability >= 0.25:
        return "low"
    else:
        return "very low"

def get_severity_level(prediction: str, probability: float) -> Dict[str, Any]:
    """Get severity level based on prediction and probability"""
    # Default severity for normal traffic
    if prediction.lower() == "normal":
        return {
            "level": "none",
            "score": 0,
            "description": "Normal network traffic"
        }
    
    # Define severity levels for different attack types
    severity_mapping = {
        "dos": {
            "level": "high",
            "score": 8,
            "description": "Denial of Service attack detected"
        },
        "probe": {
            "level": "medium",
            "score": 5,
            "description": "Network probing/scanning detected"
        },
        "r2l": {
            "level": "high",
            "score": 7,
            "description": "Remote to Local attack detected"
        },
        "u2r": {
            "level": "critical",
            "score": 10,
            "description": "User to Root attack detected"
        },
        "unknown": {
            "level": "medium",
            "score": 5,
            "description": "Unknown attack type detected"
        }
    }
    
    # Get base severity for the attack type
    severity = severity_mapping.get(prediction.lower(), severity_mapping["unknown"])
    
    # Adjust score based on probability
    adjusted_score = min(10, severity["score"] * probability)
    severity["score"] = round(adjusted_score, 1)
    
    # Add recommended actions based on severity level
    if severity["level"] == "critical":
        severity["recommended_actions"] = [
            "Immediately block the source IP",
            "Isolate affected systems",
            "Initiate incident response protocol",
            "Perform forensic analysis"
        ]
    elif severity["level"] == "high":
        severity["recommended_actions"] = [
            "Block the source IP",
            "Monitor affected systems",
            "Investigate the attack vector",
            "Update security rules"
        ]
    elif severity["level"] == "medium":
        severity["recommended_actions"] = [
            "Monitor the source IP",
            "Review logs for additional suspicious activity",
            "Consider temporary blocking if activity persists"
        ]
    else:
        severity["recommended_actions"] = [
            "Monitor for continued suspicious activity",
            "No immediate action required"
        ]
    
    return severity

def batch_predict(data: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Make predictions for a batch of connections
    
    Args:
        data: Preprocessed DataFrame containing multiple connection data points
        
    Returns:
        List of prediction results
    """
    try:
        # Load the model
        model = load_model()
        
        # Make predictions
        predictions = model.predict(data)
        prediction_probas = model.predict_proba(data)
        
        results = []
        for i, (prediction, proba) in enumerate(zip(predictions, prediction_probas)):
            # Get the probability of the predicted class
            class_idx = list(model.classes_).index(prediction)
            probability = proba[class_idx]
            
            # Create details dictionary
            details = {
                "all_probabilities": {
                    cls: float(proba[i]) 
                    for i, cls in enumerate(model.classes_)
                },
                "confidence_level": get_confidence_level(probability),
                "severity": get_severity_level(prediction, probability)
            }
            
            results.append({
                "prediction": prediction,
                "probability": float(probability),
                "details": details
            })
        
        logger.info(f"Batch prediction completed for {len(data)} samples")
        return results
    
    except Exception as e:
        logger.error(f"Error making batch prediction: {str(e)}")
        raise

if __name__ == "__main__":
    # Test prediction on a sample
    from data_loader import preprocess_data
    
    # Create a sample connection
    sample = {
        'duration': 0, 'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
        'src_bytes': 215, 'dst_bytes': 45076, 'land': 0, 'wrong_fragment': 0,
        'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 1,
        'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 0,
        'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        'count': 1, 'srv_count': 1, 'serror_rate': 0, 'srv_serror_rate': 0,
        'rerror_rate': 0, 'srv_rerror_rate': 0, 'same_srv_rate': 1,
        'diff_srv_rate': 0, 'srv_diff_host_rate': 0, 'dst_host_count': 9,
        'dst_host_srv_count': 9, 'dst_host_same_srv_rate': 1,
        'dst_host_diff_srv_rate': 0, 'dst_host_same_src_port_rate': 0.11,
        'dst_host_srv_diff_host_rate': 0, 'dst_host_serror_rate': 0,
        'dst_host_srv_serror_rate': 0, 'dst_host_rerror_rate': 0,
        'dst_host_srv_rerror_rate': 0
    }
    
    # Convert to DataFrame and preprocess
    sample_df = pd.DataFrame([sample])
    processed_sample = preprocess_data(sample_df)
    
    # Make prediction
    try:
        prediction, probability, details = predict_intrusion(processed_sample)
        print(f"Prediction: {prediction}")
        print(f"Probability: {probability:.4f}")
        print(f"Details: {details}")
    except Exception as e:
        print(f"Error: {str(e)}")
