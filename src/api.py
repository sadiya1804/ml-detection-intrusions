from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import pandas as pd
import joblib
import os
import json
import logging
from datetime import datetime
import sys
from typing import List, Dict, Any, Optional

# Add the parent directory to sys.path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
from src.predict import predict_intrusion
from src.data_loader import preprocess_data

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('logs', 'api.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Initialize FastAPI app
app = FastAPI(
    title="Network Intrusion Detection API",
    description="API for real-time detection of network intrusions using ML models trained on KDD Cup 99 dataset",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Load model on startup
MODEL_PATH = os.path.join('models', 'intrusion_detection_model.pkl')

# Define request and response models
class ConnectionData(BaseModel):
    """Model for a single network connection data point"""
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: int
    dst_bytes: int
    land: int
    wrong_fragment: int
    urgent: int
    hot: int
    num_failed_logins: int
    logged_in: int
    num_compromised: int
    root_shell: int
    su_attempted: int
    num_root: int
    num_file_creations: int
    num_shells: int
    num_access_files: int
    num_outbound_cmds: int
    is_host_login: int
    is_guest_login: int
    count: int
    srv_count: int
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float

class BatchConnectionData(BaseModel):
    """Model for batch processing of multiple connections"""
    connections: List[ConnectionData]

class PredictionResponse(BaseModel):
    """Model for prediction response"""
    prediction: str
    probability: float
    timestamp: str
    alert: bool
    details: Dict[str, Any]

class BatchPredictionResponse(BaseModel):
    """Model for batch prediction response"""
    predictions: List[PredictionResponse]
    summary: Dict[str, Any]

def log_prediction(connection_data: Dict[str, Any], prediction: str, probability: float, alert: bool):
    """Log prediction details to file"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "connection_data": connection_data,
        "prediction": prediction,
        "probability": probability,
        "alert": alert
    }
    
    log_file = os.path.join('logs', f'predictions_{datetime.now().strftime("%Y%m%d")}.json')
    
    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        logger.error(f"Failed to log prediction: {str(e)}")

@app.on_event("startup")
async def startup_event():
    """Load model and other resources on startup"""
    try:
        # Check if model exists
        if not os.path.exists(MODEL_PATH):
            logger.warning(f"Model not found at {MODEL_PATH}. API will attempt to load model when needed.")
        else:
            logger.info(f"Model found at {MODEL_PATH}")
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Network Intrusion Detection API is running"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check if model file exists
        model_exists = os.path.exists(MODEL_PATH)
        return {
            "status": "healthy",
            "model_loaded": model_exists,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@app.post("/predict", response_model=PredictionResponse)
async def predict(connection: ConnectionData, background_tasks: BackgroundTasks):
    """
    Predict if a network connection is an intrusion
    """
    try:
        # Convert Pydantic model to dict
        connection_dict = connection.dict()
        
        # Preprocess the data
        processed_data = preprocess_data(pd.DataFrame([connection_dict]))
        
        # Make prediction
        prediction, probability, details = predict_intrusion(processed_data)
        
        # Determine if this is an alert (non-normal traffic)
        alert = prediction.lower() != "normal"
        
        # Log the prediction asynchronously
        background_tasks.add_task(log_prediction, connection_dict, prediction, float(probability), alert)
        
        return {
            "prediction": prediction,
            "probability": float(probability),
            "timestamp": datetime.now().isoformat(),
            "alert": alert,
            "details": details
        }
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@app.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(batch: BatchConnectionData, background_tasks: BackgroundTasks):
    """
    Batch predict for multiple network connections
    """
    try:
        # Convert batch to dataframe
        connections_dicts = [conn.dict() for conn in batch.connections]
        batch_df = pd.DataFrame(connections_dicts)
        
        # Preprocess the batch data
        processed_batch = preprocess_data(batch_df)
        
        # Make predictions for each connection
        results = []
        attack_counts = {}
        
        for i, row in processed_batch.iterrows():
            # Make prediction for single row
            prediction, probability, details = predict_intrusion(pd.DataFrame([row]))
            
            # Count attack types
            if prediction in attack_counts:
                attack_counts[prediction] += 1
            else:
                attack_counts[prediction] = 1
                
            # Determine if this is an alert
            alert = prediction.lower() != "normal"
            
            # Create response object
            result = {
                "prediction": prediction,
                "probability": float(probability),
                "timestamp": datetime.now().isoformat(),
                "alert": alert,
                "details": details
            }
            results.append(result)
            
            # Log each prediction asynchronously
            background_tasks.add_task(log_prediction, connections_dicts[i], prediction, float(probability), alert)
        
        # Create summary
        total_alerts = sum(1 for r in results if r["alert"])
        summary = {
            "total_connections": len(results),
            "total_alerts": total_alerts,
            "alert_percentage": (total_alerts / len(results)) * 100 if results else 0,
            "attack_distribution": attack_counts,
            "timestamp": datetime.now().isoformat()
        }
        
        return {
            "predictions": results,
            "summary": summary
        }
    except Exception as e:
        logger.error(f"Batch prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {str(e)}")

@app.get("/model/info")
async def model_info():
    """Get information about the loaded model"""
    try:
        if not os.path.exists(MODEL_PATH):
            return {
                "status": "Model not loaded",
                "model_path": MODEL_PATH,
                "exists": False
            }
        
        # Load model to get its metadata
        model = joblib.load(MODEL_PATH)
        
        # Extract model information
        model_info = {
            "model_type": type(model).__name__,
            "model_path": MODEL_PATH,
            "exists": True
        }
        
        # Add model-specific attributes if available
        if hasattr(model, 'feature_importances_'):
            model_info["has_feature_importances"] = True
        
        if hasattr(model, 'classes_'):
            model_info["classes"] = model.classes_.tolist()
        
        return model_info
    except Exception as e:
        logger.error(f"Error getting model info: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
