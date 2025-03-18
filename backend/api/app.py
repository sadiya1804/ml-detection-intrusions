from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import sys
import os
import logging

sys.path.append('..')
from ml.model import IntrusionDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Intrusion Detection API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Initialize detector
detector = IntrusionDetector()

@app.on_event("startup")
async def startup_event():
    try:
        # Check if model exists, if not train it
        if not (os.path.exists('../models/intrusion_model.pkl') and 
                os.path.exists('../models/intrusion_preprocessor.pkl')):
            logger.info("Training new model...")
            detector.train('../data/kddcup.data_10_percent')
            detector.save_model('../models/intrusion_model.pkl', 
                               '../models/intrusion_preprocessor.pkl')
        else:
            logger.info("Loading existing model...")
            detector.load_model('../models/intrusion_model.pkl', 
                               '../models/intrusion_preprocessor.pkl')
    except Exception as e:
        logger.error(f"Error during startup: {str(e)}")
        raise

@app.get("/")
def read_root():
    return {"message": "Intrusion Detection API is running"}

@app.post("/predict")
def predict_intrusion(connection_data: dict):
    try:
        # Convert input data to DataFrame
        df = pd.DataFrame([connection_data])
        
        # Log the incoming connection
        logger.info(f"Analyzing connection: {connection_data['protocol_type']} - {connection_data['service']}")
        
        # Make prediction
        result = detector.predict(df)
        
        # Get the raw prediction and probabilities
        raw_prediction = result['prediction'][0]
        probabilities = result['probabilities'][0]
        anomaly_score = result['anomaly_score'][0]
        
        # Use a lower threshold for attack detection
        # If normal probability is less than 90%, consider it suspicious
        normal_idx = list(detector.model.classes_).index('normal.')
        normal_prob = probabilities[normal_idx]
        
        # If normal probability is below threshold, find the most likely attack
        if normal_prob < 0.90:
            # Find the attack class with highest probability
            attack_probs = [(cls, prob) for i, (cls, prob) in 
                           enumerate(zip(detector.model.classes_, probabilities)) 
                           if cls != 'normal.']
            most_likely_attack = max(attack_probs, key=lambda x: x[1])
            adjusted_prediction = most_likely_attack[0]
            logger.info(f"Adjusted prediction: {adjusted_prediction} (normal prob: {normal_prob:.4f})")
        else:
            adjusted_prediction = raw_prediction
        
        # Log the prediction
        logger.info(f"Prediction made: {raw_prediction}, Score: {anomaly_score:.4f}")
        
        return {
            "prediction": adjusted_prediction,
            "raw_prediction": raw_prediction,
            "anomaly_score": anomaly_score,
            "probabilities": probabilities,
            "normal_probability": normal_prob
        }
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
