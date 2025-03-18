# backend/api/app.py
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
        if not (os.path.exists('./models/intrusion_model.pkl') and 
                os.path.exists('./models/intrusion_preprocessor.pkl')):
            logger.info("Training new model...")
            detector.train('./data/kddcup.data_10_percent')
            detector.save_model('./models/intrusion_model.pkl', 
                               './models/intrusion_preprocessor.pkl')
        else:
            logger.info("Loading existing model...")
            detector.load_model('./models/intrusion_model.pkl', 
                               './models/intrusion_preprocessor.pkl')
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
        
        # Make prediction
        result = detector.predict(df)
        
        # Log the prediction
        logger.info(f"Prediction made: {result['prediction'][0]}")
        
        return {
            "prediction": result['prediction'][0],
            "anomaly_score": result['anomaly_score'][0],
            "probabilities": result['probabilities'][0]
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
