from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np
from typing import List

# Créer une instance de FastAPI
app = FastAPI()

# Charger ton modèle pré-entraîné
model = joblib.load("path_to_your_trained_model.pkl")  # Remplace par ton modèle

# Définir un schéma de données d'entrée
class InputData(BaseModel):
    features: List[float]  # Liste des valeurs des features

# Définir une route de prédiction
@app.post("/predict/")
async def predict(data: InputData):
    # Convertir les données reçues en numpy array
    features = np.array(data.features).reshape(1, -1)
    
    # Faire la prédiction avec le modèle
    prediction = model.predict(features)
    
    # Retourner la prédiction dans la réponse
    return {"prediction": prediction.tolist()}

# Lancer l'application avec Uvicorn
