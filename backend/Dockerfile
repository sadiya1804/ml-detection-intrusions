FROM python:3.9-slim

WORKDIR /app

# Installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier les dossiers nécessaires (ajoute "data")
COPY ml ./ml
COPY api ./api
COPY data ./data
COPY data/kddcup.data_10_percent ./data/kddcup.data_10_percent
COPY models ./models
COPY models/intrusion_model.pkl ./models/intrusion_model.pkl
COPY models/intrusion_preprocessor.pkl ./models/intrusion_preprocessor.pkl
COPY scripts ./scripts


# Créer explicitement le dossier "models"
RUN mkdir -p models

# Définir PYTHONPATH
ENV PYTHONPATH=/app

# Exposer le port
EXPOSE 8000

# Lancer l'application
CMD ["python", "api/app.py"]
