# Network Intrusion Detection System - README

## Project Overview
This project implements a **Network Intrusion Detection System** using machine learning to detect anomalies in network traffic. The system consists of a **FastAPI backend** for ML predictions and a **Streamlit frontend** for visualization.

---

# Backend README

## Network Intrusion Detection System - Backend
This is the backend component of our Network Intrusion Detection System, providing a **machine learning model** for intrusion detection and a **REST API** for integration with the frontend.

### Features
- Machine learning model trained on the **KDD Cup 99 dataset**
- **REST API** for real-time prediction of network intrusions
- Comprehensive logging system for traceability
- Support for multiple attack type detection
- Preprocessing pipeline for network connection data

### Installation
Clone the repository:
```bash
git clone https://github.com/sadiya1804/ml-detection-intrusions.git
cd ml-detection-intrusions
```

Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install the required packages:
```bash
pip install -r backend/requirements.txt
```

Download the **KDD Cup 99 dataset**:
```bash
python backend/scripts/download_dataset.py
```

### Usage
Start the FastAPI server:
```bash
cd backend/api
uvicorn app:app --reload
```

The API will be available at [http://localhost:8000](http://localhost:8000)

### API Endpoints
#### `GET /`
- Health check endpoint

#### `POST /predict`
- Predict if a network connection is an intrusion
- **Request body:** JSON object with connection features
- **Response:** Prediction result with anomaly score

Example request:
```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
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
    "dst_host_count": 0,
    "dst_host_srv_count": 0,
    "dst_host_same_srv_rate": 0,
    "dst_host_diff_srv_rate": 0,
    "dst_host_same_src_port_rate": 0,
    "dst_host_srv_diff_host_rate": 0,
    "dst_host_serror_rate": 0,
    "dst_host_srv_serror_rate": 0,
    "dst_host_rerror_rate": 0,
    "dst_host_srv_rerror_rate": 0
  }'
```

### Model Information
- **Algorithm:** Random Forest Classifier
- **Training Data:** KDD Cup 99 dataset
- **Features:** 41 network connection attributes
- **Target:** Connection type (normal or specific attack type)
- **Performance:** ~99% accuracy on test data

### Dependencies
- FastAPI
- Uvicorn
- Scikit-learn
- Pandas
- NumPy
- Joblib

---

# Frontend README

## Network Intrusion Detection System - Frontend
This is the frontend component of our Network Intrusion Detection System, built with **Streamlit** to provide an interactive visualization of network traffic and anomaly detection.

### Features
- Real-time visualization of network connections
- Interactive filtering by protocol type
- Time-based filtering to focus on specific time windows
- Search functionality for specific events or attack types
- Anomaly highlighting and alerts dashboard
- Statistical overview of network traffic
- Adjustable simulation speed

### Installation
Clone the repository:
```bash
git clone https://github.com/sadiya1804/ml-detection-intrusions.git
cd ml-detection-intrusions
```

Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

Install the required packages:
```bash
pip install -r frontend/requirements.txt
```

### Usage
Make sure the backend API is running

Start the Streamlit app:
```bash
cd frontend/streamlit
streamlit run app.py
```

Open your browser and navigate to [http://localhost:8501](http://localhost:8501)

### Interface Guide
#### Sidebar Controls:
- **Simulation Mode:** Choose between real-time or replay mode
- **Replay Speed:** Adjust the speed of the simulation (in replay mode)
- **Protocol Filter:** Filter connections by protocol type
- **Time Range:** Filter to show only connections from the last X minutes
- **Search:** Find specific events by protocol, service, or attack type

#### Main Dashboard:
- **Network Traffic Visualization:** Interactive time-series plot of network traffic
- **Connection Details:** Table showing details of recent connections
- **Alerts:** List of detected anomalies with timestamps and details
- **Statistics:** Overview of connection counts, anomaly percentage, and protocol distribution

### Dependencies
- Streamlit
- Pandas
- NumPy
- Plotly
- Requests

---

## Project Structure
```
ml-detection-intrusions/
├── backend/
│   ├── api/
│   │   └── app.py
│   ├── data/
│   │   └── preprocess.py
│   ├── ml/
│   │   └── model.py
│   ├── utils/
│   │   └── logger.py
│   ├── scripts/
│   │   └── download_dataset.py
│   └── requirements.txt
├── frontend/
│   ├── streamlit/
│   │   └── app.py
│   │   └── simulation.py
|   |   └── test_mode.py
│   └── requirements.txt
├── data/
│   └── kddcup.data_10_percent
├── models/
│   ├── intrusion_model.pkl
│   └── intrusion_preprocessor.pkl
└── README.md
```

---

## Contributors
**AGAVIOS Théo, VALLA Enzo, MOHAMED SORI Alhousseini, KEBE Assa, NIANG Sadiya Alimatou**

## License
This project is licensed under the **MIT License**.
