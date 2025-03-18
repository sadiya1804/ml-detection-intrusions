FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY data/kddcup.data_10_percent ./data/kddcup.data_10_percent

COPY . .

EXPOSE 8000

CMD ["streamlit", "run", "streamlit/app.py", "--server.port=8000", "--server.address=0.0.0.0"]