import streamlit as st

st.title("🎈 My new app")
st.write(
    "Let's start building! For help and inspiration, head over to [docs.streamlit.io](https://docs.streamlit.io/)."
)
bash <(cat <<'EOF'
set -e

echo "Installing dependencies..."
sudo apt update -y
sudo apt install -y docker.io docker-compose git curl

mkdir -p email-saas/backend/app/{api,services,core}
mkdir -p email-saas/frontend
cd email-saas

############################################
# DOCKER COMPOSE
############################################
cat > docker-compose.yml <<'DC'
version: "3.9"
services:
  api:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
    depends_on:
      - postgres
      - redis

  worker:
    build: .
    command: celery -A backend.app.worker.celery worker --loglevel=info --concurrency=4
    env_file:
      - .env
    depends_on:
      - redis

  retrain:
    build: .
    command: python backend/app/services/train.py
    env_file:
      - .env
    depends_on:
      - postgres

  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: emaildb

  redis:
    image: redis:7
DC

############################################
# DOCKERFILE
############################################
cat > Dockerfile <<'DF'
FROM python:3.11
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
DF

############################################
# ENV
############################################
cat > .env <<'ENV'
DATABASE_URL=postgresql://postgres:postgres@postgres:5432/emaildb
REDIS_URL=redis://redis:6379/0
ENV

############################################
# REQUIREMENTS
############################################
cat > backend/requirements.txt <<'REQ'
fastapi
uvicorn
sqlalchemy
psycopg2-binary
redis
celery
dnspython
python-whois
xgboost
scikit-learn
joblib
python-dotenv
python-multipart
REQ

############################################
# CONFIG
############################################
cat > backend/app/core/config.py <<'PY'
import os
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
PY

############################################
# DATABASE
############################################
cat > backend/app/core/database.py <<'PY'
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import DATABASE_URL

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
PY

############################################
# MODELS
############################################
cat > backend/app/core/models.py <<'PY'
from sqlalchemy import Column, Integer, String, Float, Boolean
from .database import Base

class EmailLog(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True)
    email = Column(String, index=True)
    status = Column(String)
    risk_score = Column(Float)
    confidence_score = Column(Float)
    catch_all = Column(Boolean)
PY

############################################
# SMTP SERVICE
############################################
cat > backend/app/services/smtp_service.py <<'PY'
import socket, dns.resolver, random

def get_mx(domain):
    try:
        return str(dns.resolver.resolve(domain,'MX')[0].exchange)
    except:
        return None

def smtp_check(email):
    domain = email.split("@")[1]
    mx = get_mx(domain)
    if not mx:
        return "550"
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((mx,25))
        s.recv(1024)
        s.send(f"EHLO mail{random.randint(100,999)}.local\r\n".encode())
        s.recv(1024)
        s.send(b"MAIL FROM:<verify@local.com>\r\n")
        s.recv(1024)
        s.send(f"RCPT TO:<{email}>\r\n".encode())
        r = s.recv(1024).decode()
        s.close()
        return r
    except:
        return "450"
PY

############################################
# FEATURE ENGINE
############################################
cat > backend/app/services/feature_engine.py <<'PY'
import math

def entropy(s):
    prob = [float(s.count(c))/len(s) for c in dict.fromkeys(list(s))]
    return -sum([p*math.log(p)/math.log(2.0) for p in prob])

def build(email, smtp_code):
    local = email.split("@")[0]
    return {
        "length": len(local),
        "entropy": entropy(local),
        "smtp_flag": 1 if "250" in smtp_code else 0
    }
PY

############################################
# AI SCORING
############################################
cat > backend/app/services/scoring.py <<'PY'
import os, joblib
MODEL="backend/app/services/model.pkl"

def score(features):
    if os.path.exists(MODEL):
        model=joblib.load(MODEL)
        prob=model.predict_proba([[features["length"],features["entropy"],features["smtp_flag"]]])[0][1]
    else:
        prob=0.2 if features["smtp_flag"]==1 else 0.7

    risk=int(prob*100)
    status="VALID" if risk<30 else "RISKY" if risk<60 else "INVALID"
    confidence=abs(50-risk)*2
    return status,risk,confidence
PY

############################################
# TRAIN SCRIPT
############################################
cat > backend/app/services/train.py <<'PY'
import pandas as pd
import xgboost as xgb
import joblib
import random

data=[]
for _ in range(500):
    length=random.randint(3,15)
    entropy=random.random()*3
    smtp=random.randint(0,1)
    label=0 if smtp==1 and entropy<2 else 1
    data.append([length,entropy,smtp,label])

df=pd.DataFrame(data,columns=["length","entropy","smtp","label"])
X=df[["length","entropy","smtp"]]
y=df["label"]

model=xgb.XGBClassifier(n_estimators=200,max_depth=4)
model.fit(X,y)
joblib.dump(model,"backend/app/services/model.pkl")
print("Model trained")
PY

############################################
# WORKER
############################################
cat > backend/app/worker.py <<'PY'
from celery import Celery
from .core.config import REDIS_URL
from .services.smtp_service import smtp_check
from .services.feature_engine import build
from .services.scoring import score

celery=Celery("worker",broker=REDIS_URL)

@celery.task
def verify_email(email):
    smtp_code=smtp_check(email)
    features=build(email,smtp_code)
    status,risk,confidence=score(features)
    return {"status":status,"risk_score":risk,"confidence_score":confidence}
PY

############################################
# API
############################################
cat > backend/app/main.py <<'PY'
from fastapi import FastAPI, WebSocket, UploadFile, File
from .worker import verify_email

app=FastAPI()

@app.post("/api/verify")
def verify(email:str):
    return verify_email.delay(email).get()

@app.post("/api/bulk")
async def bulk(file:UploadFile=File(...)):
    content=await file.read()
    emails=content.decode().splitlines()
    results=[]
    for e in emails:
        results.append(verify_email.delay(e).get())
    return results

@app.websocket("/ws")
async def ws(ws:WebSocket):
    await ws.accept()
    data=await ws.receive_json()
    result=verify_email.delay(data["email"]).get()
    await ws.send_json(result)
PY

############################################
# FRONTEND
############################################
cat > frontend/index.html <<'HTML'
<!DOCTYPE html>
<html>
<head><title>Email SaaS</title></head>
<body>
<h2>Email Verifier</h2>
<input id="email">
<button onclick="v()">Verify</button>
<div id="out"></div>
<script>
function v(){
 let ws=new WebSocket("ws://localhost:8000/ws");
 ws.onopen=()=>ws.send(JSON.stringify({email:document.getElementById("email").value}));
 ws.onmessage=e=>document.getElementById("out").innerHTML=JSON.stringify(JSON.parse(e.data),null,2);
}
</script>
</body>
</html>
HTML

############################################
# START
############################################
docker-compose up --build -d

echo "======================================"
echo "RUNNING"
echo "API: http://localhost:8000/docs"
echo "Frontend: open frontend/index.html"
echo "======================================"
EOF
)
