"""
AI Email Verification SaaS
Admin Password: 090078601
Free: 600 emails/IP/24h
AI Scoring with Risk Prediction + Real-Time Progress
"""

import streamlit as st
import pandas as pd
import re
import socket
import dns.resolver
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import time

# ==========================
# DATABASE CONFIG
# ==========================

DB_URL = "postgresql://postgres:password@localhost:5432/email_verifier"
engine = create_engine(DB_URL)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

# ==========================
# DB MODELS
# ==========================

class EmailVerification(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    status = Column(String)
    safe_to_send = Column(Boolean)
    ai_confidence = Column(Float)
    ai_risk_score = Column(Float)
    ai_pred_status = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Usage(Base):
    __tablename__ = "usage"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)
    count = Column(Integer, default=0)
    reset = Column(DateTime)

Base.metadata.create_all(bind=engine)

# ==========================
# CONFIG
# ==========================

ADMIN_PASSWORD = "090078601"
FREE_LIMIT = 600
MAX_FILE_SIZE_MB = 200

if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

# ==========================
# UTILITIES
# ==========================

def get_client_ip():
    try:
        return st.runtime.scriptrunner.get_script_run_ctx().request.remote_addr
    except:
        return "local_user"

def check_rate_limit(ip, amount):
    if st.session_state.is_admin:
        return True

    usage = db.query(Usage).filter_by(ip=ip).first()
    now = datetime.utcnow()

    if not usage:
        usage = Usage(ip=ip, count=0, reset=now + timedelta(hours=24))
        db.add(usage)
        db.commit()

    if now > usage.reset:
        usage.count = 0
        usage.reset = now + timedelta(hours=24)
        db.commit()

    if usage.count + amount > FREE_LIMIT:
        return False

    usage.count += amount
    db.commit()
    return True

# ==========================
# EMAIL VERIFICATION
# ==========================

def validate_syntax(email):
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(pattern, email) is not None

def validate_mx(domain):
    try:
        return dns.resolver.resolve(domain, 'MX')
    except:
        return None

def smtp_probe(email):
    try:
        domain = email.split("@")[1]
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(records[0].exchange)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.settimeout(8)
        server.connect((mx_record, 25))
        server.recv(1024)
        server.send(b"EHLO example.com\r\n")
        server.recv(1024)
        server.send(b"MAIL FROM:<check@example.com>\r\n")
        server.recv(1024)
        server.send(f"RCPT TO:<{email}>\r\n".encode())
        response = server.recv(1024).decode()
        server.close()
        return response
    except:
        return None

# ==========================
# AI SCORING
# ==========================

def train_ai_model():
    df = pd.read_sql(db.query(EmailVerification).statement, db.bind)
    if df.empty:
        return None, None
    df['domain_len'] = df['email'].apply(lambda x: len(x.split('@')[1]))
    df['local_len'] = df['email'].apply(lambda x: len(x.split('@')[0]))
    df['status_encoded'] = LabelEncoder().fit_transform(df['status'])
    X = df[['domain_len', 'local_len']]
    y = df['status_encoded']
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    label_map = dict(zip(df['status_encoded'], df['status']))
    return model, label_map

def ai_predict(email, model, label_map):
    if model is None:
        return 50.0, 0.5, "RISKY"
    domain_len = len(email.split("@")[1])
    local_len = len(email.split("@")[0])
    X = [[domain_len, local_len]]
    pred_encoded = model.predict(X)[0]
    pred_proba = max(model.predict_proba(X)[0])
    pred_status = label_map.get(pred_encoded, "RISKY")
    risk_score = 100 - (pred_proba*100)
    confidence = pred_proba*100
    return risk_score, confidence, pred_status

def verify_email(email, model=None, label_map=None):
    email = email.strip()
    if not validate_syntax(email):
        status = "INVALID"
    else:
        domain = email.split("@")[1]
        if not validate_mx(domain):
            status = "INVALID"
        else:
            response = smtp_probe(email)
            if response is None:
                status = "RISKY"
            elif "550" in response:
                status = "INVALID"
            elif "250" in response:
                status = "VALID"
            else:
                status = "RISKY"

    risk_score, confidence, ai_status = ai_predict(email, model, label_map)
    safe_to_send = risk_score < 50

    record = EmailVerification(
        email=email,
        status=status,
        safe_to_send=safe_to_send,
        ai_confidence=confidence,
        ai_risk_score=risk_score,
        ai_pred_status=ai_status
    )
    db.add(record)
    db.commit()

    return {
        "email": email,
        "status": status,
        "safe_to_send": safe_to_send,
        "ai_confidence": round(confidence,2),
        "ai_risk_score": round(risk_score,2),
        "ai_pred_status": ai_status
    }

# ==========================
# UI
# ==========================

st.set_page_config(page_title="AI Email Verifier", layout="wide")
ip = get_client_ip()

with st.sidebar:
    st.markdown("## 🔐 Admin Access")
    if not st.session_state.is_admin:
        password = st.text_input("Enter Admin Password", type="password")
        if password == ADMIN_PASSWORD:
            st.session_state.is_admin = True
            st.success("Admin Mode Enabled")
    else:
        st.success("Admin Panel Active")
        if st.button("Logout"):
            st.session_state.is_admin = False

# Train AI
model, label_map = train_ai_model()

# ==========================
# ADMIN PAGE
# ==========================
if st.session_state.is_admin:
    st.title("🛡 Admin Bulk Verification + Real-Time AI Scoring")
    uploaded_file = st.file_uploader("Upload CSV (Any Size)", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        email_column = df.columns[0]
        emails = df[email_column].dropna().astype(str).tolist()
        
        placeholder = st.empty()
        results_list = []
        
        for i, email in enumerate(emails):
            result = verify_email(email, model, label_map)
            results_list.append(result)
            
            # Real-time display
            progress = (i+1)/len(emails)
            placeholder.dataframe(pd.DataFrame(results_list))
            st.progress(progress)
            st.write(f"Processing {i+1}/{len(emails)}: {email} → {result['status']} | AI Risk {result['ai_risk_score']:.1f} | Confidence {result['ai_confidence']:.1f}")
            
            time.sleep(0.1)  # simulate delay for demo

# ==========================
# PUBLIC PAGE
# ==========================
else:
    st.title("📧 AI Bulk Email Verification")
    st.markdown("""
    ### Free Plan
    - 600 emails per IP every 24h
    - Drag & Drop CSV up to 200MB
    - For unlimited verification contact: **numanriaz4309@gmail.com**
    """)
    uploaded_file = st.file_uploader("Drag & Drop CSV (Max 200MB)", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        email_column = df.columns[0]
        emails = df[email_column].dropna().astype(str).tolist()
        if not check_rate_limit(ip, len(emails)):
            st.error("Free limit exceeded (600 emails / 24h).")
        else:
            placeholder = st.empty()
            results_list = []
            for i, email in enumerate(emails):
                result = verify_email(email, model, label_map)
                results_list.append(result)
                progress = (i+1)/len(emails)
                placeholder.dataframe(pd.DataFrame(results_list))
                st.progress(progress)
                st.write(f"Processing {i+1}/{len(emails)}: {email} → {result['status']} | AI Risk {result['ai_risk_score']:.1f} | Confidence {result['ai_confidence']:.1f}")
                time.sleep(0.1)
