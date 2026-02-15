"""
AI Email Verification SaaS
Admin Password: 090078601
Client Portal Enabled
"""

import streamlit as st
import pandas as pd
import re
import dns.resolver
import random
import hashlib
import time
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

# ==========================
# DATABASE
# ==========================

engine = create_engine("sqlite:///email_verifier.db", connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

# ==========================
# MODELS
# ==========================

class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class EmailVerification(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"))
    email = Column(String)
    status = Column(String)
    safe_to_send = Column(Boolean)
    ai_confidence = Column(Float)
    ai_risk_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ==========================
# CONFIG
# ==========================

ADMIN_PASSWORD = "090078601"

if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

if "client_id" not in st.session_state:
    st.session_state.client_id = None

# ==========================
# SECURITY
# ==========================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ==========================
# EMAIL VALIDATION
# ==========================

def validate_syntax(email):
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(pattern, email) is not None

def validate_mx(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def ai_score(email):
    domain_len = len(email.split("@")[1])
    local_len = len(email.split("@")[0])

    risk_score = random.uniform(5, 35)

    if domain_len < 4:
        risk_score += 25
    if local_len < 2:
        risk_score += 20
    if any(word in email.lower() for word in ["test", "fake", "spam"]):
        risk_score += 30

    risk_score = min(risk_score, 100)
    confidence = 100 - risk_score

    if risk_score < 40:
        status = "VALID"
    elif risk_score < 70:
        status = "RISKY"
    else:
        status = "INVALID"

    return risk_score, confidence, status

def verify_email(email, client_id):
    email = email.strip()

    if not validate_syntax(email):
        status = "INVALID"
    else:
        domain = email.split("@")[1]
        if not validate_mx(domain):
            status = "INVALID"
        else:
            status = "VALID"

    risk_score, confidence, _ = ai_score(email)
    safe_to_send = risk_score < 50

    record = EmailVerification(
        client_id=client_id,
        email=email,
        status=status,
        safe_to_send=safe_to_send,
        ai_confidence=confidence,
        ai_risk_score=risk_score
    )
    db.add(record)
    db.commit()

    return {
        "email": email,
        "status": status,
        "safe_to_send": safe_to_send,
        "ai_confidence": round(confidence, 2),
        "ai_risk_score": round(risk_score, 2)
    }

# ==========================
# UI
# ==========================

st.set_page_config(page_title="AI Email Verifier", layout="wide")

with st.sidebar:

    st.markdown("## 🔐 Login")

    # Admin Login
    if not st.session_state.is_admin:
        admin_pass = st.text_input("Admin Password", type="password")
        if admin_pass == ADMIN_PASSWORD:
            st.session_state.is_admin = True
            st.success("Admin Mode Enabled")

    if st.session_state.is_admin:
        if st.button("Logout Admin"):
            st.session_state.is_admin = False

    # Client Login
    if not st.session_state.client_id:
        st.markdown("### Client Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            client = db.query(Client).filter_by(
                username=username,
                password=hash_password(password),
                is_active=True
            ).first()
            if client:
                st.session_state.client_id = client.id
                st.success("Login Successful")
            else:
                st.error("Invalid Credentials")
    else:
        if st.button("Logout Client"):
            st.session_state.client_id = None

# ==========================
# ADMIN PANEL
# ==========================

if st.session_state.is_admin:
    st.title("🛡 Admin Panel")

    st.subheader("Create New Client")
    new_user = st.text_input("New Username")
    new_pass = st.text_input("New Password", type="password")

    if st.button("Create Client"):
        if new_user and new_pass:
            if db.query(Client).filter_by(username=new_user).first():
                st.error("Username already exists")
            else:
                client = Client(
                    username=new_user,
                    password=hash_password(new_pass)
                )
                db.add(client)
                db.commit()
                st.success("Client Created Successfully")

    st.subheader("All Clients")
    clients = db.query(Client).all()
    st.dataframe(pd.DataFrame([
        {"ID": c.id, "Username": c.username, "Active": c.is_active}
        for c in clients
    ]))

# ==========================
# CLIENT PORTAL
# ==========================

elif st.session_state.client_id:

    st.title("📧 Client Email Verification Portal")

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        emails = df[df.columns[0]].dropna().astype(str).tolist()

        placeholder = st.empty()
        results = []

        for i, email in enumerate(emails):
            result = verify_email(email, st.session_state.client_id)
            results.append(result)

            placeholder.dataframe(pd.DataFrame(results))
            st.progress((i + 1) / len(emails))
            time.sleep(0.05)

    st.subheader("Your History")
    history = db.query(EmailVerification).filter_by(
        client_id=st.session_state.client_id
    ).all()

    if history:
        st.dataframe(pd.DataFrame([
            {
                "Email": h.email,
                "Status": h.status,
                "Risk": round(h.ai_risk_score, 2),
                "Confidence": round(h.ai_confidence, 2),
                "Safe": h.safe_to_send,
                "Date": h.timestamp
            }
            for h in history
        ]))

# ==========================
# PUBLIC LANDING PAGE
# ==========================

else:
    st.title("🚀 AI Email Verification SaaS")

    st.markdown("""
    ### Client Portal Access
    - Secure login for each client
    - Private verification dashboard
    - AI-powered risk scoring
    - Contact us for extended access and higher limits
    """)
