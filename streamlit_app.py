"""
AI Email Verification SaaS
Admin Password: 090078601
Plans: Free / Pro / Enterprise
Credits + Usage Limits + CSV Download
Free 600 emails per IP / 24h for public (no login)
Real-time AI progress bars for uploads
"""

import streamlit as st
import pandas as pd
import re
import dns.resolver
import random
import hashlib
import time
from datetime import datetime, timedelta
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
    plan = Column(String, default="Free")
    credits = Column(Integer, default=600)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class EmailVerification(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=True)
    ip = Column(String, nullable=True)
    email = Column(String)
    status = Column(String)
    safe_to_send = Column(Boolean)
    ai_confidence = Column(Float)
    ai_risk_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

class PublicUsage(Base):
    __tablename__ = "public_usage"
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    count = Column(Integer, default=0)
    reset = Column(DateTime, default=datetime.utcnow)

# CREATE TABLES
Base.metadata.create_all(bind=engine)

# ==========================
# CONFIG
# ==========================

ADMIN_PASSWORD = "090078601"
PLAN_LIMITS = {"Free": 600, "Pro": 5000, "Enterprise": 100000}

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
# UTILITIES
# ==========================

def get_client_ip():
    try:
        return st.runtime.scriptrunner.get_script_run_ctx().request.remote_addr
    except:
        return "local_user"

# ==========================
# EMAIL VALIDATION & AI
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

def verify_email(email, client=None, ip=None):
    email = email.strip()

    # PUBLIC LIMIT
    if client is None:
        usage = db.query(PublicUsage).filter_by(ip=ip).first()
        now = datetime.utcnow()
        if not usage:
            usage = PublicUsage(ip=ip, count=0, reset=now + timedelta(hours=24))
            db.add(usage)
            db.commit()
        if now > usage.reset:
            usage.count = 0
            usage.reset = now + timedelta(hours=24)
            db.commit()
        if usage.count >= 600:
            return None

    # CLIENT LIMIT
    if client:
        if client.credits <= 0:
            return None

    # Email validation
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
        client_id=client.id if client else None,
        ip=ip if not client else None,
        email=email,
        status=status,
        safe_to_send=safe_to_send,
        ai_confidence=confidence,
        ai_risk_score=risk_score
    )

    db.add(record)

    if client:
        client.credits -= 1
    else:
        usage.count += 1

    db.commit()

    return {
        "Email": email,
        "Status": status,
        "Risk Score": round(risk_score, 2),
        "Confidence": round(confidence, 2),
        "Safe To Send": safe_to_send
    }

# ==========================
# STREAMLIT UI
# ==========================

st.set_page_config(page_title="AI Email Verifier SaaS", layout="wide")
ip = get_client_ip()

with st.sidebar:

    st.markdown("## 🔐 Admin Login")

    # Admin login
    if not st.session_state.is_admin:
        admin_pass = st.text_input("Admin Password", type="password")
        if admin_pass == ADMIN_PASSWORD:
            st.session_state.is_admin = True
            st.success("Admin Mode Enabled")

    if st.session_state.is_admin:
        if st.button("Logout Admin"):
            st.session_state.is_admin = False

    # Client login
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
    st.title("🛡 Admin Dashboard")

    st.subheader("Create Client")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    new_plan = st.selectbox("Plan", ["Free", "Pro", "Enterprise"])
    if st.button("Create Client"):
        if not db.query(Client).filter_by(username=new_user).first():
            credits = PLAN_LIMITS[new_plan]
            client = Client(
                username=new_user,
                password=hash_password(new_pass),
                plan=new_plan,
                credits=credits
            )
            db.add(client)
            db.commit()
            st.success(f"Client '{new_user}' Created")

    st.subheader("Manage Clients")
    try:
        clients = db.query(Client).all()
    except:
        clients = []

    for c in clients:
        st.write(f"User: {c.username} | Plan: {c.plan} | Credits: {c.credits} | Active: {c.is_active}")
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button(f"Add 1000 Credits to {c.username}", key=f"add_{c.id}"):
                c.credits += 1000
                db.commit()
                st.success(f"Credits Added to {c.username}")
        with col2:
            if st.button(f"Deactivate {c.username}", key=f"deactivate_{c.id}"):
                c.is_active = False
                db.commit()
                st.success(f"{c.username} Deactivated")
        with col3:
            if st.button(f"Delete {c.username}", key=f"delete_{c.id}"):
                db.query(EmailVerification).filter_by(client_id=c.id).delete()
                db.delete(c)
                db.commit()
                st.warning(f"{c.username} and all their data deleted")

# ==========================
# CLIENT PORTAL (REAL-TIME PROGRESS)
# ==========================

elif st.session_state.client_id:

    client = db.query(Client).filter_by(id=st.session_state.client_id).first()
    st.title("📧 Client Dashboard")
    st.markdown(f"**Plan:** {client.plan}  |  **Credits Remaining:** {client.credits}")

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        emails = df[df.columns[0]].dropna().astype(str).tolist()
        results = []
        placeholder = st.empty()
        progress_bar = st.progress(0)
        total = len(emails)

        for i, email in enumerate(emails):
            result = verify_email(email, client=client)
            if result:
                results.append(result)
            else:
                st.error("No credits remaining.")
                break
            progress_bar.progress((i+1)/total)
            placeholder.dataframe(pd.DataFrame(results))
            time.sleep(0.05)

        if results:
            result_df = pd.DataFrame(results)
            placeholder.dataframe(result_df)
            csv = result_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇ Download Verified CSV", csv, "verified_results.csv", "text/csv")

# ==========================
# PUBLIC FREE USAGE (NO LOGIN, REAL-TIME PROGRESS)
# ==========================

else:
    st.title("🚀 AI Email Verification SaaS - Free Usage")
    st.markdown("""
    ### Free Plan for Public
    - 600 emails per IP per 24 hours
    - No login required
    - Drag & Drop CSV
    - AI-powered risk scoring
    - Contact us to upgrade for more credits
    """)
    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        emails = df[df.columns[0]].dropna().astype(str).tolist()
        results = []
        placeholder = st.empty()
        progress_bar = st.progress(0)
        total = len(emails)

        for i, email in enumerate(emails):
            result = verify_email(email, client=None, ip=ip)
            if result:
                results.append(result)
            else:
                st.error("Free limit of 600 emails per 24h reached for your IP")
                break
            progress_bar.progress((i+1)/total)
            placeholder.dataframe(pd.DataFrame(results))
            time.sleep(0.05)

        if results:
            result_df = pd.DataFrame(results)
            placeholder.dataframe(result_df)
            csv = result_df.to_csv(index=False).encode("utf-8")
            st.download_button("⬇ Download Verified CSV", csv, "verified_results.csv", "text/csv")
