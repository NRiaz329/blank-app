import streamlit as st
import pandas as pd
import re
import dns.resolver
import random
import hashlib
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

# ==========================
# DATABASE
# ==========================

engine = create_engine("sqlite:///email_verifier.db", connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

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
    ip = Column(String, unique=True)
    count = Column(Integer, default=0)
    reset = Column(DateTime, default=datetime.utcnow)

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

# ==========================
# VERIFY EMAIL (safe)
# ==========================

def verify_email(email, session, client=None, ip=None):
    email = email.strip()
    now = datetime.utcnow()

    # PUBLIC LIMIT
    if client is None:
        usage = session.query(PublicUsage).filter_by(ip=ip).first()
        if not usage:
            usage = PublicUsage(ip=ip, count=0, reset=now + timedelta(hours=24))
            session.add(usage)
            session.commit()  # commit new usage record
        elif now > usage.reset:
            usage.count = 0
            usage.reset = now + timedelta(hours=24)
        if usage.count >= 600:
            return None

    # CLIENT LIMIT
    if client and client.credits <= 0:
        return None

    # Validate email syntax & MX
    if not validate_syntax(email):
        status = "INVALID"
    else:
        domain = email.split("@")[1]
        if not validate_mx(domain):
            status = "INVALID"
        else:
            status = "VALID"

    risk_score, confidence, ai_status = ai_score(email)
    safe_to_send = risk_score < 50

    # Safe DB transaction using session.begin()
    with session.begin():
        record = EmailVerification(
            client_id=client.id if client else None,
            ip=ip if not client else None,
            email=email,
            status=status,
            safe_to_send=safe_to_send,
            ai_confidence=confidence,
            ai_risk_score=risk_score
        )
        session.add(record)

        if client:
            client.credits -= 1
        else:
            usage.count += 1

    return {
        "Email": email,
        "Status": status,
        "AI Prediction": ai_status,
        "Risk Score": round(risk_score, 2),
        "Confidence": round(confidence, 2),
        "Safe To Send": safe_to_send
    }

# ==========================
# STREAMLIT UI
# ==========================

st.set_page_config(page_title="AI Email Verifier SaaS", layout="wide")
ip = get_client_ip()
session = SessionLocal()

# SHOW PLAN LIMITS
st.markdown("## 📋 Plans & Limits")
st.markdown("""
| Plan        | Daily Email Limit |
|------------|----------------|
| Free       | 600 emails/IP per 24h (public no-login) |
| Pro        | 5,000 emails per client account |
| Enterprise | 100,000 emails per client account |
""")
st.markdown("---")

# --------------------------
# SIDEBAR: LOGIN / ADMIN
# --------------------------
with st.sidebar:
    st.markdown("## 🔐 Admin Login")
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
            client = session.query(Client).filter_by(
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
        if not session.query(Client).filter_by(username=new_user).first():
            credits = PLAN_LIMITS[new_plan]
            client = Client(
                username=new_user,
                password=hash_password(new_pass),
                plan=new_plan,
                credits=credits
            )
            session.add(client)
            session.commit()
            st.success(f"Client '{new_user}' Created")

# ==========================
# CLIENT / PUBLIC CSV PROCESSING
# ==========================

def process_csv(uploaded_file, client=None, ip=None):
    df = pd.read_csv(uploaded_file)
    emails = df[df.columns[0]].dropna().astype(str).tolist()
    results = []
    placeholder = st.empty()
    progress_bar = st.progress(0)

    for i, email in enumerate(emails):
        result = verify_email(email, session=session, client=client, ip=ip)
        if result:
            results.append(result)
            color = "green" if result["AI Prediction"]=="VALID" else "orange" if result["AI Prediction"]=="RISKY" else "red"
            placeholder.markdown(f"{i+1}/{len(emails)} → <span style='color:{color}'>{result['Email']} | {result['AI Prediction']} | Risk: {result['Risk Score']}%</span>", unsafe_allow_html=True)
        else:
            if client:
                st.error("No credits remaining.")
            else:
                st.error("Free limit reached for your IP")
            break
        progress_bar.progress((i+1)/len(emails))

    if results:
        result_df = pd.DataFrame(results)
        st.dataframe(result_df)
        csv = result_df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇ Download Verified CSV", csv, "verified_results.csv", "text/csv")

# ==========================
# CLIENT PORTAL
# ==========================
if st.session_state.client_id:
    client = session.query(Client).filter_by(id=st.session_state.client_id).first()
    st.title("📧 Client Dashboard")
    st.markdown(f"**Plan:** {client.plan}  |  **Credits Remaining:** {client.credits}")
    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded_file:
        process_csv(uploaded_file, client=client)

# ==========================
# PUBLIC FREE USAGE
# ==========================
elif not st.session_state.client_id and not st.session_state.is_admin:
    st.title("🚀 AI Email Verification SaaS - Free Usage")
    st.markdown("### Free Plan: 600 emails per IP / 24h, no login")
    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded_file:
        process_csv(uploaded_file, client=None, ip=ip)
