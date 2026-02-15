streamlit
pandas
dnspython
sqlalchemy
"""
AI Email Verification SaaS
Admin Password: 090078601
Free: 600 emails/IP/24h
Streamlit Cloud Compatible Version
"""

import streamlit as st
import pandas as pd
import re
import dns.resolver
import random
import time
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker

# ==========================
# DATABASE (SQLite for Cloud)
# ==========================

engine = create_engine("sqlite:///email_verifier.db")
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

# ==========================
# MODELS
# ==========================

class EmailVerification(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True)
    email = Column(String)
    status = Column(String)
    safe_to_send = Column(Boolean)
    ai_confidence = Column(Float)
    ai_risk_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Usage(Base):
    __tablename__ = "usage"
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    count = Column(Integer, default=0)
    reset = Column(DateTime)

Base.metadata.create_all(bind=engine)

# ==========================
# CONFIG
# ==========================

ADMIN_PASSWORD = "090078601"
FREE_LIMIT = 600

if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

# ==========================
# UTILITIES
# ==========================

def get_client_ip():
    return "cloud_user"  # Streamlit Cloud safe

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

# ==========================
# LIGHTWEIGHT AI SCORING
# ==========================

def ai_score(email):
    domain_len = len(email.split("@")[1])
    local_len = len(email.split("@")[0])

    risk_score = random.uniform(10, 40)

    if domain_len < 4 or local_len < 2:
        risk_score += 30
    if any(x in email for x in ["test", "fake", "spam"]):
        risk_score += 25

    risk_score = min(risk_score, 100)
    confidence = 100 - risk_score

    if risk_score < 40:
        status = "VALID"
    elif risk_score < 70:
        status = "RISKY"
    else:
        status = "INVALID"

    return risk_score, confidence, status

def verify_email(email):
    email = email.strip()

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

    record = EmailVerification(
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
        "ai_risk_score": round(risk_score, 2),
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

# ==========================
# ADMIN PAGE
# ==========================

if st.session_state.is_admin:
    st.title("🛡 Admin Bulk Verification + AI Scoring")

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        emails = df[df.columns[0]].dropna().astype(str).tolist()

        placeholder = st.empty()
        results = []

        for i, email in enumerate(emails):
            result = verify_email(email)
            results.append(result)

            placeholder.dataframe(pd.DataFrame(results))
            st.progress((i+1)/len(emails))
            time.sleep(0.05)

# ==========================
# PUBLIC PAGE
# ==========================

else:
    st.title("📧 AI Bulk Email Verification")

    st.markdown("""
    ### Free Plan
    - 600 emails per 24h
    - CSV Upload
    - For unlimited plan: numanriaz4309@gmail.com
    """)

    uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        emails = df[df.columns[0]].dropna().astype(str).tolist()

        if not check_rate_limit(ip, len(emails)):
            st.error("Free limit exceeded (600 emails / 24h).")
        else:
            placeholder = st.empty()
            results = []

            for i, email in enumerate(emails):
                result = verify_email(email)
                results.append(result)

                placeholder.dataframe(pd.DataFrame(results))
                st.progress((i+1)/len(emails))
                time.sleep(0.05)
streamlit
pandas
dnspython
sqlalchemy
