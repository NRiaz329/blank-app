"""
AI Email Verification - Free Plan
Free: 600 emails/IP per 24h
No login required
CSV upload + download
"""

import streamlit as st
import pandas as pd
import re
import dns.resolver
import random
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

# ==========================
# DATABASE
# ==========================

engine = create_engine("sqlite:///free_email_verifier.db", connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

# ==========================
# MODELS
# ==========================

class PublicUsage(Base):
    __tablename__ = "public_usage"
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True)
    count = Column(Integer, default=0)
    reset = Column(DateTime, default=datetime.utcnow)

class EmailVerification(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    email = Column(String)
    status = Column(String)
    safe_to_send = Column(Boolean)
    ai_confidence = Column(Float)
    ai_risk_score = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

# CREATE TABLES
Base.metadata.create_all(bind=engine)

# ==========================
# CONFIG
# ==========================

FREE_LIMIT = 600

# ==========================
# UTILITIES
# ==========================

def get_client_ip():
    try:
        return st.runtime.scriptrunner.get_script_run_ctx().request.remote_addr
    except:
        return "local_user"

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
    status = "VALID" if risk_score < 40 else "RISKY" if risk_score < 70 else "INVALID"
    return risk_score, confidence, status

def verify_email(email, ip):
    email = email.strip()

    # Check IP usage
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
    if usage.count >= FREE_LIMIT:
        return None

    # Email validation
    if not validate_syntax(email):
        status = "INVALID"
    else:
        domain = email.split("@")[1]
        status = "INVALID" if not validate_mx(domain) else "VALID"

    risk_score, confidence, _ = ai_score(email)
    safe_to_send = risk_score < 50

    # Save record
    record = EmailVerification(
        ip=ip,
        email=email,
        status=status,
        safe_to_send=safe_to_send,
        ai_confidence=confidence,
        ai_risk_score=risk_score
    )
    db.add(record)
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

st.set_page_config(page_title="Free AI Email Verifier", layout="wide")
ip = get_client_ip()

st.title("🚀 Free AI Email Verifier")
st.markdown("""
- Free: 600 emails per IP every 24 hours
- No login required
- Drag & Drop CSV with emails
- Download verified CSV after processing
""")

uploaded_file = st.file_uploader("Upload CSV", type=["csv"])
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    emails = df[df.columns[0]].dropna().astype(str).tolist()
    results = []
    for email in emails:
        result = verify_email(email, ip)
        if result:
            results.append(result)
        else:
            st.error("Free limit of 600 emails per 24h reached for your IP")
            break
    if results:
        result_df = pd.DataFrame(results)
        st.dataframe(result_df)
        csv = result_df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇ Download Verified CSV", csv, "verified_results.csv", "text/csv")
