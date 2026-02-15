"""
🔥 FIRST — BEST PROMPT FOR GITHUB (Copy This)

Enhance my Email Verification system to prioritize zero hard bounces.

Implement Conservative Safe Mode logic:

1. Only mark VALID when:
   - Syntax valid
   - MX record exists
   - SMTP returns 250 for RCPT TO
   - Not catch-all
   - Response time < 5 seconds
   - No greylisting detected

2. If:
   - Catch-all detected
   - Temporary (450, 421)
   - Greylisting
   - Timeout
   - Provider blocks verification
   → Mark as RISKY

3. If:
   - 550 or explicit rejection
   → Mark as INVALID

Add:
- Confidence score (0–100)
- Bounce risk score (0–100)
- Safe-to-send boolean flag

Goal:
Minimize hard bounces over maximizing VALID classification.
Use only DNS + raw SMTP socket logic.
"""

import streamlit as st
import pandas as pd
import re
import socket
import dns.resolver
import random
import string
import time
from datetime import datetime, timedelta

# ==============================
# CONFIG
# ==============================

ADMIN_PASSWORD = "your_super_secret_password"
FREE_LIMIT = 600

# ==============================
# SESSION INIT
# ==============================

if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

if "usage" not in st.session_state:
    st.session_state.usage = {}

# ==============================
# UTILITIES
# ==============================

def get_client_ip():
    try:
        return st.runtime.scriptrunner.get_script_run_ctx().request.remote_addr
    except:
        return "local_user"

def check_rate_limit(ip):
    if st.session_state.is_admin:
        return True

    now = datetime.utcnow()

    if ip not in st.session_state.usage:
        st.session_state.usage[ip] = {
            "count": 0,
            "reset": now + timedelta(hours=24)
        }

    data = st.session_state.usage[ip]

    if now > data["reset"]:
        st.session_state.usage[ip] = {
            "count": 0,
            "reset": now + timedelta(hours=24)
        }

    if st.session_state.usage[ip]["count"] >= FREE_LIMIT:
        return False

    st.session_state.usage[ip]["count"] += 1
    return True

# ==============================
# VALIDATION LOGIC
# ==============================

def validate_syntax(email):
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(pattern, email) is not None

def validate_mx(domain):
    try:
        return dns.resolver.resolve(domain, 'MX')
    except:
        return None

def generate_fake_email(domain):
    random_local = ''.join(random.choices(string.ascii_lowercase, k=12))
    return f"{random_local}@{domain}"

def smtp_probe(email):
    try:
        domain = email.split("@")[1]
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(records[0].exchange)

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.settimeout(10)

        start_time = time.time()
        server.connect((mx_record, 25))
        server.recv(1024)

        helo_host = f"mail{random.randint(1,999)}.example.com"
        server.send(f"EHLO {helo_host}\r\n".encode())
        server.recv(1024)

        server.send(b"MAIL FROM:<check@example.com>\r\n")
        server.recv(1024)

        server.send(f"RCPT TO:<{email}>\r\n".encode())
        response = server.recv(1024).decode()

        response_time = time.time() - start_time
        server.close()

        return response, response_time

    except:
        return None, None

# ==============================
# SAFE VERIFICATION STRATEGY
# ==============================

def verify_email(email):
    if not validate_syntax(email):
        return build_result(email, "INVALID", 100, 100, False, "Invalid syntax")

    domain = email.split("@")[1]

    if not validate_mx(domain):
        return build_result(email, "INVALID", 100, 100, False, "No MX record")

    smtp_response, response_time = smtp_probe(email)

    if smtp_response is None:
        return build_result(email, "RISKY", 80, 50, False, "SMTP connection failed")

    if "550" in smtp_response:
        return build_result(email, "INVALID", 100, 100, False, "Mailbox rejected")

    if "450" in smtp_response or "421" in smtp_response:
        return build_result(email, "RISKY", 75, 60, False, "Greylisted or temporary failure")

    if "250" in smtp_response:
        fake_email = generate_fake_email(domain)
        fake_response, _ = smtp_probe(fake_email)

        if fake_response and "250" in fake_response:
            return build_result(email, "CATCH_ALL", 70, 40, False, "Catch-all domain detected")

        if response_time and response_time < 5:
            return build_result(email, "VALID", 10, 95, True, "High confidence mailbox exists")

        return build_result(email, "RISKY", 60, 70, False, "Slow or uncertain response")

    return build_result(email, "RISKY", 60, 60, False, "Uncertain response")

def build_result(email, status, risk, confidence, safe_to_send, reason):
    return {
        "email": email,
        "status": status,
        "risk_score": risk,
        "confidence_score": confidence,
        "safe_to_send": safe_to_send,
        "reason": reason
    }

# ==============================
# UI
# ==============================

st.title("📧 Advanced Email Verification")

ip = get_client_ip()

with st.sidebar:
    if not st.session_state.is_admin:
        password = st.text_input("Admin Access", type="password")
        if password == ADMIN_PASSWORD:
            st.session_state.is_admin = True
            st.success("Admin unlocked")
    else:
        st.success("Admin Mode Active")
        if st.button("Logout"):
            st.session_state.is_admin = False

# ==============================
# SINGLE VERIFY
# ==============================

st.header("🔎 Live Email Verification")

email_input = st.text_input("Enter Email")

if st.button("Verify Email"):
    if not email_input:
        st.warning("Enter an email.")
    else:
        if not check_rate_limit(ip):
            st.error("Free limit reached (600 per 24h).")
        else:
            with st.spinner("Running deep verification..."):
                result = verify_email(email_input)
            st.json(result)

# ==============================
# BULK VERIFY
# ==============================

st.header("📂 Bulk Verification")

uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    df.columns = df.columns.str.strip().str.lower()

    if "email" not in df.columns:
        st.error("CSV must contain 'email' column.")
        st.stop()

    emails = df["email"].dropna().astype(str).str.strip().tolist()
    results = []

    for email in emails:
        if not check_rate_limit(ip):
            st.error("Free limit reached during bulk verification.")
            break
        results.append(verify_email(email))

    result_df = pd.DataFrame(results)
    st.dataframe(result_df)
