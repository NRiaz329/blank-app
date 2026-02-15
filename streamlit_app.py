"""
🔥 Advanced Email Verification SaaS
Admin Password: 090078601
Free Limit: 600 emails per IP / 24h
AI Risk Scoring + Dashboard + Theme Toggle Enabled
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

# =========================
# CONFIG
# =========================

ADMIN_PASSWORD = "090078601"
FREE_LIMIT = 600

# =========================
# SESSION INIT
# =========================

if "is_admin" not in st.session_state:
    st.session_state.is_admin = False

if "usage" not in st.session_state:
    st.session_state.usage = {}

if "messages" not in st.session_state:
    st.session_state.messages = []

if "history" not in st.session_state:
    st.session_state.history = []

if "theme" not in st.session_state:
    st.session_state.theme = "Light"

# =========================
# THEME SYSTEM
# =========================

def apply_theme():
    if st.session_state.theme == "Dark":
        st.markdown("""
        <style>
        body {background-color:#0E1117; color:white;}
        .stApp {background-color:#0E1117;}
        </style>
        """, unsafe_allow_html=True)

apply_theme()

# =========================
# UTILITIES
# =========================

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

# =========================
# VALIDATION CORE
# =========================

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
        server.settimeout(8)

        start_time = time.time()
        server.connect((mx_record, 25))
        server.recv(1024)

        server.send(b"EHLO example.com\r\n")
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

# =========================
# AI RISK MODEL
# =========================

def ai_score(status, response_time):
    score = 100

    if status == "INVALID":
        score = 5
    elif status == "CATCH_ALL":
        score = 45
    elif status == "RISKY":
        score = 60
    elif status == "VALID":
        score = 95

    if response_time and response_time > 5:
        score -= 10

    return max(min(score, 100), 0)

# =========================
# VERIFICATION ENGINE
# =========================

def verify_email(email):
    if not validate_syntax(email):
        result = {"email": email, "status": "INVALID", "reason": "Invalid syntax"}
    else:
        domain = email.split("@")[1]

        if not validate_mx(domain):
            result = {"email": email, "status": "INVALID", "reason": "No MX record"}
        else:
            smtp_response, response_time = smtp_probe(email)

            if smtp_response is None:
                result = {"email": email, "status": "RISKY", "reason": "SMTP failed"}
            elif "550" in smtp_response:
                result = {"email": email, "status": "INVALID", "reason": "Mailbox rejected"}
            elif "250" in smtp_response:
                fake_email = generate_fake_email(domain)
                fake_response, _ = smtp_probe(fake_email)

                if fake_response and "250" in fake_response:
                    result = {"email": email, "status": "CATCH_ALL", "reason": "Catch-all domain"}
                else:
                    result = {"email": email, "status": "VALID", "reason": "Mailbox confirmed"}
            else:
                result = {"email": email, "status": "RISKY", "reason": "Uncertain"}

    score = ai_score(result["status"], None)
    result["ai_confidence_score"] = score
    result["safe_to_send"] = score >= 85

    st.session_state.history.append(result)
    return result

# =========================
# UI
# =========================

st.title("📧 AI Email Verification Platform")

ip = get_client_ip()

page = st.sidebar.selectbox("Navigation",
    ["Dashboard", "Live Verify", "Bulk Verify", "Contact", "Q&A"])

# THEME TOGGLE
st.sidebar.markdown("### Theme")
theme_choice = st.sidebar.radio("Select Theme", ["Light", "Dark"])
st.session_state.theme = theme_choice
apply_theme()

# ADMIN LOGIN
with st.sidebar:
    if not st.session_state.is_admin:
        password = st.text_input("Admin Login", type="password")
        if password == ADMIN_PASSWORD:
            st.session_state.is_admin = True
            st.success("Admin Mode Activated")
    else:
        st.success("Admin Mode Active")
        if st.button("Logout"):
            st.session_state.is_admin = False

# =========================
# DASHBOARD
# =========================

if page == "Dashboard":
    st.header("📊 Verification Dashboard")

    df = pd.DataFrame(st.session_state.history)

    if not df.empty:
        total = len(df)
        valid = len(df[df.status == "VALID"])
        risky = len(df[df.status == "RISKY"])
        invalid = len(df[df.status == "INVALID"])
        catch_all = len(df[df.status == "CATCH_ALL"])

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Checked", total)
        col2.metric("Valid", valid)
        col3.metric("Invalid", invalid)

        st.metric("Risky", risky)
        st.metric("Catch-All", catch_all)

        st.dataframe(df)
    else:
        st.info("No verification data yet.")

# =========================
# LIVE VERIFY
# =========================

elif page == "Live Verify":
    email_input = st.text_input("Enter Email")

    if st.button("Verify"):
        if not check_rate_limit(ip):
            st.error("Free limit reached (600 / 24h)")
        else:
            with st.spinner("Verifying..."):
                result = verify_email(email_input)
            st.json(result)

# =========================
# BULK VERIFY
# =========================

elif page == "Bulk Verify":
    uploaded_file = st.file_uploader("Upload CSV (must contain 'email' column)", type=["csv"])

    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        df.columns = df.columns.str.strip().str.lower()

        if "email" in df.columns:
            results = []
            for email in df["email"].dropna():
                if not check_rate_limit(ip):
                    break
                results.append(verify_email(email))
            st.dataframe(pd.DataFrame(results))
        else:
            st.error("CSV must contain 'email' column")

    bulk_text = st.text_area("Or Paste Emails (one per line)")

    if st.button("Verify Pasted"):
        emails = [e.strip() for e in bulk_text.split("\n") if e.strip()]
        results = []
        for email in emails:
            if not check_rate_limit(ip):
                break
            results.append(verify_email(email))
        st.dataframe(pd.DataFrame(results))

# =========================
# CONTACT
# =========================

elif page == "Contact":
    name = st.text_input("Name")
    email = st.text_input("Email")
    message = st.text_area("Message")

    if st.button("Send"):
        if name and email and message:
            st.session_state.messages.append({
                "name": name,
                "email": email,
                "message": message,
                "time": datetime.utcnow()
            })
            st.success("Message sent.")
        else:
            st.warning("Fill all fields.")

    if st.session_state.is_admin:
        st.subheader("Admin Inbox")
        st.write(st.session_state.messages)

# =========================
# Q&A PAGE
# =========================

elif page == "Q&A":
    st.header("How To Use This Platform")

    st.markdown("""
    **How does it work?**
    - Enter email in Live Verify
    - Or upload CSV / paste bulk emails
    - System checks syntax, MX, SMTP
    - AI assigns confidence score

    **How many free emails?**
    - 600 emails per IP every 24 hours
    - Admin account has unlimited

    **What does AI score mean?**
    - 90–100 = Very Safe
    - 70–89 = Moderate Risk
    - Below 70 = Avoid Sending

    **Goal**
    - Prevent bounce
    - Avoid catch-all traps
    - Protect sender reputation
    """)
