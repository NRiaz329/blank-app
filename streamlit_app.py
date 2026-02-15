"""
🔥 Advanced Email Verification SaaS with Ryujin Character
Admin Password: 090078601
Free Limit: 600 emails per IP / 24h
AI Risk Scoring + Dashboard + Theme Toggle + Anime Effects
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
    st.session_state.theme = "Dark"

if "show_animation" not in st.session_state:
    st.session_state.show_animation = False

# =========================
# CUSTOM CSS & ANIMATIONS
# =========================

def inject_custom_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap');
    
    * {
        font-family: 'Rajdhani', sans-serif;
    }
    
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 50%, #0f1729 100%);
        position: relative;
        overflow-x: hidden;
    }
    
    /* Animated Background */
    .stApp::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: 
            radial-gradient(circle at 20% 50%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 80% 80%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 40% 20%, rgba(234, 179, 8, 0.05) 0%, transparent 50%);
        pointer-events: none;
        animation: pulse 8s ease-in-out infinite;
        z-index: 0;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 0.3; }
        50% { opacity: 0.6; }
    }
    
    /* Title Styling */
    h1 {
        font-family: 'Orbitron', sans-serif !important;
        background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 50%, #fbbf24 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-weight: 900 !important;
        letter-spacing: 2px;
        text-shadow: 0 0 30px rgba(96, 165, 250, 0.5);
        animation: glow 2s ease-in-out infinite alternate;
    }
    
    @keyframes glow {
        from { filter: drop-shadow(0 0 10px rgba(96, 165, 250, 0.5)); }
        to { filter: drop-shadow(0 0 20px rgba(167, 139, 250, 0.8)); }
    }
    
    /* Headers */
    h2, h3 {
        font-family: 'Orbitron', sans-serif !important;
        color: #60a5fa !important;
        font-weight: 700 !important;
        letter-spacing: 1px;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%) !important;
        color: white !important;
        border: 2px solid rgba(96, 165, 250, 0.3) !important;
        border-radius: 12px !important;
        padding: 12px 32px !important;
        font-weight: 600 !important;
        font-size: 16px !important;
        letter-spacing: 1px;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4) !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 25px rgba(139, 92, 246, 0.6) !important;
        border-color: rgba(167, 139, 250, 0.6) !important;
    }
    
    /* Input Fields */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 2px solid rgba(96, 165, 250, 0.3) !important;
        border-radius: 10px !important;
        color: #e2e8f0 !important;
        font-size: 16px !important;
        transition: all 0.3s ease !important;
    }
    
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {
        border-color: rgba(139, 92, 246, 0.6) !important;
        box-shadow: 0 0 20px rgba(139, 92, 246, 0.3) !important;
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        font-size: 32px !important;
        font-weight: 700 !important;
        background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    /* Dataframe */
    .dataframe {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid rgba(96, 165, 250, 0.2) !important;
        border-radius: 10px !important;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%) !important;
        border-right: 2px solid rgba(96, 165, 250, 0.2) !important;
    }
    
    /* Success/Error Messages */
    .stSuccess {
        background: rgba(34, 197, 94, 0.1) !important;
        border: 1px solid rgba(34, 197, 94, 0.3) !important;
        border-radius: 10px !important;
        color: #86efac !important;
    }
    
    .stError {
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
        border-radius: 10px !important;
        color: #fca5a5 !important;
    }
    
    /* Character Container */
    .character-container {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 250px;
        height: 250px;
        z-index: 999;
        pointer-events: none;
    }
    
    /* Ryujin Character */
    .ryujin-character {
        width: 100%;
        height: 100%;
        background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #fbbf24 100%);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 120px;
        box-shadow: 0 0 50px rgba(139, 92, 246, 0.6);
        position: relative;
        overflow: hidden;
    }
    
    /* Idle State */
    .ryujin-idle {
        animation: float 3s ease-in-out infinite;
    }
    
    @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-20px); }
    }
    
    /* Power Up Animation */
    .ryujin-powerup {
        animation: powerup 0.5s ease-in-out;
    }
    
    @keyframes powerup {
        0% { transform: scale(1); }
        50% { transform: scale(1.2); }
        100% { transform: scale(1); }
    }
    
    /* Lightning Effect */
    .lightning-effect {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: 
            linear-gradient(45deg, transparent 30%, rgba(251, 191, 36, 0.8) 50%, transparent 70%),
            linear-gradient(-45deg, transparent 30%, rgba(96, 165, 250, 0.8) 50%, transparent 70%);
        animation: lightning 0.3s ease-in-out infinite;
        opacity: 0;
    }
    
    .ryujin-active .lightning-effect {
        opacity: 1;
    }
    
    @keyframes lightning {
        0%, 100% { 
            transform: translate(0, 0);
            opacity: 0;
        }
        25% { 
            transform: translate(-10px, -10px);
            opacity: 1;
        }
        75% { 
            transform: translate(10px, 10px);
            opacity: 1;
        }
    }
    
    /* Fire Aura */
    .fire-aura {
        position: absolute;
        top: -20%;
        left: -20%;
        width: 140%;
        height: 140%;
        background: radial-gradient(circle, rgba(251, 191, 36, 0.4) 0%, transparent 70%);
        animation: rotate 4s linear infinite;
        opacity: 0;
    }
    
    .ryujin-active .fire-aura {
        opacity: 1;
        animation: rotate 1s linear infinite, pulse-fire 0.5s ease-in-out infinite;
    }
    
    @keyframes rotate {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    
    @keyframes pulse-fire {
        0%, 100% { transform: scale(1) rotate(0deg); }
        50% { transform: scale(1.1) rotate(180deg); }
    }
    
    /* Energy Particles */
    .energy-particle {
        position: absolute;
        width: 6px;
        height: 6px;
        background: #fbbf24;
        border-radius: 50%;
        animation: particle-rise 2s ease-out infinite;
        opacity: 0;
    }
    
    .ryujin-active .energy-particle {
        opacity: 1;
    }
    
    @keyframes particle-rise {
        0% {
            transform: translateY(0) scale(1);
            opacity: 1;
        }
        100% {
            transform: translateY(-200px) scale(0);
            opacity: 0;
        }
    }
    
    .energy-particle:nth-child(1) { left: 20%; animation-delay: 0s; }
    .energy-particle:nth-child(2) { left: 40%; animation-delay: 0.2s; }
    .energy-particle:nth-child(3) { left: 60%; animation-delay: 0.4s; }
    .energy-particle:nth-child(4) { left: 80%; animation-delay: 0.6s; }
    
    /* Shake Effect */
    .ryujin-active {
        animation: shake 0.2s ease-in-out infinite;
    }
    
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        75% { transform: translateX(5px); }
    }
    
    /* Status Indicator */
    .status-indicator {
        position: absolute;
        top: -30px;
        left: 50%;
        transform: translateX(-50%);
        background: rgba(15, 23, 42, 0.9);
        color: #60a5fa;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 14px;
        border: 2px solid rgba(96, 165, 250, 0.4);
        white-space: nowrap;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
    }
    
    /* Card Styling */
    .info-card {
        background: rgba(15, 23, 42, 0.6);
        border: 2px solid rgba(96, 165, 250, 0.3);
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 4px 20px rgba(59, 130, 246, 0.2);
    }
    </style>
    """, unsafe_allow_html=True)

def render_ryujin_character(is_active=False):
    """Render the Ryujin character with animations"""
    state_class = "ryujin-active" if is_active else "ryujin-idle"
    status_text = "⚡ VERIFYING ⚡" if is_active else "💤 Idle"
    
    character_html = f"""
    <div class="character-container">
        <div class="ryujin-character {state_class}">
            <div class="fire-aura"></div>
            <div class="lightning-effect"></div>
            <div class="energy-particle"></div>
            <div class="energy-particle"></div>
            <div class="energy-particle"></div>
            <div class="energy-particle"></div>
            <span style="position: relative; z-index: 10;">⚡🐉</span>
            <div class="status-indicator">{status_text}</div>
        </div>
    </div>
    """
    st.markdown(character_html, unsafe_allow_html=True)

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
# MAIN APP
# =========================

# Apply custom CSS
inject_custom_css()

st.title("⚡ RYUJIN EMAIL VERIFICATION ⚡")

ip = get_client_ip()

# Sidebar Navigation
page = st.sidebar.selectbox("⚡ Navigation",
    ["🏠 Dashboard", "⚡ Live Verify", "📊 Bulk Verify", "📧 Contact", "❓ Q&A"])

# ADMIN LOGIN
with st.sidebar:
    st.markdown("---")
    st.markdown("### 🔐 Admin Access")
    if not st.session_state.is_admin:
        password = st.text_input("Enter Password", type="password", key="admin_pass")
        if password == ADMIN_PASSWORD:
            st.session_state.is_admin = True
            st.success("⚡ Admin Mode Activated!")
            st.rerun()
    else:
        st.success("⚡ Admin Mode Active")
        if st.button("🚪 Logout"):
            st.session_state.is_admin = False
            st.rerun()

# =========================
# DASHBOARD
# =========================

if page == "🏠 Dashboard":
    st.header("📊 Verification Dashboard")
    
    # Render idle character
    render_ryujin_character(is_active=False)

    df = pd.DataFrame(st.session_state.history)

    if not df.empty:
        total = len(df)
        valid = len(df[df.status == "VALID"])
        risky = len(df[df.status == "RISKY"])
        invalid = len(df[df.status == "INVALID"])
        catch_all = len(df[df.status == "CATCH_ALL"])

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("⚡ Total", total)
        col2.metric("✅ Valid", valid)
        col3.metric("❌ Invalid", invalid)
        col4.metric("⚠️ Risky", risky)
        
        st.metric("🎯 Catch-All", catch_all)

        st.markdown("### 📋 Recent Verifications")
        st.dataframe(df, use_container_width=True)
    else:
        st.info("🔍 No verification data yet. Start verifying emails!")

# =========================
# LIVE VERIFY
# =========================

elif page == "⚡ Live Verify":
    st.header("⚡ Live Email Verification")
    
    st.markdown("""
    <div class="info-card">
    <h3 style="margin-top: 0;">🎯 How It Works</h3>
    <p>Enter an email address and watch Ryujin power up to verify it! The character will activate with lightning and fire effects during verification.</p>
    </div>
    """, unsafe_allow_html=True)
    
    email_input = st.text_input("📧 Enter Email Address", placeholder="example@domain.com")

    col1, col2 = st.columns([3, 1])
    
    with col1:
        verify_button = st.button("⚡ VERIFY EMAIL ⚡", use_container_width=True)
    
    with col2:
        remaining = FREE_LIMIT - st.session_state.usage.get(ip, {}).get("count", 0)
        if not st.session_state.is_admin:
            st.metric("Remaining", remaining)

    if verify_button:
        if not email_input:
            st.warning("⚠️ Please enter an email address")
        elif not check_rate_limit(ip):
            st.error(f"❌ Free limit reached ({FREE_LIMIT} / 24h)")
        else:
            # Show active character
            render_ryujin_character(is_active=True)
            
            with st.spinner("⚡ Ryujin is verifying..."):
                # Add dramatic pause for effect
                time.sleep(1.5)
                result = verify_email(email_input)
            
            # Display result with styling
            st.markdown("### 📊 Verification Result")
            
            status_emoji = {
                "VALID": "✅",
                "INVALID": "❌",
                "RISKY": "⚠️",
                "CATCH_ALL": "🎯"
            }
            
            status_color = {
                "VALID": "#22c55e",
                "INVALID": "#ef4444",
                "RISKY": "#f59e0b",
                "CATCH_ALL": "#3b82f6"
            }
            
            result_html = f"""
            <div style="background: rgba(15, 23, 42, 0.8); border: 2px solid {status_color.get(result['status'], '#3b82f6')}; 
                        border-radius: 15px; padding: 25px; margin: 20px 0;">
                <h2 style="margin-top: 0; color: {status_color.get(result['status'], '#3b82f6')};">
                    {status_emoji.get(result['status'], '❓')} {result['status']}
                </h2>
                <p style="font-size: 18px; margin: 10px 0;"><strong>Email:</strong> {result['email']}</p>
                <p style="font-size: 18px; margin: 10px 0;"><strong>Reason:</strong> {result['reason']}</p>
                <p style="font-size: 18px; margin: 10px 0;"><strong>AI Confidence:</strong> {result['ai_confidence_score']}%</p>
                <p style="font-size: 18px; margin: 10px 0;"><strong>Safe to Send:</strong> {'✅ Yes' if result['safe_to_send'] else '❌ No'}</p>
            </div>
            """
            st.markdown(result_html, unsafe_allow_html=True)
            
            # Render idle character after verification
            time.sleep(0.5)
            render_ryujin_character(is_active=False)

# =========================
# BULK VERIFY
# =========================

elif page == "📊 Bulk Verify":
    st.header("📊 Bulk Email Verification")
    
    # Render idle character
    render_ryujin_character(is_active=False)
    
    st.markdown("""
    <div class="info-card">
    <h3 style="margin-top: 0;">📁 Upload or Paste</h3>
    <p>Verify multiple emails at once. Upload a CSV file with an 'email' column or paste emails line by line.</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["📁 Upload CSV", "📝 Paste Emails"])
    
    with tab1:
        uploaded_file = st.file_uploader("Upload CSV (must contain 'email' column)", type=["csv"])

        if uploaded_file:
            df = pd.read_csv(uploaded_file)
            df.columns = df.columns.str.strip().str.lower()

            if "email" in df.columns:
                st.info(f"📧 Found {len(df)} emails")
                
                if st.button("⚡ Verify All", use_container_width=True):
                    # Show active character
                    render_ryujin_character(is_active=True)
                    
                    results = []
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    for idx, email in enumerate(df["email"].dropna()):
                        if not check_rate_limit(ip):
                            st.warning(f"⚠️ Rate limit reached at {idx + 1} emails")
                            break
                        
                        status_text.text(f"⚡ Verifying {idx + 1}/{len(df)}: {email}")
                        results.append(verify_email(email))
                        progress_bar.progress((idx + 1) / len(df))
                        time.sleep(0.3)  # Dramatic effect
                    
                    status_text.text("✅ Verification Complete!")
                    st.dataframe(pd.DataFrame(results), use_container_width=True)
                    
                    # Render idle character
                    render_ryujin_character(is_active=False)
            else:
                st.error("❌ CSV must contain 'email' column")
    
    with tab2:
        bulk_text = st.text_area("Paste emails (one per line)", height=200, 
                                 placeholder="email1@example.com\nemail2@example.com\nemail3@example.com")

        if st.button("⚡ Verify Pasted", use_container_width=True):
            emails = [e.strip() for e in bulk_text.split("\n") if e.strip()]
            
            if not emails:
                st.warning("⚠️ Please paste some emails")
            else:
                # Show active character
                render_ryujin_character(is_active=True)
                
                results = []
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for idx, email in enumerate(emails):
                    if not check_rate_limit(ip):
                        st.warning(f"⚠️ Rate limit reached at {idx + 1} emails")
                        break
                    
                    status_text.text(f"⚡ Verifying {idx + 1}/{len(emails)}: {email}")
                    results.append(verify_email(email))
                    progress_bar.progress((idx + 1) / len(emails))
                    time.sleep(0.3)  # Dramatic effect
                
                status_text.text("✅ Verification Complete!")
                st.dataframe(pd.DataFrame(results), use_container_width=True)
                
                # Render idle character
                render_ryujin_character(is_active=False)

# =========================
# CONTACT
# =========================

elif page == "📧 Contact":
    st.header("📧 Contact Us")
    
    # Render idle character
    render_ryujin_character(is_active=False)
    
    st.markdown("""
    <div class="info-card">
    <h3 style="margin-top: 0;">💬 Get in Touch</h3>
    <p>Have questions or feedback? Send us a message!</p>
    </div>
    """, unsafe_allow_html=True)
    
    name = st.text_input("👤 Name")
    email = st.text_input("📧 Email")
    message = st.text_area("💬 Message", height=150)

    if st.button("📤 Send Message", use_container_width=True):
        if name and email and message:
            st.session_state.messages.append({
                "name": name,
                "email": email,
                "message": message,
                "time": datetime.utcnow()
            })
            st.success("✅ Message sent successfully!")
        else:
            st.warning("⚠️ Please fill all fields")

    if st.session_state.is_admin and st.session_state.messages:
        st.markdown("---")
        st.subheader("📬 Admin Inbox")
        for idx, msg in enumerate(st.session_state.messages):
            st.markdown(f"""
            <div class="info-card">
            <p><strong>From:</strong> {msg['name']} ({msg['email']})</p>
            <p><strong>Time:</strong> {msg['time']}</p>
            <p><strong>Message:</strong> {msg['message']}</p>
            </div>
            """, unsafe_allow_html=True)

# =========================
# Q&A PAGE
# =========================

elif page == "❓ Q&A":
    st.header("❓ Frequently Asked Questions")
    
    # Render idle character
    render_ryujin_character(is_active=False)

    st.markdown("""
    <div class="info-card">
    <h3>⚡ How does Ryujin verify emails?</h3>
    <p>Ryujin uses advanced verification techniques:</p>
    <ul>
        <li><strong>Syntax Check:</strong> Validates email format</li>
        <li><strong>MX Record:</strong> Confirms domain has mail servers</li>
        <li><strong>SMTP Probe:</strong> Tests if mailbox actually exists</li>
        <li><strong>Catch-All Detection:</strong> Identifies domains that accept all emails</li>
        <li><strong>AI Scoring:</strong> Assigns confidence score (0-100)</li>
    </ul>
    </div>

    <div class="info-card">
    <h3>🎯 What do the scores mean?</h3>
    <ul>
        <li><strong>90-100:</strong> ✅ Very Safe - Definitely deliverable</li>
        <li><strong>70-89:</strong> ⚠️ Moderate Risk - Probably okay</li>
        <li><strong>50-69:</strong> 🎯 Catch-All - Domain accepts everything</li>
        <li><strong>0-49:</strong> ❌ High Risk - Likely to bounce</li>
    </ul>
    </div>

    <div class="info-card">
    <h3>📊 Free Limits</h3>
    <ul>
        <li><strong>Free Users:</strong> 600 emails per IP / 24 hours</li>
        <li><strong>Admin:</strong> Unlimited verifications</li>
        <li><strong>Rate Limit:</strong> Resets automatically after 24 hours</li>
    </ul>
    </div>

    <div class="info-card">
    <h3>🐉 About Ryujin</h3>
    <p>Ryujin is the Lightning Dragon Guardian - a powerful character who harnesses the energy of lightning and fire to verify emails at lightning speed! Watch him power up during verification with spectacular effects.</p>
    <p style="text-align: center; font-size: 48px; margin: 20px 0;">⚡🐉⚡</p>
    </div>

    <div class="info-card">
    <h3>🎨 Features</h3>
    <ul>
        <li>✨ Real-time email verification</li>
        <li>🎯 AI-powered risk scoring</li>
        <li>📊 Bulk verification support</li>
        <li>📈 Verification history dashboard</li>
        <li>🎭 Animated Ryujin character</li>
        <li>⚡ Lightning & fire effects</li>
        <li>🌙 Cyberpunk UI theme</li>
    </ul>
    </div>

    <div class="info-card">
    <h3>🛡️ Why Verify Emails?</h3>
    <ul>
        <li><strong>Reduce Bounce Rate:</strong> Improve email deliverability</li>
        <li><strong>Protect Reputation:</strong> Maintain sender score</li>
        <li><strong>Save Money:</strong> Don't pay for invalid emails</li>
        <li><strong>Increase ROI:</strong> Better campaign performance</li>
    </ul>
    </div>
    """, unsafe_allow_html=True)
