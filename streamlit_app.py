import streamlit as st
import pandas as pd
import re
import dns.resolver
import random
import hashlib
import socket
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
from sqlalchemy import inspect

# ==========================
# DATABASE
# ==========================

engine = create_engine("sqlite:///email_verifier.db", connect_args={"check_same_thread": False})
Base = declarative_base()
session_factory = sessionmaker(bind=engine)
SessionLocal = scoped_session(session_factory)

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
    reason = Column(Text, nullable=True)  # Changed to Text for longer reasons
    timestamp = Column(DateTime, default=datetime.utcnow)

class PublicUsage(Base):
    __tablename__ = "public_usage"
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True)
    count = Column(Integer, default=0)
    reset = Column(DateTime, default=datetime.utcnow)

# ==========================
# DATABASE MIGRATION
# ==========================

def migrate_database():
    """Add missing columns to existing tables"""
    inspector = inspect(engine)
    
    # Check if 'reason' column exists in emails table
    columns = [col['name'] for col in inspector.get_columns('emails')]
    
    if 'reason' not in columns:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE emails ADD COLUMN reason TEXT"))
            conn.commit()
            print("✅ Added 'reason' column to emails table")

# Import text for raw SQL
from sqlalchemy import text

# Run migration before creating tables
try:
    migrate_database()
except Exception as e:
    print(f"Migration note: {e}")

# Create all tables
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
# ENHANCED EMAIL VALIDATION
# ==========================

# Disposable/temporary email domains
DISPOSABLE_DOMAINS = [
    'tempmail.com', 'guerrillamail.com', '10minutemail.com', 'mailinator.com',
    'throwaway.email', 'temp-mail.org', 'yopmail.com', 'maildrop.cc',
    'trashmail.com', 'fakeinbox.com', 'discard.email', 'getnada.com'
]

# Common typo domains
COMMON_TYPOS = {
    'gmial.com': 'gmail.com',
    'gmai.com': 'gmail.com',
    'gmil.com': 'gmail.com',
    'gmaill.com': 'gmail.com',
    'yahooo.com': 'yahoo.com',
    'yaho.com': 'yahoo.com',
    'hotmial.com': 'hotmail.com',
    'hotmal.com': 'hotmail.com',
    'outlok.com': 'outlook.com',
}

# Known valid domains with strict rules
STRICT_DOMAINS = {
    'gmail.com': {
        'min_length': 6,
        'max_length': 30,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_']
    },
    'googlemail.com': {
        'min_length': 6,
        'max_length': 30,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_']
    },
    'hotmail.com': {
        'min_length': 1,
        'max_length': 64,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-']
    },
    'outlook.com': {
        'min_length': 1,
        'max_length': 64,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-']
    },
    'yahoo.com': {
        'min_length': 4,
        'max_length': 32,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_']
    },
    'icloud.com': {
        'min_length': 3,
        'max_length': 20,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-']
    },
    'protonmail.com': {
        'min_length': 1,
        'max_length': 40,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-', '+']
    }
}

def validate_basic_syntax(email):
    """Basic RFC 5322 compliant email validation"""
    if not email or len(email) > 320:  # RFC max length
        return False, "Email too long or empty"
    
    if email.count('@') != 1:
        return False, "Email must contain exactly one @"
    
    local, domain = email.split('@')
    
    # Basic checks
    if not local or not domain:
        return False, "Missing local or domain part"
    
    if len(local) > 64:  # RFC max local part length
        return False, "Local part too long (max 64 chars)"
    
    # Check for valid characters in local part
    valid_local_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$'
    if not re.match(valid_local_pattern, local):
        return False, "Invalid characters in local part"
    
    # Check domain format
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if not re.match(domain_pattern, domain):
        return False, "Invalid domain format"
    
    # Check for valid TLD
    if '.' not in domain:
        return False, "Domain must have a TLD"
    
    tld = domain.split('.')[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False, "Invalid TLD"
    
    return True, "Valid syntax"

def validate_strict_domain_rules(local, domain):
    """Apply strict validation rules for known email providers"""
    domain_lower = domain.lower()
    
    if domain_lower not in STRICT_DOMAINS:
        # For unknown domains, apply general rules
        return validate_general_rules(local)
    
    rules = STRICT_DOMAINS[domain_lower]
    
    # Check length
    if len(local) < rules['min_length']:
        return False, f"Local part too short (min {rules['min_length']} chars for {domain})"
    
    if len(local) > rules['max_length']:
        return False, f"Local part too long (max {rules['max_length']} chars for {domain})"
    
    # Check for consecutive dots (gmail.com doesn't allow this)
    if not rules['allow_consecutive_dots'] and '..' in local:
        return False, f"Consecutive dots not allowed for {domain}"
    
    # Check starting/ending dots
    if not rules['allow_starting_dot'] and local.startswith('.'):
        return False, f"Cannot start with dot for {domain}"
    
    if not rules['allow_ending_dot'] and local.endswith('.'):
        return False, f"Cannot end with dot for {domain}"
    
    # Check allowed special characters
    allowed_chars = set(rules['allowed_special_chars'])
    special_chars_in_local = set(c for c in local if not c.isalnum())
    
    invalid_chars = special_chars_in_local - allowed_chars
    if invalid_chars:
        return False, f"Invalid characters {invalid_chars} for {domain}"
    
    # Check for consecutive special characters
    if not rules['allow_consecutive_special']:
        for i in range(len(local) - 1):
            if not local[i].isalnum() and not local[i+1].isalnum():
                return False, f"Consecutive special characters not allowed for {domain}"
    
    # Gmail specific: dots are ignored, check for abuse
    if domain_lower in ['gmail.com', 'googlemail.com']:
        # Remove dots to check real username
        no_dots = local.replace('.', '')
        if len(no_dots) < 6:
            return False, "Gmail username too short (min 6 chars excluding dots)"
        
        # Check for too many dots (spam pattern)
        if local.count('.') > len(no_dots) / 2:
            return False, "Too many dots in Gmail address"
    
    return True, "Valid"

def validate_general_rules(local):
    """General validation rules for non-major providers"""
    # Cannot start or end with special characters
    if not local[0].isalnum() or not local[-1].isalnum():
        return False, "Must start and end with alphanumeric character"
    
    # Check for consecutive dots
    if '..' in local:
        return False, "Consecutive dots not allowed"
    
    # Check for suspicious patterns
    if local.count('.') > 5:
        return False, "Too many dots"
    
    # Check length
    if len(local) < 1:
        return False, "Local part too short"
    
    return True, "Valid"

def check_disposable_domain(domain):
    """Check if domain is a known disposable email service"""
    domain_lower = domain.lower()
    return domain_lower in DISPOSABLE_DOMAINS

def check_domain_typo(domain):
    """Check for common typos and suggest correction"""
    domain_lower = domain.lower()
    if domain_lower in COMMON_TYPOS:
        return True, COMMON_TYPOS[domain_lower]
    return False, None

def validate_mx_record(domain):
    """Validate MX records exist and are reachable"""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            return False, "No MX records found"
        
        # Check if at least one MX record is valid
        valid_mx = False
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            try:
                # Try to resolve the MX host
                socket.gethostbyname(mx_host)
                valid_mx = True
                break
            except:
                continue
        
        if not valid_mx:
            return False, "MX records exist but not reachable"
        
        return True, "MX records valid"
    except dns.resolver.NXDOMAIN:
        return False, "Domain does not exist"
    except dns.resolver.NoAnswer:
        return False, "No MX records found"
    except dns.resolver.Timeout:
        return False, "DNS timeout"
    except Exception as e:
        return False, f"DNS error: {str(e)}"

def check_role_based_email(local):
    """Check if email is role-based (often not for personal use)"""
    role_based = [
        'admin', 'administrator', 'info', 'support', 'help', 'contact',
        'sales', 'marketing', 'webmaster', 'postmaster', 'noreply',
        'no-reply', 'abuse', 'hostmaster', 'root', 'mailer-daemon'
    ]
    return local.lower() in role_based

def enhanced_ai_score(email, validation_results):
    """Enhanced AI risk scoring based on multiple validation factors"""
    local, domain = email.split('@')
    risk_score = 0
    reasons = []
    
    # Base risk
    risk_score += random.uniform(1, 5)
    
    # Syntax validation failed
    if not validation_results['syntax_valid']:
        risk_score += 40
        reasons.append("Invalid syntax")
    
    # Domain checks
    if validation_results['is_disposable']:
        risk_score += 45
        reasons.append("Disposable email domain")
    
    if validation_results['has_typo']:
        risk_score += 25
        reasons.append(f"Possible typo (did you mean {validation_results['suggested_domain']}?)")
    
    if not validation_results['mx_valid']:
        risk_score += 35
        reasons.append(validation_results['mx_reason'])
    
    if not validation_results['domain_rules_valid']:
        risk_score += 30
        reasons.append(validation_results['domain_rules_reason'])
    
    # Local part analysis
    if len(local) < 3:
        risk_score += 15
        reasons.append("Very short local part")
    
    if len(local) > 40:
        risk_score += 10
        reasons.append("Very long local part")
    
    # Check for random-looking strings
    if len(local) > 15 and sum(c.isdigit() for c in local) > len(local) / 2:
        risk_score += 20
        reasons.append("Too many numbers (looks random)")
    
    # Check for suspicious patterns
    suspicious_words = ['test', 'fake', 'spam', 'temp', 'trash', 'junk', 'dummy']
    if any(word in local.lower() for word in suspicious_words):
        risk_score += 25
        reasons.append("Suspicious keywords detected")
    
    # Role-based email
    if validation_results['is_role_based']:
        risk_score += 15
        reasons.append("Role-based email")
    
    # Check for repeated characters (spam pattern)
    for i in range(len(local) - 2):
        if local[i] == local[i+1] == local[i+2]:
            risk_score += 15
            reasons.append("Repeated character pattern")
            break
    
    # Domain reputation (simple check)
    domain_lower = domain.lower()
    trusted_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                       'icloud.com', 'protonmail.com', 'aol.com']
    
    if domain_lower in trusted_domains:
        risk_score -= 10  # Bonus for known providers
    elif domain.count('.') > 2:
        risk_score += 10
        reasons.append("Unusual domain structure")
    
    # Cap risk score
    risk_score = max(0, min(risk_score, 100))
    confidence = 100 - risk_score
    
    # Determine status
    if risk_score < 30:
        status = "VALID"
    elif risk_score < 60:
        status = "RISKY"
    else:
        status = "INVALID"
    
    return risk_score, confidence, status, reasons

# ==========================
# MAIN VERIFY EMAIL FUNCTION
# ==========================

def verify_email(email, client=None, ip=None):
    """Enhanced email verification with strict validation and proper session management"""
    # Create a new session for this verification
    session = SessionLocal()
    
    try:
        email = email.strip().lower()
        now = datetime.utcnow()
        
        # PUBLIC LIMIT
        if client is None:
            usage = session.query(PublicUsage).filter_by(ip=ip).first()
            if not usage:
                usage = PublicUsage(ip=ip, count=0, reset=now + timedelta(hours=24))
                session.add(usage)
                session.flush()  # Flush to get the ID
            elif now > usage.reset:
                usage.count = 0
                usage.reset = now + timedelta(hours=24)
            if usage.count >= 600:
                return None
        
        # CLIENT LIMIT
        if client and client.credits <= 0:
            return None
        
        # Initialize validation results
        validation_results = {
            'syntax_valid': False,
            'syntax_reason': '',
            'domain_rules_valid': False,
            'domain_rules_reason': '',
            'mx_valid': False,
            'mx_reason': '',
            'is_disposable': False,
            'has_typo': False,
            'suggested_domain': None,
            'is_role_based': False
        }
        
        # Step 1: Basic syntax validation
        syntax_valid, syntax_reason = validate_basic_syntax(email)
        validation_results['syntax_valid'] = syntax_valid
        validation_results['syntax_reason'] = syntax_reason
        
        if not syntax_valid:
            status = "INVALID"
            risk_score = 100
            confidence = 0
            reasons = [syntax_reason]
        else:
            local, domain = email.split('@')
            
            # Step 2: Check for disposable domains
            validation_results['is_disposable'] = check_disposable_domain(domain)
            
            # Step 3: Check for typos
            has_typo, suggested = check_domain_typo(domain)
            validation_results['has_typo'] = has_typo
            validation_results['suggested_domain'] = suggested
            
            # Step 4: Validate domain-specific rules
            domain_rules_valid, domain_rules_reason = validate_strict_domain_rules(local, domain)
            validation_results['domain_rules_valid'] = domain_rules_valid
            validation_results['domain_rules_reason'] = domain_rules_reason
            
            # Step 5: Validate MX records
            mx_valid, mx_reason = validate_mx_record(domain)
            validation_results['mx_valid'] = mx_valid
            validation_results['mx_reason'] = mx_reason
            
            # Step 6: Check role-based
            validation_results['is_role_based'] = check_role_based_email(local)
            
            # Step 7: AI Risk Scoring
            risk_score, confidence, status, reasons = enhanced_ai_score(email, validation_results)
        
        # Determine if safe to send
        safe_to_send = risk_score < 40 and validation_results['syntax_valid'] and validation_results['mx_valid']
        
        # Compile reason string (limit to 500 chars to avoid database issues)
        reason_str = "; ".join(reasons) if reasons else "All checks passed"
        reason_str = reason_str[:500]  # Truncate if too long
        
        # Save to database
        record = EmailVerification(
            client_id=client.id if client else None,
            ip=ip if not client else None,
            email=email,
            status=status,
            safe_to_send=safe_to_send,
            ai_confidence=confidence,
            ai_risk_score=risk_score,
            reason=reason_str
        )
        session.add(record)
        
        # Update credits/usage
        if client:
            client.credits -= 1
        else:
            usage.count += 1
        
        # Commit all changes
        session.commit()
        
        return {
            "Email": email,
            "Status": status,
            "AI Prediction": status,
            "Risk Score": round(risk_score, 2),
            "Confidence": round(confidence, 2),
            "Safe To Send": safe_to_send,
            "Reason": reason_str,
            "MX Valid": validation_results['mx_valid'],
            "Disposable": validation_results['is_disposable'],
            "Typo Detected": validation_results['has_typo']
        }
    
    except Exception as e:
        session.rollback()
        st.error(f"Error verifying {email}: {str(e)}")
        return None
    finally:
        session.close()

# ==========================
# STREAMLIT UI
# ==========================

st.set_page_config(page_title="AI Email Verifier SaaS - Enhanced", layout="wide")
ip = get_client_ip()

# SHOW PLAN LIMITS
st.markdown("## 📋 Plans & Limits")
st.markdown("""
| Plan        | Daily Email Limit |
|------------|----------------|
| Free       | 600 emails/IP per 24h (public no-login) |
| Pro        | 5,000 emails per client account |
| Enterprise | 100,000 emails per client account |
""")

st.markdown("### ✨ Enhanced Validation Features")
st.markdown("""
- **Strict Domain Rules**: Gmail, Hotmail, Yahoo, Outlook, iCloud validation
- **MX Record Verification**: Checks mail server existence
- **Disposable Email Detection**: Blocks temporary email services
- **Typo Detection**: Identifies common domain typos
- **Role-based Detection**: Identifies generic emails (admin@, info@, etc.)
- **Pattern Analysis**: Detects spam-like patterns and suspicious formats
- **Multi-layer AI Scoring**: Advanced risk assessment
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
            session = SessionLocal()
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
            session.close()
    else:
        if st.button("Logout Client"):
            st.session_state.client_id = None

# ==========================
# ADMIN PANEL
# ==========================
if st.session_state.is_admin:
    st.title("🛡 Admin Dashboard")
    
    tab1, tab2 = st.tabs(["Create Client", "View Statistics"])
    
    with tab1:
        st.subheader("Create Client")
        new_user = st.text_input("Username")
        new_pass = st.text_input("Password", type="password")
        new_plan = st.selectbox("Plan", ["Free", "Pro", "Enterprise"])
        if st.button("Create Client"):
            session = SessionLocal()
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
                st.success(f"Client '{new_user}' Created with {credits} credits")
            else:
                st.error("Username already exists")
            session.close()
    
    with tab2:
        st.subheader("Verification Statistics")
        session = SessionLocal()
        total_verifications = session.query(EmailVerification).count()
        valid_count = session.query(EmailVerification).filter_by(status="VALID").count()
        risky_count = session.query(EmailVerification).filter_by(status="RISKY").count()
        invalid_count = session.query(EmailVerification).filter_by(status="INVALID").count()
        session.close()
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Verified", total_verifications)
        col2.metric("Valid", valid_count)
        col3.metric("Risky", risky_count)
        col4.metric("Invalid", invalid_count)

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
        # Refresh client data if logged in
        if client:
            session = SessionLocal()
            client = session.query(Client).filter_by(id=client.id).first()
            session.close()
        
        result = verify_email(email, client=client, ip=ip)
        if result:
            results.append(result)
            color = "green" if result["AI Prediction"]=="VALID" else "orange" if result["AI Prediction"]=="RISKY" else "red"
            placeholder.markdown(
                f"{i+1}/{len(emails)} → <span style='color:{color}'><b>{result['Email']}</b> | {result['AI Prediction']} | "
                f"Risk: {result['Risk Score']}% | MX: {'✓' if result['MX Valid'] else '✗'}</span><br>"
                f"<small>{result['Reason']}</small>", 
                unsafe_allow_html=True
            )
        else:
            if client:
                st.error("No credits remaining.")
            else:
                st.error("Free limit reached for your IP")
            break
        progress_bar.progress((i+1)/len(emails))
    
    if results:
        result_df = pd.DataFrame(results)
        st.success(f"✅ Verified {len(results)} emails")
        
        # Show summary
        col1, col2, col3 = st.columns(3)
        valid = len([r for r in results if r["Status"] == "VALID"])
        risky = len([r for r in results if r["Status"] == "RISKY"])
        invalid = len([r for r in results if r["Status"] == "INVALID"])
        
        col1.metric("Valid", valid, delta=f"{valid/len(results)*100:.1f}%")
        col2.metric("Risky", risky, delta=f"{risky/len(results)*100:.1f}%")
        col3.metric("Invalid", invalid, delta=f"{invalid/len(results)*100:.1f}%")
        
        st.dataframe(result_df, use_container_width=True)
        
        # Create separated download format
        valid_emails = [r["Email"] for r in results if r["Status"] == "VALID"]
        risky_emails = [r["Email"] for r in results if r["Status"] == "RISKY"]
        invalid_emails = [r["Email"] for r in results if r["Status"] == "INVALID"]
        
        # Pad lists to same length
        max_len = max(len(valid_emails), len(risky_emails), len(invalid_emails))
        valid_emails += [''] * (max_len - len(valid_emails))
        risky_emails += [''] * (max_len - len(risky_emails))
        invalid_emails += [''] * (max_len - len(invalid_emails))
        
        # Create separated DataFrame
        separated_df = pd.DataFrame({
            'Valid Emails': valid_emails,
            'Risky Emails': risky_emails,
            'Invalid Emails': invalid_emails
        })
        
        # Download buttons
        col_dl1, col_dl2 = st.columns(2)
        
        with col_dl1:
            # Full detailed results
            csv_full = result_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇ Download Full Details CSV", 
                csv_full, 
                "verified_full_details.csv", 
                "text/csv",
                key="full_csv"
            )
        
        with col_dl2:
            # Separated by status
            csv_separated = separated_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇ Download Separated CSV (Valid/Risky/Invalid)", 
                csv_separated, 
                "verified_separated.csv", 
                "text/csv",
                key="separated_csv"
            )

# ==========================
# SINGLE EMAIL TEST
# ==========================

def test_single_email(client=None, ip=None):
    st.markdown("### 🔍 Test Single Email")
    test_email = st.text_input("Enter email to test", placeholder="example@domain.com")
    
    if st.button("Verify Email") and test_email:
        with st.spinner("Verifying..."):
            # Refresh client data if logged in
            if client:
                session = SessionLocal()
                client = session.query(Client).filter_by(id=client.id).first()
                session.close()
            
            result = verify_email(test_email, client=client, ip=ip)
            
            if result:
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    if result["Status"] == "VALID":
                        st.success(f"✅ {result['Email']} - VALID")
                    elif result["Status"] == "RISKY":
                        st.warning(f"⚠️ {result['Email']} - RISKY")
                    else:
                        st.error(f"❌ {result['Email']} - INVALID")
                    
                    st.markdown(f"**Reason:** {result['Reason']}")
                
                with col2:
                    st.metric("Risk Score", f"{result['Risk Score']}%")
                    st.metric("Confidence", f"{result['Confidence']}%")
                    st.metric("Safe to Send", "Yes" if result["Safe To Send"] else "No")
                
                # Detailed info
                with st.expander("📊 Detailed Analysis"):
                    st.json({
                        "Email": result["Email"],
                        "Status": result["Status"],
                        "Risk Score": result["Risk Score"],
                        "Confidence": result["Confidence"],
                        "MX Records Valid": result["MX Valid"],
                        "Disposable Domain": result["Disposable"],
                        "Typo Detected": result["Typo Detected"],
                        "Safe to Send": result["Safe To Send"],
                        "Validation Notes": result["Reason"]
                    })
            else:
                st.error("Verification limit reached")

# ==========================
# CLIENT PORTAL
# ==========================
if st.session_state.client_id:
    session = SessionLocal()
    client = session.query(Client).filter_by(id=st.session_state.client_id).first()
    session.close()
    
    st.title("📧 Client Dashboard")
    st.markdown(f"**Plan:** {client.plan}  |  **Credits Remaining:** {client.credits}")
    
    tab1, tab2 = st.tabs(["Bulk Verification", "Single Email Test"])
    
    with tab1:
        uploaded_file = st.file_uploader("Upload CSV (first column should contain emails)", type=["csv"])
        if uploaded_file:
            process_csv(uploaded_file, client=client)
    
    with tab2:
        test_single_email(client=client, ip=ip)

# ==========================
# PUBLIC FREE USAGE
# ==========================
elif not st.session_state.client_id and not st.session_state.is_admin:
    st.title("🚀 AI Email Verification SaaS - Enhanced Free Usage")
    st.markdown("### Free Plan: 600 emails per IP / 24h, no login required")
    
    tab1, tab2 = st.tabs(["Bulk Verification", "Single Email Test"])
    
    with tab1:
        uploaded_file = st.file_uploader("Upload CSV (first column should contain emails)", type=["csv"])
        if uploaded_file:
            process_csv(uploaded_file, client=None, ip=ip)
    
    with tab2:
        test_single_email(client=None, ip=ip)
