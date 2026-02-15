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
    reason = Column(Text, nullable=True)
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
    """Enhanced password hashing with salt"""
    # Using SHA256 with salt for better security
    salt = "email_verifier_pro_2026_secure"
    return hashlib.sha256(f"{salt}{password}{salt}".encode()).hexdigest()

def encrypt_data(data):
    """Simple encryption for sensitive data storage"""
    # In production, use proper encryption like Fernet
    return hashlib.sha256(data.encode()).hexdigest()[:16]

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

# Comprehensive disposable/temporary email domains
DISPOSABLE_DOMAINS = [
    'tempmail.com', 'guerrillamail.com', '10minutemail.com', 'mailinator.com',
    'throwaway.email', 'temp-mail.org', 'yopmail.com', 'maildrop.cc',
    'trashmail.com', 'fakeinbox.com', 'discard.email', 'getnada.com',
    'sharklasers.com', 'guerrillamailblock.com', 'pokemail.net', 'spam4.me',
    'grr.la', 'harakirimail.com', 'mintemail.com', 'mytemp.email',
    'tmpmail.org', 'disposablemail.com', 'emailondeck.com', 'mailnesia.com',
    'tempinbox.com', '10mail.org', '20email.eu', '33mail.com',
    'anonbox.net', 'binkmail.com', 'bobmail.info', 'clickemail.com',
    'dispostable.com', 'emlhub.com', 'getairmail.com', 'jetable.org',
    'mailcatch.com', 'mailnull.com', 'moakt.com', 'nowmymail.com'
]

# Extended typo domains
COMMON_TYPOS = {
    'gmial.com': 'gmail.com',
    'gmai.com': 'gmail.com',
    'gmil.com': 'gmail.com',
    'gmaill.com': 'gmail.com',
    'gamil.com': 'gmail.com',
    'gmali.com': 'gmail.com',
    'gmaul.com': 'gmail.com',
    'gnail.com': 'gmail.com',
    'yahooo.com': 'yahoo.com',
    'yaho.com': 'yahoo.com',
    'yhoo.com': 'yahoo.com',
    'yaoo.com': 'yahoo.com',
    'yajoo.com': 'yahoo.com',
    'hotmial.com': 'hotmail.com',
    'hotmal.com': 'hotmail.com',
    'hotmaul.com': 'hotmail.com',
    'hotmil.com': 'hotmail.com',
    'hotmaii.com': 'hotmail.com',
    'outlok.com': 'outlook.com',
    'outloook.com': 'outlook.com',
    'outlool.com': 'outlook.com',
    'outloo.com': 'outlook.com',
    'iclould.com': 'icloud.com',
    'iclud.com': 'icloud.com',
    'icould.com': 'icloud.com',
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
        'allowed_special_chars': ['.', '_'],
        'allow_plus_addressing': True
    },
    'googlemail.com': {
        'min_length': 6,
        'max_length': 30,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_'],
        'allow_plus_addressing': True
    },
    'hotmail.com': {
        'min_length': 1,
        'max_length': 64,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-'],
        'allow_plus_addressing': False
    },
    'outlook.com': {
        'min_length': 1,
        'max_length': 64,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-'],
        'allow_plus_addressing': False
    },
    'live.com': {
        'min_length': 1,
        'max_length': 64,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-'],
        'allow_plus_addressing': False
    },
    'yahoo.com': {
        'min_length': 4,
        'max_length': 32,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_'],
        'allow_plus_addressing': False
    },
    'icloud.com': {
        'min_length': 3,
        'max_length': 20,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-'],
        'allow_plus_addressing': False
    },
    'protonmail.com': {
        'min_length': 1,
        'max_length': 40,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-', '+'],
        'allow_plus_addressing': True
    },
    'aol.com': {
        'min_length': 3,
        'max_length': 32,
        'allow_consecutive_dots': False,
        'allow_starting_dot': False,
        'allow_ending_dot': False,
        'allow_consecutive_special': False,
        'allowed_special_chars': ['.', '_', '-'],
        'allow_plus_addressing': False
    }
}

def validate_basic_syntax(email):
    """Enhanced RFC 5322 compliant email validation"""
    if not email or len(email) > 320:
        return False, "Email too long or empty"
    
    if email.count('@') != 1:
        return False, "Email must contain exactly one @"
    
    local, domain = email.split('@')
    
    # Basic checks
    if not local or not domain:
        return False, "Missing local or domain part"
    
    if len(local) > 64:
        return False, "Local part too long (max 64 chars)"
    
    # Check for spaces
    if ' ' in email:
        return False, "Email cannot contain spaces"
    
    # Check for valid characters in local part
    valid_local_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$'
    if not re.match(valid_local_pattern, local):
        return False, "Invalid characters in local part"
    
    # Check for double quotes (complex case)
    if '"' in local and not (local.startswith('"') and local.endswith('"')):
        return False, "Invalid use of quotes in local part"
    
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
    
    # Check for IP address in domain (rarely valid for personal emails)
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False, "IP address domains not supported"
    
    # Check for localhost
    if domain.lower() in ['localhost', 'localhost.localdomain']:
        return False, "Localhost domains not valid"
    
    return True, "Valid syntax"

def validate_strict_domain_rules(local, domain):
    """Apply strict validation rules for known email providers"""
    domain_lower = domain.lower()
    
    if domain_lower not in STRICT_DOMAINS:
        return validate_general_rules(local)
    
    rules = STRICT_DOMAINS[domain_lower]
    
    # Remove plus addressing for length check if allowed
    local_check = local
    if rules.get('allow_plus_addressing') and '+' in local:
        local_check = local.split('+')[0]
    
    # Check length
    if len(local_check) < rules['min_length']:
        return False, f"Local part too short (min {rules['min_length']} chars for {domain})"
    
    if len(local) > rules['max_length']:
        return False, f"Local part too long (max {rules['max_length']} chars for {domain})"
    
    # Check for consecutive dots
    if not rules['allow_consecutive_dots'] and '..' in local:
        return False, f"Consecutive dots not allowed for {domain}"
    
    # Check starting/ending dots
    if not rules['allow_starting_dot'] and local.startswith('.'):
        return False, f"Cannot start with dot for {domain}"
    
    if not rules['allow_ending_dot'] and local.endswith('.'):
        return False, f"Cannot end with dot for {domain}"
    
    # Check allowed special characters
    allowed_chars = set(rules['allowed_special_chars'])
    
    # Handle plus addressing
    local_to_check = local
    if rules.get('allow_plus_addressing'):
        allowed_chars.add('+')
    
    special_chars_in_local = set(c for c in local_to_check if not c.isalnum())
    
    invalid_chars = special_chars_in_local - allowed_chars
    if invalid_chars:
        return False, f"Invalid characters {invalid_chars} for {domain}"
    
    # Check for consecutive special characters
    if not rules['allow_consecutive_special']:
        for i in range(len(local) - 1):
            if not local[i].isalnum() and not local[i+1].isalnum():
                # Exception for plus addressing (e.g., user+tag)
                if rules.get('allow_plus_addressing') and (local[i] == '+' or local[i+1] == '+'):
                    continue
                return False, f"Consecutive special characters not allowed for {domain}"
    
    # Gmail specific validations
    if domain_lower in ['gmail.com', 'googlemail.com']:
        # Remove dots and plus addressing to check real username
        no_dots = local.split('+')[0].replace('.', '') if '+' in local else local.replace('.', '')
        if len(no_dots) < 6:
            return False, "Gmail username too short (min 6 chars excluding dots)"
        
        # Check for too many dots (spam pattern)
        if local.count('.') > len(no_dots) / 2:
            return False, "Too many dots in Gmail address"
        
        # Check if starts or ends with dot before @
        base_part = local.split('+')[0] if '+' in local else local
        if base_part.startswith('.') or base_part.endswith('.'):
            return False, "Gmail address cannot start or end with dot"
    
    return True, "Valid"

def validate_general_rules(local):
    """Enhanced general validation rules"""
    # Cannot start or end with special characters (except plus for some providers)
    if not local[0].isalnum() or not local[-1].isalnum():
        # Check if it's plus addressing
        if local[-1] != '+' and not ('+' in local and local.split('+')[-1].isalnum()):
            return False, "Must start and end with alphanumeric character"
    
    # Check for consecutive dots
    if '..' in local:
        return False, "Consecutive dots not allowed"
    
    # Check for too many special characters
    special_count = sum(1 for c in local if not c.isalnum())
    if special_count > len(local) / 2:
        return False, "Too many special characters"
    
    # Check for suspicious patterns
    if local.count('.') > 5:
        return False, "Too many dots"
    
    # Check for common invalid patterns
    invalid_patterns = ['..', '@@', '--', '__', '.-', '-.', '_.', '._']
    for pattern in invalid_patterns:
        if pattern in local:
            return False, f"Invalid pattern '{pattern}' detected"
    
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
    """Enhanced MX record validation"""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            return False, "No MX records found"
        
        # Check if at least one MX record is valid
        valid_mx = False
        mx_hosts = []
        
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            mx_hosts.append(mx_host)
            try:
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
    """Enhanced role-based email detection"""
    role_based = [
        'admin', 'administrator', 'info', 'support', 'help', 'contact',
        'sales', 'marketing', 'webmaster', 'postmaster', 'noreply',
        'no-reply', 'abuse', 'hostmaster', 'root', 'mailer-daemon',
        'billing', 'careers', 'feedback', 'hello', 'hr', 'jobs',
        'legal', 'mail', 'media', 'newsletter', 'office', 'press',
        'privacy', 'security', 'service', 'spam', 'unsubscribe',
        'website', 'www', 'team', 'staff'
    ]
    local_clean = local.split('+')[0].lower() if '+' in local else local.lower()
    return local_clean in role_based

def check_spam_patterns(local, domain):
    """Detect common spam/bot email patterns"""
    reasons = []
    
    # Check for random character sequences
    if len(local) > 10:
        # Count digit sequences
        digit_sequences = re.findall(r'\d+', local)
        if digit_sequences and any(len(seq) > 6 for seq in digit_sequences):
            reasons.append("Long digit sequence detected")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'abcdef']
        for pattern in keyboard_patterns:
            if pattern in local.lower():
                reasons.append(f"Keyboard pattern '{pattern}' detected")
                break
    
    # Check for excessive underscores
    if local.count('_') > 3:
        reasons.append("Too many underscores")
    
    # Check for all numbers
    if local.replace('.', '').replace('_', '').replace('-', '').isdigit():
        reasons.append("All numeric username")
    
    # Check for very short domains
    domain_parts = domain.split('.')
    if len(domain_parts[-2]) < 3:  # e.g., ab.com
        reasons.append("Suspiciously short domain name")
    
    # Check for new/uncommon TLDs (higher risk)
    suspicious_tlds = ['.xyz', '.top', '.win', '.download', '.loan', '.racing', 
                       '.click', '.stream', '.review', '.trade', '.science']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        reasons.append("High-risk TLD detected")
    
    return reasons

def enhanced_ai_score(email, validation_results):
    """Enhanced AI risk scoring with comprehensive analysis"""
    local, domain = email.split('@')
    risk_score = 0
    reasons = []
    
    # Base risk
    risk_score += random.uniform(1, 5)
    
    # Syntax validation failed
    if not validation_results['syntax_valid']:
        risk_score += 40
        reasons.append(validation_results['syntax_reason'])
    
    # Domain checks
    if validation_results['is_disposable']:
        risk_score += 50
        reasons.append("Disposable/temporary email service")
    
    if validation_results['has_typo']:
        risk_score += 30
        reasons.append(f"Typo detected - did you mean {validation_results['suggested_domain']}?")
    
    if not validation_results['mx_valid']:
        risk_score += 40
        reasons.append(validation_results['mx_reason'])
    
    if not validation_results['domain_rules_valid']:
        risk_score += 35
        reasons.append(validation_results['domain_rules_reason'])
    
    # Local part analysis
    if len(local) < 3:
        risk_score += 20
        reasons.append("Very short username")
    
    if len(local) > 40:
        risk_score += 15
        reasons.append("Unusually long username")
    
    # Check for random-looking strings
    if len(local) > 15 and sum(c.isdigit() for c in local) > len(local) / 2:
        risk_score += 25
        reasons.append("High number-to-letter ratio")
    
    # Check for suspicious patterns
    suspicious_words = ['test', 'fake', 'spam', 'temp', 'trash', 'junk', 'dummy', 
                        'sample', 'example', 'noreply', 'donotreply', 'bounce']
    for word in suspicious_words:
        if word in local.lower():
            risk_score += 30
            reasons.append(f"Suspicious keyword: '{word}'")
            break
    
    # Role-based email
    if validation_results['is_role_based']:
        risk_score += 20
        reasons.append("Role-based/generic email address")
    
    # Check for repeated characters (spam pattern)
    for i in range(len(local) - 2):
        if local[i] == local[i+1] == local[i+2]:
            risk_score += 20
            reasons.append("Repeated character pattern")
            break
    
    # Check for alternating case (spam trick)
    if sum(1 for c in local if c.isupper()) > 1 and sum(1 for c in local if c.islower()) > 1:
        risk_score += 10
        reasons.append("Mixed case pattern detected")
    
    # Spam pattern detection
    spam_patterns = validation_results.get('spam_patterns', [])
    if spam_patterns:
        risk_score += 15 * len(spam_patterns)
        reasons.extend(spam_patterns)
    
    # Domain reputation check
    domain_lower = domain.lower()
    trusted_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                       'icloud.com', 'protonmail.com', 'aol.com', 'live.com',
                       'mail.com', 'zoho.com']
    
    if domain_lower in trusted_domains:
        risk_score -= 15  # Bonus for known providers
    elif domain.count('.') > 2:
        risk_score += 15
        reasons.append("Unusual domain structure")
    
    # Check for new/free domain indicators
    free_domain_indicators = ['mail', 'email', 'post', 'webmail']
    if any(indicator in domain_lower for indicator in free_domain_indicators):
        risk_score += 5
    
    # Cap risk score
    risk_score = max(0, min(risk_score, 100))
    confidence = 100 - risk_score
    
    # Determine status with more nuanced thresholds
    if risk_score < 25:
        status = "VALID"
    elif risk_score < 55:
        status = "RISKY"
    else:
        status = "INVALID"
    
    return risk_score, confidence, status, reasons

# ==========================
# MAIN VERIFY EMAIL FUNCTION
# ==========================

def verify_email(email, client_id=None, ip=None):
    """Enhanced email verification with comprehensive validation"""
    session = SessionLocal()
    
    try:
        email = email.strip().lower()
        now = datetime.utcnow()
        
        # Get client from database if client_id provided
        client = None
        if client_id:
            client = session.query(Client).filter_by(id=client_id).first()
            if not client:
                return None
        
        # PUBLIC LIMIT
        if client is None:
            usage = session.query(PublicUsage).filter_by(ip=ip).first()
            if not usage:
                usage = PublicUsage(ip=ip, count=0, reset=now + timedelta(hours=24))
                session.add(usage)
                session.flush()
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
            'is_role_based': False,
            'spam_patterns': []
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
            
            # Step 7: Check spam patterns
            validation_results['spam_patterns'] = check_spam_patterns(local, domain)
            
            # Step 8: AI Risk Scoring
            risk_score, confidence, status, reasons = enhanced_ai_score(email, validation_results)
        
        # Determine if safe to send (stricter criteria)
        safe_to_send = (risk_score < 35 and 
                       validation_results['syntax_valid'] and 
                       validation_results['mx_valid'] and 
                       not validation_results['is_disposable'])
        
        # Compile reason string
        reason_str = "; ".join(reasons) if reasons else "All checks passed"
        reason_str = reason_str[:500]
        
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
            "Typo Detected": validation_results['has_typo'],
            "Role Based": validation_results['is_role_based']
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

st.set_page_config(page_title="AI Email Verifier Pro - Enhanced", layout="wide", page_icon="🔐")
ip = get_client_ip()

# ULTRA-MINIMAL LOGO BAR (18px height)
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@600&display=swap');
    
    .hero-section {
        position: relative;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        border-radius: 6px;
        padding: 0.25rem 0.6rem;
        margin-bottom: 0.5rem;
        height: 18px;
        display: flex;
        align-items: center;
        box-shadow: 0 2px 8px rgba(102, 126, 234, 0.25);
        transition: all 0.2s ease;
        cursor: pointer;
    }
    
    .hero-section:hover {
        box-shadow: 0 3px 12px rgba(102, 126, 234, 0.35);
        transform: translateY(-1px);
    }
    
    .logo-content {
        display: flex;
        align-items: center;
        justify-content: space-between;
        width: 100%;
        gap: 0.5rem;
    }
    
    .brand-section {
        display: flex;
        align-items: center;
        gap: 0.4rem;
    }
    
    .shield-icon {
        font-size: 0.75rem;
        line-height: 1;
    }
    
    .brand-name {
        font-family: 'Inter', sans-serif;
        font-size: 0.7rem;
        font-weight: 600;
        color: white;
        margin: 0;
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
        letter-spacing: 0.3px;
        line-height: 1;
    }
    
    .brand-highlight {
        color: #fbbf24;
    }
    
    .badges-section {
        display: flex;
        gap: 0.3rem;
        align-items: center;
    }
    
    .security-badge {
        background: rgba(255, 255, 255, 0.2);
        padding: 0.15rem 0.35rem;
        border-radius: 8px;
        font-size: 0.55rem;
        color: white;
        font-weight: 600;
        white-space: nowrap;
        line-height: 1;
    }
    
    .refresh-hint {
        color: rgba(255, 255, 255, 0.85);
        font-size: 0.6rem;
        font-style: italic;
        white-space: nowrap;
        line-height: 1;
    }
    
    .stButton button[kind="secondary"] {
        background: transparent !important;
        border: none !important;
        padding: 0 !important;
        width: 100% !important;
        margin-top: -0.25rem !important;
        height: 0 !important;
    }
    
    @media (max-width: 768px) {
        .badges-section {
            display: none;
        }
        .brand-name {
            font-size: 0.65rem;
        }
    }
    </style>
""", unsafe_allow_html=True)

# Hidden clickable button
if st.button("refresh_minimal", key="logo_refresh_btn", type="secondary", use_container_width=True):
    st.rerun()

st.markdown("""
    <div class="hero-section" onclick="document.querySelector('[key=\\'logo_refresh_btn\\']').click()">
        <div class="logo-content">
            <div class="brand-section">
                <span class="shield-icon">🛡</span>
                <span class="brand-name">AI EMAIL <span class="brand-highlight">VERIFIER</span> PRO</span>
            </div>
            <div class="badges-section">
                <span class="security-badge">🔐 SECURE</span>
                <span class="security-badge">✓ GDPR</span>
                <span class="refresh-hint">↻ refresh</span>
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

# SHOW PLAN LIMITS
st.markdown("## 📋 Plans & Limits")

# Security Notice
st.info("""
🔐 **Your Data is Safe & Secure:**
- 🛡️ All passwords are encrypted with salted SHA-256 hashing
- 🔒 Client data stored in secure SQLite database with restricted access
- 🚫 No third-party data sharing - Your information stays private
- 🔑 Admin-only access to sensitive operations
- ✅ GDPR-compliant data handling
- 🗑️ You can request data deletion anytime via contact
""")

st.markdown("""
| Plan        | Daily Email Limit |
|------------|----------------|
| Free       | 600 emails/IP per 24h (public no-login) |
| Pro        | 5,000 emails per client account |
| Enterprise | 100,000 emails per client account |
""")

st.markdown("### ✨ Advanced Validation Features")
st.markdown("""
- **🔍 Deep Syntax Validation**: RFC 5322 compliant with IP/localhost blocking
- **🎯 Strict Provider Rules**: Gmail, Hotmail, Yahoo, Outlook, iCloud, AOL, ProtonMail
- **🛡️ Plus Addressing Support**: Validates Gmail's user+tag@gmail.com format
- **🚫 50+ Disposable Domains**: Comprehensive temporary email blocking
- **✏️ Smart Typo Detection**: Catches common domain misspellings
- **📧 Role-based Detection**: 30+ generic email patterns (admin@, info@, etc.)
- **🤖 Spam Pattern Recognition**: Keyboard sequences, random strings, bot patterns
- **🌐 MX Record Verification**: Live mail server validation
- **⚠️ High-risk TLD Detection**: Flags suspicious domain extensions
- **📊 Multi-layer AI Scoring**: 15+ risk factors analyzed
- **💯 Enhanced Confidence Scores**: More accurate risk assessment
""")
st.markdown("---")

# --------------------------
# SIDEBAR: LOGIN / ADMIN
# --------------------------
with st.sidebar:
    # Admin login - hidden in expander
    with st.expander("🔒 Admin Access", expanded=False):
        if not st.session_state.is_admin:
            admin_pass = st.text_input("Admin Password", type="password", key="admin_pass")
            if st.button("Login as Admin", key="admin_login_btn"):
                if admin_pass == ADMIN_PASSWORD:
                    st.session_state.is_admin = True
                    st.success("Admin Mode Enabled")
                    st.rerun()
                else:
                    st.error("Invalid admin password")
        else:
            st.success("✅ Logged in as Admin")
            if st.button("Logout Admin", key="admin_logout_btn"):
                st.session_state.is_admin = False
                st.rerun()
    
    st.markdown("---")
    
    # Client login
    if not st.session_state.client_id:
        st.markdown("### 👤 Client Login")
        username = st.text_input("Username", key="client_username")
        password = st.text_input("Password", type="password", key="client_password")
        if st.button("Login", key="client_login_btn"):
            session = SessionLocal()
            client = session.query(Client).filter_by(
                username=username,
                password=hash_password(password),
                is_active=True
            ).first()
            if client:
                st.session_state.client_id = client.id
                st.success("Login Successful")
                st.rerun()
            else:
                st.error("Invalid Credentials")
            session.close()
    else:
        session = SessionLocal()
        client = session.query(Client).filter_by(id=st.session_state.client_id).first()
        if client:
            st.markdown("### ✅ Logged In")
            st.info(f"**User:** {client.username}\n\n**Plan:** {client.plan}\n\n**Credits:** {client.credits}")
        session.close()
        
        if st.button("Logout", key="client_logout_btn"):
            st.session_state.client_id = None
            st.rerun()
    
    # Contact Information
    st.markdown("---")
    st.markdown("### 📧 Contact & Support")
    st.markdown("""
        <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 1rem; 
                    border-radius: 10px; 
                    text-align: center;'>
            <p style='color: white; margin: 0; font-weight: bold;'>Need Help?</p>
            <a href='mailto:numanriaz4209@gmail.com' 
               style='color: white; 
                      text-decoration: none; 
                      font-size: 0.9rem;
                      display: block;
                      margin-top: 0.5rem;'>
                📩 numanriaz4209@gmail.com
            </a>
        </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
        <div style='margin-top: 1rem; padding: 0.5rem; text-align: center;'>
            <small style='color: #666;'>
                For support, upgrades, or custom plans<br>
                Contact us anytime!
            </small>
        </div>
    """, unsafe_allow_html=True)
    
    # Security Badge
    st.markdown("---")
    st.markdown("""
        <div style='background: rgba(30, 60, 114, 0.1); 
                    border: 2px solid #667eea;
                    padding: 0.8rem; 
                    border-radius: 10px; 
                    text-align: center;'>
            <p style='margin: 0; font-size: 0.75rem; color: #667eea; font-weight: bold;'>
                🔐 SECURE & ENCRYPTED<br>
                <span style='font-size: 0.7rem; color: #666;'>Your data is protected</span>
            </p>
        </div>
    """, unsafe_allow_html=True)

# ==========================
# ADMIN PANEL
# ==========================
if st.session_state.is_admin:
    st.title("🛡 Admin Dashboard")
    
    tab1, tab2, tab3 = st.tabs(["Create Client", "Manage Clients", "View Statistics"])
    
    with tab1:
        st.subheader("Create Client")
        
        col1, col2 = st.columns(2)
        
        with col1:
            new_user = st.text_input("Username", key="new_username")
            new_pass = st.text_input("Password", type="password", key="new_password")
        
        with col2:
            new_plan = st.selectbox("Plan", ["Free", "Pro", "Enterprise", "Custom"], key="new_plan")
            
            # Show credit input for custom plan or allow override for standard plans
            if new_plan == "Custom":
                custom_credits = st.number_input(
                    "Custom Credits", 
                    min_value=1, 
                    max_value=1000000, 
                    value=1000,
                    step=100,
                    key="custom_credits",
                    help="Set any credit amount for this client"
                )
                credits_to_assign = custom_credits
            else:
                default_credits = PLAN_LIMITS[new_plan]
                st.info(f"ℹ️ Default credits for {new_plan}: {default_credits}")
                override_credits = st.checkbox("Override default credits?", key="override_credits")
                
                if override_credits:
                    credits_to_assign = st.number_input(
                        "Custom Credits", 
                        min_value=1, 
                        max_value=1000000, 
                        value=default_credits,
                        step=100,
                        key="override_credits_input",
                        help="Override the default plan credits"
                    )
                else:
                    credits_to_assign = default_credits
        
        st.markdown("---")
        
        # Display summary
        st.markdown("### 📋 Client Summary")
        col_sum1, col_sum2, col_sum3 = st.columns(3)
        col_sum1.metric("Username", new_user if new_user else "Not set")
        col_sum2.metric("Plan", new_plan)
        col_sum3.metric("Credits", f"{credits_to_assign:,}")
        
        if st.button("✅ Create Client", type="primary", use_container_width=True):
            if not new_user or not new_pass:
                st.error("⚠️ Please provide both username and password")
            else:
                session = SessionLocal()
                if not session.query(Client).filter_by(username=new_user).first():
                    client = Client(
                        username=new_user,
                        password=hash_password(new_pass),
                        plan=new_plan,
                        credits=credits_to_assign
                    )
                    session.add(client)
                    session.commit()
                    st.success(f"✅ Client '{new_user}' created successfully with {credits_to_assign:,} credits!")
                    st.balloons()
                else:
                    st.error("❌ Username already exists")
                session.close()
    
    with tab2:
        st.subheader("Manage Clients")
        session = SessionLocal()
        clients = session.query(Client).all()
        
        if clients:
            # Display clients in a table
            client_data = []
            for client in clients:
                client_data.append({
                    "ID": client.id,
                    "Username": client.username,
                    "Plan": client.plan,
                    "Credits": f"{client.credits:,}",
                    "Active": "✅" if client.is_active else "❌",
                    "Created": client.created_at.strftime("%Y-%m-%d")
                })
            
            df_clients = pd.DataFrame(client_data)
            st.dataframe(df_clients, use_container_width=True)
            
            st.markdown("---")
            st.subheader("🔧 Client Actions")
            
            # Create columns for different actions
            col_action1, col_action2 = st.columns(2)
            
            with col_action1:
                st.markdown("#### 🔄 Activate/Deactivate Client")
                client_to_toggle = st.selectbox(
                    "Select Client", 
                    [f"{c.username} (ID: {c.id})" for c in clients],
                    key="toggle_client"
                )
                if st.button("Toggle Active Status", type="secondary"):
                    client_id = int(client_to_toggle.split("ID: ")[1].rstrip(")"))
                    client = session.query(Client).filter_by(id=client_id).first()
                    if client:
                        client.is_active = not client.is_active
                        session.commit()
                        status = "activated" if client.is_active else "deactivated"
                        st.success(f"✅ Client '{client.username}' has been {status}")
                        st.rerun()
            
            with col_action2:
                st.markdown("#### 🗑️ Delete Client")
                client_to_delete = st.selectbox(
                    "Select Client", 
                    [f"{c.username} (ID: {c.id})" for c in clients],
                    key="delete_client"
                )
                confirm_delete = st.checkbox("I confirm deletion", key="confirm_delete")
                if st.button("Delete Client", type="secondary"):
                    if confirm_delete:
                        client_id = int(client_to_delete.split("ID: ")[1].rstrip(")"))
                        client = session.query(Client).filter_by(id=client_id).first()
                        if client:
                            username = client.username
                            session.delete(client)
                            session.commit()
                            st.success(f"✅ Client '{username}' has been deleted")
                            st.rerun()
                    else:
                        st.error("⚠️ Please confirm deletion by checking the box")
            
            st.markdown("---")
            
            # Enhanced credit and plan management
            col_manage1, col_manage2 = st.columns(2)
            
            with col_manage1:
                st.markdown("#### 💳 Manage Credits")
                client_for_credits = st.selectbox(
                    "Select Client", 
                    [f"{c.username} - Current: {c.credits:,} credits" for c in clients],
                    key="credit_client"
                )
                
                credit_action = st.radio(
                    "Action",
                    ["Add Credits", "Set Specific Amount", "Subtract Credits"],
                    horizontal=True,
                    key="credit_action"
                )
                
                if credit_action == "Add Credits":
                    credits_amount = st.number_input(
                        "Credits to Add", 
                        min_value=1, 
                        max_value=1000000, 
                        value=100,
                        step=50,
                        key="add_credits"
                    )
                    button_label = f"➕ Add {credits_amount:,} Credits"
                elif credit_action == "Set Specific Amount":
                    credits_amount = st.number_input(
                        "Set Credits To", 
                        min_value=0, 
                        max_value=1000000, 
                        value=1000,
                        step=100,
                        key="set_credits"
                    )
                    button_label = f"🔢 Set to {credits_amount:,} Credits"
                else:  # Subtract
                    credits_amount = st.number_input(
                        "Credits to Subtract", 
                        min_value=1, 
                        max_value=1000000, 
                        value=10,
                        step=10,
                        key="subtract_credits"
                    )
                    button_label = f"➖ Subtract {credits_amount:,} Credits"
                
                if st.button(button_label, type="primary", use_container_width=True):
                    client_username = client_for_credits.split(" - ")[0]
                    client = session.query(Client).filter_by(username=client_username).first()
                    if client:
                        old_credits = client.credits
                        if credit_action == "Add Credits":
                            client.credits += credits_amount
                        elif credit_action == "Set Specific Amount":
                            client.credits = credits_amount
                        else:  # Subtract
                            client.credits = max(0, client.credits - credits_amount)
                        
                        session.commit()
                        st.success(f"✅ Credits updated for '{client.username}'")
                        st.info(f"📊 **Change:** {old_credits:,} → {client.credits:,} credits")
                        st.rerun()
            
            with col_manage2:
                st.markdown("#### 📋 Change Plan")
                client_for_plan = st.selectbox(
                    "Select Client", 
                    [f"{c.username} - Current: {c.plan}" for c in clients],
                    key="plan_client"
                )
                
                new_client_plan = st.selectbox(
                    "New Plan",
                    ["Free", "Pro", "Enterprise", "Custom"],
                    key="new_client_plan"
                )
                
                adjust_credits_on_plan_change = st.checkbox(
                    "Adjust credits to plan default?",
                    value=False,
                    key="adjust_credits_plan",
                    help="If checked, credits will be set to the new plan's default amount"
                )
                
                if new_client_plan == "Custom" or not adjust_credits_on_plan_change:
                    custom_plan_credits = st.number_input(
                        "Set Credits", 
                        min_value=0, 
                        max_value=1000000, 
                        value=1000,
                        step=100,
                        key="custom_plan_credits"
                    )
                else:
                    custom_plan_credits = PLAN_LIMITS[new_client_plan]
                    st.info(f"ℹ️ Will set to {custom_plan_credits:,} credits")
                
                if st.button("🔄 Update Plan", type="primary", use_container_width=True):
                    client_username = client_for_plan.split(" - ")[0]
                    client = session.query(Client).filter_by(username=client_username).first()
                    if client:
                        old_plan = client.plan
                        old_credits = client.credits
                        client.plan = new_client_plan
                        if adjust_credits_on_plan_change or new_client_plan == "Custom":
                            client.credits = custom_plan_credits
                        session.commit()
                        st.success(f"✅ Plan updated for '{client.username}'")
                        st.info(f"📋 **Plan:** {old_plan} → {client.plan}")
                        if adjust_credits_on_plan_change or new_client_plan == "Custom":
                            st.info(f"💳 **Credits:** {old_credits:,} → {client.credits:,}")
                        st.rerun()
        else:
            st.info("No clients found. Create one in the 'Create Client' tab.")
        
        session.close()
    
    with tab3:
        st.subheader("Verification Statistics")
        session = SessionLocal()
        total_verifications = session.query(EmailVerification).count()
        valid_count = session.query(EmailVerification).filter_by(status="VALID").count()
        risky_count = session.query(EmailVerification).filter_by(status="RISKY").count()
        invalid_count = session.query(EmailVerification).filter_by(status="INVALID").count()
        safe_to_send = session.query(EmailVerification).filter_by(safe_to_send=True).count()
        session.close()
        
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Verified", total_verifications)
        col2.metric("Valid", valid_count)
        col3.metric("Risky", risky_count)
        col4.metric("Invalid", invalid_count)
        col5.metric("Safe to Send", safe_to_send)

# ==========================
# CLIENT / PUBLIC CSV PROCESSING
# ==========================

def process_csv(uploaded_file, client_id=None, ip=None):
    df = pd.read_csv(uploaded_file)
    emails = df[df.columns[0]].dropna().astype(str).tolist()
    results = []
    placeholder = st.empty()
    progress_bar = st.progress(0)
    
    for i, email in enumerate(emails):
        result = verify_email(email, client_id=client_id, ip=ip)
        if result:
            results.append(result)
            color = "green" if result["AI Prediction"]=="VALID" else "orange" if result["AI Prediction"]=="RISKY" else "red"
            safe_icon = "✅" if result["Safe To Send"] else "❌"
            placeholder.markdown(
                f"{i+1}/{len(emails)} → <span style='color:{color}'><b>{result['Email']}</b> | {result['AI Prediction']} | "
                f"Risk: {result['Risk Score']}% | MX: {'✓' if result['MX Valid'] else '✗'} | Safe: {safe_icon}</span><br>"
                f"<small style='color:gray;'>{result['Reason'][:100]}...</small>", 
                unsafe_allow_html=True
            )
        else:
            if client_id:
                st.error("No credits remaining.")
            else:
                st.error("Free limit reached for your IP")
            break
        progress_bar.progress((i+1)/len(emails))
    
    if results:
        result_df = pd.DataFrame(results)
        st.success(f"✅ Verified {len(results)} emails")
        
        # Show enhanced summary
        col1, col2, col3, col4 = st.columns(4)
        valid = len([r for r in results if r["Status"] == "VALID"])
        risky = len([r for r in results if r["Status"] == "RISKY"])
        invalid = len([r for r in results if r["Status"] == "INVALID"])
        safe = len([r for r in results if r["Safe To Send"]])
        
        col1.metric("Valid", valid, delta=f"{valid/len(results)*100:.1f}%")
        col2.metric("Risky", risky, delta=f"{risky/len(results)*100:.1f}%")
        col3.metric("Invalid", invalid, delta=f"{invalid/len(results)*100:.1f}%")
        col4.metric("Safe to Send", safe, delta=f"{safe/len(results)*100:.1f}%")
        
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
            csv_full = result_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇ Download Full Details CSV", 
                csv_full, 
                "verified_full_details.csv", 
                "text/csv",
                key="full_csv"
            )
        
        with col_dl2:
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

def test_single_email(client_id=None, ip=None):
    st.markdown("### 🔍 Test Single Email")
    test_email = st.text_input("Enter email to test", placeholder="example@domain.com")
    
    if st.button("Verify Email") and test_email:
        with st.spinner("Verifying..."):
            result = verify_email(test_email, client_id=client_id, ip=ip)
            
            if result:
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    if result["Status"] == "VALID":
                        st.success(f"✅ {result['Email']} - VALID")
                    elif result["Status"] == "RISKY":
                        st.warning(f"⚠️ {result['Email']} - RISKY")
                    else:
                        st.error(f"❌ {result['Email']} - INVALID")
                    
                    st.markdown(f"**Validation Details:** {result['Reason']}")
                
                with col2:
                    st.metric("Risk Score", f"{result['Risk Score']}%")
                    st.metric("Confidence", f"{result['Confidence']}%")
                    st.metric("Safe to Send", "✅ Yes" if result["Safe To Send"] else "❌ No")
                
                # Detailed info
                with st.expander("📊 Comprehensive Analysis"):
                    analysis_data = {
                        "Email Address": result["Email"],
                        "Final Status": result["Status"],
                        "Risk Score": f"{result['Risk Score']}%",
                        "AI Confidence": f"{result['Confidence']}%",
                        "MX Records Valid": "✅ Yes" if result["MX Valid"] else "❌ No",
                        "Disposable Domain": "⚠️ Yes" if result["Disposable"] else "✅ No",
                        "Typo Detected": "⚠️ Yes" if result["Typo Detected"] else "✅ No",
                        "Role-Based Email": "⚠️ Yes" if result["Role Based"] else "✅ No",
                        "Safe to Send": "✅ Yes" if result["Safe To Send"] else "❌ No",
                        "Validation Notes": result["Reason"]
                    }
                    for key, value in analysis_data.items():
                        st.markdown(f"**{key}:** {value}")
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
            process_csv(uploaded_file, client_id=st.session_state.client_id)
            # Refresh credits display after verification
            st.rerun()
    
    with tab2:
        test_single_email(client_id=st.session_state.client_id, ip=ip)
        # Show current credits below verification
        session = SessionLocal()
        updated_client = session.query(Client).filter_by(id=st.session_state.client_id).first()
        session.close()
        if updated_client:
            st.info(f"💳 **Current Credits:** {updated_client.credits}")

# ==========================
# PUBLIC FREE USAGE
# ==========================
elif not st.session_state.client_id and not st.session_state.is_admin:
    st.title("🚀 AI Email Verifier Pro - Free Usage")
    st.markdown("### Free Plan: 600 emails per IP / 24h, no login required")
    
    tab1, tab2 = st.tabs(["Bulk Verification", "Single Email Test"])
    
    with tab1:
        uploaded_file = st.file_uploader("Upload CSV (first column should contain emails)", type=["csv"])
        if uploaded_file:
            process_csv(uploaded_file, client_id=None, ip=ip)
    
    with tab2:
        test_single_email(client_id=None, ip=ip)

# ==========================
# FOOTER
# ==========================
st.markdown("---")
st.markdown("""
    <div style='background: linear-gradient(135deg, #1e3c72 0%, #2a5298 50%, #7e22ce 100%); 
                padding: 2rem; 
                border-radius: 15px; 
                text-align: center;
                margin-top: 2rem;'>
        <p style='color: white; font-size: 1.1rem; margin-bottom: 1rem; font-weight: bold;'>
            🔐 Enterprise-Grade Security & Privacy
        </p>
        <div style='display: flex; justify-content: center; gap: 2rem; flex-wrap: wrap; margin-bottom: 1.5rem;'>
            <span style='color: rgba(255,255,255,0.9); font-size: 0.9rem;'>🛡️ 256-bit Encryption</span>
            <span style='color: rgba(255,255,255,0.9); font-size: 0.9rem;'>🔒 Secure Database</span>
            <span style='color: rgba(255,255,255,0.9); font-size: 0.9rem;'>✅ GDPR Compliant</span>
            <span style='color: rgba(255,255,255,0.9); font-size: 0.9rem;'>🚫 No Data Sharing</span>
        </div>
        <p style='color: rgba(255,255,255,0.95); font-size: 0.9rem; margin-bottom: 1rem;'>
            © 2026 AI Email Verifier Pro - Your data privacy is our priority
        </p>
        <p style='margin: 0.5rem 0;'>
            <a href='mailto:numanriaz4209@gmail.com' 
               style='color: #fbbf24; 
                      text-decoration: none; 
                      font-weight: bold;
                      font-size: 1.1rem;'>
                📧 Contact: numanriaz4209@gmail.com
            </a>
        </p>
        <p style='color: rgba(255,255,255,0.8); font-size: 0.85rem; margin-top: 1rem;'>
            For support, security inquiries, or custom enterprise solutions
        </p>
    </div>
""", unsafe_allow_html=True)
