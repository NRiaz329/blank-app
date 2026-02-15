import streamlit as st
import re
import smtplib
import dns.resolver
import pandas as pd

def is_valid_email_format(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

def smtp_verify(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        with smtplib.SMTP() as smtp:
            smtp.set_debuglevel(0)
            smtp.connect(mx_record)
            smtp.helo()
            smtp.mail('test@example.com')
            code, message = smtp.rcpt(email)
            return code == 250
    except Exception:
        return False

def is_disposable_email(email):
    disposable_domains = {'mailinator.com', '10minutemail.com', 'temp-mail.org'}  # Example disposable domains
    domain = email.split('@')[1]
    return domain in disposable_domains

def process_bulk_csv(file):
    df = pd.read_csv(file)
    for index, row in df.iterrows():
        email = row['email']
        if not is_valid_email_format(email):
            st.write(f"Invalid email format: {email}")
        elif not smtp_verify(email):
            st.write(f"SMTP verification failed for: {email}")
        elif is_disposable_email(email):
            st.write(f"Disposable email detected: {email}")
        else:
            st.write(f"Email verified: {email}")

st.title('Email Verification App')
uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
if uploaded_file is not None:
    process_bulk_csv(uploaded_file)