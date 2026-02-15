import streamlit as st
import pandas as pd

# Function to validate email format
def is_valid_email(email):
    import re
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

# Function to verify emails and update results
def verify_emails(email_list):
    results = []
    for email in email_list:
        valid = is_valid_email(email)
        results.append((email, valid))
    return results

# Streamlit app layout
st.title('Email Verification App')

# Email upload section
upload_type = st.selectbox('Select Input Type:', ('Paste Emails', 'Upload CSV'))
if upload_type == 'Paste Emails':
    emails_input = st.text_area('Enter emails (one per line):')
    email_list = emails_input.split('\n') if emails_input else []
elif upload_type == 'Upload CSV':
    uploaded_file = st.file_uploader('Choose a CSV file:', type='csv')
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        email_list = df.get('email').tolist()  # Assuming the column header is 'email'

# Verification button
if st.button('Verify Emails'):
    with st.spinner('Verifying emails...'):
        results = verify_emails(email_list)
    df_results = pd.DataFrame(results, columns=['Email', 'Valid'])
    st.write(df_results)

    # Export options
    if st.button('Export Results'):
        export_format = st.selectbox('Select Export Format:', ('CSV', 'JSON', 'TXT', 'Excel'))
        if export_format == 'CSV':
            df_results.to_csv('results.csv', index=False)
            st.success('Results exported to results.csv')
        elif export_format == 'JSON':
            df_results.to_json('results.json', orient='records')
            st.success('Results exported to results.json')
        elif export_format == 'TXT':
            df_results.to_csv('results.txt', index=False, sep='\t')
            st.success('Results exported to results.txt')
        elif export_format == 'Excel':
            df_results.to_excel('results.xlsx', index=False)
            st.success('Results exported to results.xlsx')
