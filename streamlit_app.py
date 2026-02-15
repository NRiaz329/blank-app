import streamlit as st
import pandas as pd

uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)

        # Normalize column names (strip spaces + lowercase)
        df.columns = df.columns.str.strip().str.lower()

        if "email" not in df.columns:
            st.error("CSV must contain a column named 'email'.")
            st.stop()

        # Drop empty values and convert to list
        email_list = (
            df["email"]
            .dropna()
            .astype(str)
            .str.strip()
            .tolist()
        )

        possible_columns = ["email", "emails", "e-mail"]

email_column = None
for col in df.columns:
    if col in possible_columns:
        email_column = col
        break

if email_column is None:
    st.error("No email column detected in CSV.")
    st.stop()

email_list = df[email_column].dropna().astype(str).str.strip().tolist()

