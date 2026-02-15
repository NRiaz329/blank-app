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

        if not email_list:
            st.warning("No valid email values found in the file.")
            st.stop()

        st.success(f"Loaded {len(email_list)} emails successfully.")

    except Exception as e:
        st.error("Error reading CSV file.")
        st.exception(e)
