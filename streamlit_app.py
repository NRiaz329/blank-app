import streamlit as st
import pandas as pd
import json

# Define the function to handle data export based on the selected format

def export_data(data, export_type):
    if export_type == 'CSV':
        return data.to_csv(index=False)
    elif export_type == 'TXT':
        return data.to_string(index=False)
    elif export_type == 'JSON':
        return data.to_json(orient='records')
    elif export_type == 'Excel':
        return data.to_excel(index=False)

# Streamlit application with tabs for different functionalities
st.title('Enhanced Streamlit App')

# Tabs for UI navigation
tabs = st.tabs(['Single Verification', 'Bulk Upload', 'Paste Input', 'Results Export'])

# Single Verification Tab
with tabs[0]:
    st.subheader('Single Verification')
    input_value = st.text_input('Enter value to verify')
    if st.button('Verify'):
        if input_value:
            st.success(f'Value verified: {input_value}')
        else:
            st.error('Please enter a value.')

# Bulk Upload Tab
with tabs[1]:
    st.subheader('Bulk Upload')
    uploaded_file = st.file_uploader('Choose a file', type='csv')
    if uploaded_file is not None:
        data = pd.read_csv(uploaded_file)
        st.write(data)
        if st.button('Process Data'):
            st.success('Data processed successfully!')

# Paste Input Tab
with tabs[2]:
    st.subheader('Paste Input')
    text_area_input = st.text_area('Paste your inputs here')
    if st.button('Submit'):  
        # Process inputs from the text area
        inputs = text_area_input.split('\n')
        st.success('Inputs received!')

# Results Export Tab
with tabs[3]:
    st.subheader('Results Export')
    if 'data' in locals():  # Check if there is data available for export
        export_type = st.selectbox('Select export format', ['CSV', 'TXT', 'JSON', 'Excel'])
        if st.button('Export Data'):
            exported_data = export_data(data, export_type)
            st.download_button(
                label='Download Data',
                data=exported_data,
                file_name=f'data_export.{export_type.lower()}',
                mime='application/octet-stream'
            )

