import pandas as pd
import plotly.express as px
import streamlit as st
import os
# Function to read data from Excel file
def load_data():
    
    file_path = os.getenv('EXCEL_FILE_PATH', 'C:/data/all_tables_data.xlsx')  # Default path if env variable is not set
    xls = pd.ExcelFile(file_path)
    orders_df = pd.read_excel(xls, sheet_name='orders')
    return orders_df

# Function to prepare data for heat map
def prepare_data(orders_df):
    # Group by delivery_location and count customers
    location_counts = orders_df.groupby('delivery_location')['customer_id'].nunique().reset_index()
    location_counts.columns = ['location', 'num_customers']
    return location_counts

# Function to plot heat map
def plot_heat_map(location_counts):
    fig = px.choropleth(location_counts,
                        locations='location',
                        locationmode='USA-states',
                        color='num_customers',
                        hover_name='location',
                        scope='usa',
                        title='Customer Locations Heat Map')
    st.plotly_chart(fig)

# Streamlit App
st.title("Customer Locations Heat Map")

# Load data
orders_df = load_data()

# Prepare data
location_counts = prepare_data(orders_df)

# Plot heat map
plot_heat_map(location_counts)
