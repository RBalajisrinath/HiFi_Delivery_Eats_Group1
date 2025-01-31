import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
# Function to read data from Excel file
def load_data():
    
    file_path = os.path.join('C:\\', 'data', 'all_tables_data.xlsx')
    xls = pd.ExcelFile(file_path)
    orders_df = pd.read_excel(xls, sheet_name='orders')
    order_items_df = pd.read_excel(xls, sheet_name='order_items')
    menu_items_df = pd.read_excel(xls, sheet_name='menu_items')

    # Ensure column names are consistent
    menu_items_df = menu_items_df.rename(columns={'menu_item_id': 'item_id'})
    order_items_df = order_items_df.rename(columns={'menu_item_id': 'item_id'})

    # Merge dataframes to get complete view
    merged_df = pd.merge(order_items_df, orders_df, on='order_id')
    merged_df = pd.merge(merged_df, menu_items_df, on='item_id')

    # Convert 'order_date' to datetime
    merged_df['order_date'] = pd.to_datetime(merged_df['order_date'], errors='coerce')

    # Drop rows with NaT values in 'order_date'
    merged_df = merged_df.dropna(subset=['order_date'])

    return merged_df

# Data processing functions
def fetch_top_selling_items(df, year, month):
    filtered_data = df[(df['order_date'].dt.year == int(year)) & (df['order_date'].dt.month == int(month))]
    top_items = filtered_data.groupby('name').agg(total_quantity=('quantity', 'sum')).reset_index()
    top_items = top_items.sort_values(by='total_quantity', ascending=False)
    return top_items

def plot_top_selling_items(df, year, month):
    top_items = fetch_top_selling_items(df, year, month)
    fig = px.pie(top_items, names='name', values='total_quantity', title=f'Top Selling Items in {month}/{year}')
    st.plotly_chart(fig)

def fetch_most_sold_item(df, year, month):
    top_items = fetch_top_selling_items(df, year, month)
    most_sold_item = top_items.iloc[0]
    return most_sold_item['name'], most_sold_item['total_quantity']

def plot_most_sold_item(df, year, month):
    item_name, total_quantity = fetch_most_sold_item(df, year, month)
    fig = go.Figure(go.Indicator(
        mode="number",
        value=total_quantity,
        title={"text": f"Most Sold Item: {item_name}"},
        number={'suffix': " units"}
    ))
    st.plotly_chart(fig)

# Streamlit App
st.title("Top Selling Items Visualization")

# Load data directly from specified file path
df = load_data()

# Form for selecting year and month
# Print column names for verification

if not df.empty:
    if 'order_date' in df.columns:
        df['order_date'] = pd.to_datetime(df['order_date'], errors='coerce')  # Ensure datetime conversion

        year = st.selectbox("Select Year", options=sorted(df['order_date'].dt.year.dropna().astype(str).unique()))
        month = st.selectbox("Select Month", options=[str(i).zfill(2) for i in range(1, 13)])

        if year and month:
            st.header("Top Selling Items Pie Chart")
            plot_top_selling_items(df, year, month)
            
            st.header("Most Sold Item")
            plot_most_sold_item(df, year, month)
    else:
        st.error("The 'order_date' column is missing in the provided data.")
else:
    st.error("Uploaded DataFrame is empty.")
