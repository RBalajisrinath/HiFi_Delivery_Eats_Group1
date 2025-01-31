import sqlite3
import random
import jwt
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from dotenv import load_dotenv
import os
import string
import plotly.express as px
from matplotlib.backends.backend_pdf import PdfPages
import bcrypt
import secrets
import matplotlib.pyplot as plt 
import io 
import matplotlib 
matplotlib.use('Agg')
import seaborn as sns
import base64
import pandas as pd
import matplotlib.dates as mdates
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import tempfile
from datetime import datetime, timedelta
from textblob import TextBlob
import re
import streamlit as st
import plotly.graph_objs as go
import plotly.io as pio
from functools import wraps
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__, static_folder='static')
app.secret_key = 'supersecretkey'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'existing_database.db')
JWT_SECRET = 'your_jwt_secret'  # Add a secret key for JWT

# Configuring Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

EMAIL_ADDRESS = "hifieats21@gmail.com"  # Replace with your Gmail address
EMAIL_PASSWORD = "morz awdj fqgb srcv"  # Replace with your Gmail password

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'hifieats21@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'morz awdj fqgb srcv'  # Replace with your email password
app.config['MAIL_DEFAULT_SENDER'] = 'hifieats21@gmail.com'  # Replace with your email

mail = Mail(app)
# Configuring OAuth


# Configuring OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='131047593159-l1ud0f5hs3e3pq39k6ko5kchka7pd07d.apps.googleusercontent.com',  # Your Google client ID
    client_secret='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',  # Your Google client secret
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_basic'
    }
)


facebook = oauth.register(
    name='facebook',
    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),  # Your Facebook client ID
    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET'),  # Your Facebook client secret
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://127.0.0.1:5000/facebook/callback',  # Your redirect URI
    client_kwargs={ 'scope': 'openid email profile', 'token_endpoint_auth_method': 'client_secret_basic', 'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo', 'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs'}

)

twitter = oauth.register(
    name='twitter',
    client_id=os.environ.get('TWITTER_CLIENT_ID'),  # Your Twitter client ID
    client_secret=os.environ.get('TWITTER_CLIENT_SECRET'),  # Your Twitter client secret
    request_token_url='https://api.twitter.com/oauth/request_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    access_token_url='https://api.twitter.com/oauth/access_token',
    access_token_params=None,
    redirect_uri='http://localhost:5000/twitter/callback',  # Your redirect URI
    client_kwargs={'scope': 'email'}
)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_token(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return None

# Function to generate a random OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Function to send OTP email
def send_otp_email(recipient, otp):
    msg = Message('Your OTP Code', recipients=[recipient])
    msg.body = f'Your OTP code is {otp}'
    msg.sender = app.config['MAIL_DEFAULT_SENDER']  # Ensure sender is specified
    mail.send(msg)

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        contact_info = request.form['contact_info']
        
        # Generate OTP and store it in the session
        otp = generate_otp()
        session['otp'] = otp
        session['contact_info'] = contact_info
        
        # Send OTP to user's email
        send_otp_email(contact_info, otp)
        
        flash('OTP sent to your registered contact.', 'success')
        return redirect(url_for('verify_otp'))
    
    return render_template('forgot.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        verification_code = request.form['verification_code']
        
        # Retrieve the OTP from the session
        stored_otp = session.get('otp')
        
        if verification_code == stored_otp:
            flash('Verification successful!', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
    
    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not email or not new_password or not confirm_password:
            flash('All fields are required!', 'error')
            return redirect(url_for('reset_password'))

        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('reset_password'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            hashed_password = hash_password(new_password)
            cursor.execute('UPDATE Users SET password_hash = ? WHERE email = ?', (hashed_password, email))
            conn.commit()
            conn.close()
            flash('Password reset successful. Please sign in.', 'success')
            return redirect(url_for('signin'))
        else:
            conn.close()
            flash('Email not found!', 'error')
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html')


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        full_name = request.form['full-name']
        phone_number = request.form['phone-number']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Email already exists!', 'error')
            return redirect(url_for('signup'))
        
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO Users (email, password_hash, full_name, phone_number, is_active) VALUES (?, ?, ?, ?, ?)',
                       (email, hashed_password, full_name, phone_number, 0))  # Initially inactive
        conn.commit()

        # Send confirmation email
        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm your email', sender=os.environ.get('EMAIL_USER'), recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f"Hello, welcome to HiFi Eats! Please confirm your email by clicking the link below:\n\n{link}"
        mail.send(msg)
        
        flash('Registration successful! A confirmation email has been sent to your email address.', 'success')
        return redirect(url_for('signin'))
    
    return render_template('signup.html')

# @app.route('/signin', methods=['GET', 'POST'])
# def signin():
#     if request.method == 'POST':
#         email = request.form['phone-email']
#         password = request.form['password']
        
#         conn = get_db()
#         cursor = conn.cursor()
#         cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
#         user = cursor.fetchone()
        
#         if user and verify_password(password, user['password_hash']):
#             session['user_id'] = user['user_id']
#             session['is_admin'] = user['is_admin']

#             conn.close()
#             flash('Sign in successful', 'success')
#             return redirect(url_for('dashboard'))  # Redirect to the dashboard route
#         else:
#             conn.close()
#             flash('Invalid credentials', 'error')
#             return redirect(url_for('signin'))
#     return render_template('signin.html')

# Dummy promotions for the example
PROMOTIONS = {
    "offers": [
        {
            "id": 1,
            "title": "Welcome Bonus",
            "description": "Get 20% off on your first order!",
            "promo_code": "WELCOME20",
            "discount_amount": 20.0,
            "discount_type": "percentage",
            "valid_from": (datetime.now()).strftime('%Y-%m-%d'),
            "valid_until": (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
            "usage_limit": 1,
            "min_order_amount": 0.0,
            "image_url": "/static/images/welcome.jpg"
        },
        {
            "id": 2,
            "title": "Summer Special",
            "description": "Flat ₹100 off on orders above ₹500",
            "promo_code": "SUMMER100",
            "discount_amount": 100.0,
            "discount_type": "fixed",
            "valid_from": (datetime.now()).strftime('%Y-%m-%d'),
            "valid_until": (datetime.now() + timedelta(days=60)).strftime('%Y-%m-%d'),
            "usage_limit": None,
            "min_order_amount": 500.0,
            "image_url": "/static/images/summer.jpg"
        }
    ]
}
# Route for sign-in page
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['phone-email']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user and verify_password(password, user['password_hash']):
            session['user_id'] = user['user_id']
            session['user'] = user['email']  # Set the user email in session
            session['is_admin'] = user['is_admin']
            session['claimed_promotions'] = {} 

            conn.close()
            flash('Sign in successful', 'success')
            return redirect(url_for('dashboard'))  # Redirect to the dashboard route
        else:
            conn.close()
            flash('Invalid credentials', 'error')
            return redirect(url_for('signin'))
    return render_template('signin.html')

# Decorator to check if the user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

# Function to get active promotions
def get_active_promotions(user_id):
    current_date = datetime.now().strftime('%Y-%m-%d')
    claimed_promos = session.get('claimed_promotions', {})
    
    active_promotions = [
        {**promo, 'is_claimed': str(promo['id']) in claimed_promos}
        for promo in PROMOTIONS['offers']
        if promo['valid_from'] <= current_date <= promo['valid_until']
    ]
    return active_promotions

@app.route('/dashboard')
@login_required
def dashboard():
    if 'user' in session:  # Checking if the user is logged in
        user_email = session['user']
        
        # If the user is an admin, redirect to the admin dashboard
        if session.get('is_admin'):
            print("Admin user detected, redirecting to admin dashboard")
            return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard if the user is an admin
        
        # If the user is a regular user, proceed to display the user dashboard
        print("Regular user detected, rendering user dashboard")
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute('SELECT * FROM Users WHERE user_id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    # Get active promotions
    active_promotions = get_active_promotions(session['user_id'])
    
    # Get user's recent orders
    cursor.execute('''SELECT * FROM Orders WHERE customer_id = ? ORDER BY order_date DESC LIMIT 5''', (session['user_id'],))
    recent_orders = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, promotions=active_promotions, recent_orders=recent_orders)

@app.route('/claim_promotion/<int:promotion_id>')
@login_required
def claim_promotion(promotion_id):
    if 'user' not in session:
        flash('Please log in to claim promotions', 'error')
        return redirect(url_for('signin'))

    user_email = session['user']
    claimed_promos = session.get('claimed_promotions', {})
    
    # Find the promotion
    promotion = next(
        (p for p in PROMOTIONS['offers'] if p['id'] == promotion_id), 
        None
    )
    
    if not promotion:
        flash('Promotion not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if already claimed
    if str(promotion_id) in claimed_promos:
        flash('You have already claimed this promotion', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if promotion is valid
    current_date = datetime.now().strftime('%Y-%m-%d')
    if not (promotion['valid_from'] <= current_date <= promotion['valid_until']):
        flash('This promotion has expired', 'error')
        return redirect(url_for('dashboard'))
    
    # Store the claimed promotion in session
    claimed_promos[str(promotion_id)] = {
        'claimed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'used': False
    }
    session['claimed_promotions'] = claimed_promos
    
    # Send email notification
    try:
        msg = Message(
            f"Your Claimed Promotion: {promotion['title']}",
            sender=app.config['MAIL_USERNAME'],
            recipients=[user_email]
        )
        
        discount_text = (
            f"{promotion['discount_amount']}% off" 
            if promotion['discount_type'] == 'percentage'
            else f"₹{promotion['discount_amount']} off"
        )
        
        msg.body = f"""
        Dear {user_email},

        Congratulations! You have successfully claimed the following promotion:

        Promotion Details:
        Title: {promotion['title']}
        Description: {promotion['description']}
        Promo Code: {promotion['promo_code']}
        Discount: {discount_text}
        Minimum Order Amount: ₹{promotion['min_order_amount']}
        Valid Until: {promotion['valid_until']}
        
        To redeem this offer, use the promo code during checkout.

        Thank you for being a valued customer!

        Regards,
        HiFi Eats Team
        """
        
        mail.send(msg)
        flash('Promotion claimed successfully! Check your email for the promo code.', 'success')
    except Exception as e:
        print(f"Error sending email: {e}")
        flash('Promotion claimed but there was an error sending the email. Please contact support.', 'warning')
    
    return redirect(url_for('dashboard'))



@app.route('/assign_role/<int:user_id>', methods=['GET', 'POST'])
def assign_role(user_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        role_id = request.form['role']
        
        # Assign role to user
        cursor.execute('UPDATE Users SET role_id = ? WHERE user_id = ?', (role_id, user_id))
        conn.commit()
        conn.close()

        flash('Role assigned successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    else:
        # Retrieve user and role details to populate the form
        cursor.execute('SELECT * FROM Users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        
        cursor.execute('SELECT * FROM roles')
        roles = cursor.fetchall()
        conn.close()

        return render_template('assign_role.html', user=user, roles=roles)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if request.method == 'POST':
        # Process the form data and update the user
        email = request.form['email']
        full_name = request.form['full_name']
        phone_number = request.form['phone_number']
        is_active = request.form.get('is_active', False)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE Users SET email = ?, full_name = ?, phone_number = ?, is_active = ? WHERE user_id = ?',
                       (email, full_name, phone_number, is_active, user_id))
        conn.commit()
        conn.close()

        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        # Retrieve user details to populate the form
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        return render_template('edit_user.html', user=user)

@app.route('/assign_role_page', methods=['GET', 'POST'])
def assign_role_page():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM Users')
    users = cursor.fetchall()
    
    cursor.execute('SELECT * FROM roles')
    roles = cursor.fetchall()
    
    conn.close()
    
    return render_template('assign_role_page.html', users=users, roles=roles)
@app.route('/user_list')
def user_list():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users')
    users = cursor.fetchall()
    conn.close()

    return render_template('user_list.html', users=users)



def get_most_sold_item(data):
    df = pd.DataFrame(data, columns=['name', 'total_quantity_sold'])
    most_sold_item = df.loc[df['total_quantity_sold'].idxmax()]
    return most_sold_item


@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT Users.user_id, Users.email, Users.full_name, Users.phone_number, roles.role_name
        FROM Users
        LEFT JOIN roles ON Users.role_id = roles.role_id
    ''')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', users=users)

def is_admin():
    user_email = session.get('user')
    if not user_email:
        print("No user in session")
        return False
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM Users WHERE email = ?', (user_email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"User {user_email} is {'an admin' if user['is_admin'] == 1 else 'not an admin'}")
    return user and user['is_admin'] == 1

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/admin/deactivate_user/<int:user_id>')
def deactivate_user(user_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        print("hello")
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE Users SET is_active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deactivated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Google login route
@app.route('/google_login')
def google_login():
    nonce = secrets.token_urlsafe()
    session['nonce'] = nonce
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google/callback')
def google_auth():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    email = user_info['email']
    full_name = user_info.get('name', 'Google User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO Users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Google.', 'success')
    return redirect(url_for('dashboard'))

# Facebook login route
@app.route('/facebook_login')
def facebook_login():
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)

@app.route('/facebook/callback')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    user_info = oauth.facebook.get('me?fields=id,name,email').json()

    email = user_info['email']
    full_name = user_info.get('name', 'Facebook User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO Users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Facebook.', 'success')
    return redirect(url_for('dashboard'))

# Twitter login route
@app.route('/twitter_login')
def twitter_login():
    redirect_uri = url_for('twitter_auth', _external=True)
    return oauth.twitter.authorize_redirect(redirect_uri)

@app.route('/twitter/callback')
def twitter_auth():
    token = oauth.twitter.authorize_access_token()
    user_info = oauth.twitter.get('account/verify_credentials.json').json()

    email = user_info.get('email', f"{user_info['screen_name']}@twitter.com")
    full_name = user_info.get('name', 'Twitter User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO Users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Twitter.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        # Update user status to confirmed in the database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE Users SET is_active = 1 WHERE email = ?', (email,))
        conn.commit()
        conn.close()
    except SignatureExpired:
        flash('The confirmation link has expired.')
        return redirect(url_for('signup'))

    flash('Email confirmed successfully! You can now log in.')
    return redirect(url_for('signin'))

# @app.route('/dashboard')
# def dashboard():
#     if 'user' in session:
#         user_email = session['user']
#         if session.get('is_admin'):
#             print("Admin user detected, redirecting to admin dashboard")
#             return redirect(url_for('admin_dashboard'))
#         print("Regular user detected, rendering user dashboard")
#         return render_template('dashboard.html', user_email=user_email)
#     else:
#         flash('You need to log in first.', 'error')
#         return redirect(url_for('signin'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM Users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

def fetch_delivery_data_for_agent(agent_id):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    SELECT Delivery_ID, Order_ID, Delivery_Agent_ID, Status, Pickup_time, Delivery_time
    FROM Delivery
    WHERE Delivery_Agent_ID = ?
    '''
    cursor.execute(query, (agent_id,))
    data = cursor.fetchall()
    conn.close()
    
    return data


def generate_average_delivery_time_chart(average_delivery_time):
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.barh(['Average Delivery Time'], [average_delivery_time], color='skyblue')
    ax.set_xlim(0, max(60, average_delivery_time * 1.2))  # Ensure some padding on the right
    ax.set_xlabel('Time (minutes)')
    plt.title('Average Delivery Time')
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer
def generate_on_time_delivery_rate_chart(on_time_rate):
    labels = ['On-Time', 'Late']
    sizes = [on_time_rate, 1 - on_time_rate]
    colors = ['lightgreen', 'lightcoral']
    explode = (0.1, 0)  # explode the On-Time slice
    
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('On-Time Delivery Rate')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

def calculate_on_time_delivery_rate(data, on_time_threshold=30):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No deliveries, so on-time rate is 0
    
    on_time_deliveries = df[df['delivery_duration'] <= on_time_threshold]
    on_time_rate = len(on_time_deliveries) / len(df)
    
    return on_time_rate

def calculate_average_delivery_time(data):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No Delivery, so average delivery time is 0
    
    average_delivery_time = df['delivery_duration'].mean()
    
    return average_delivery_time

@app.route('/delivery_metrics', methods=['GET', 'POST'])
def delivery_metrics():
    if request.method == 'POST':
        agent_id = request.form.get('agent_id')
        data = fetch_delivery_data_for_agent(agent_id)
        average_delivery_time = calculate_average_delivery_time(data)
        on_time_rate = calculate_on_time_delivery_rate(data)
        
        if data:
            avg_time_img_buffer = generate_average_delivery_time_chart(average_delivery_time)
            on_time_rate_img_buffer = generate_on_time_delivery_rate_chart(on_time_rate)
            
            avg_time_plot_url = base64.b64encode(avg_time_img_buffer.getvalue()).decode()
            on_time_rate_plot_url = base64.b64encode(on_time_rate_img_buffer.getvalue()).decode()
        else:
            avg_time_plot_url = None
            on_time_rate_plot_url = None
        
        return render_template('delivery_metrics.html', 
                               avg_time_plot_url=avg_time_plot_url, 
                               on_time_rate_plot_url=on_time_rate_plot_url, 
                               agent_id=agent_id)
    
    return render_template('delivery_metrics.html', 
                           avg_time_plot_url=None, 
                           on_time_rate_plot_url=None, 
                           agent_id=None)

def update_delivery_status(delivery_id, status, delivery_time=None):
    conn = get_db()
    cursor = conn.cursor()
    
    if delivery_time:
        query = '''
        UPDATE Delivery
        SET Status = ?, Delivery_time = ?
        WHERE Delivery_ID = ?
        '''
        cursor.execute(query, (status, delivery_time, delivery_id))
    else:
        query = '''
        UPDATE Delivery
        SET Status = ?
        WHERE Delivery_ID = ?
        '''
        cursor.execute(query, (status, delivery_id))
    
    conn.commit()
    conn.close()

def add_delivery(order_id, agent_id, status, pickup_time, delivery_time):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    INSERT INTO Delivery (Order_ID, Delivery_Agent_ID, Status, Pickup_time, Delivery_time)
    VALUES (?, ?, ?, ?, ?)
    '''
    cursor.execute(query, (order_id, agent_id, status, pickup_time, delivery_time))
    conn.commit()
    conn.close()

@app.route('/restaurant_dashboard')
def restaurant_dashboard():
    return render_template('restaurant_dashboard.html')

@app.route('/admin_notifications')
def admin_notifications():
    return render_template('admin_notifications.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('signin'))

@app.route('/anomalies')
def anomalies():
    return render_template('anomalies.html')

# Mock data to simulate orders
mock_orders = [
    {
        "order_id": 1,
        "customer_id": 101,
        "customer_email": "user1@example.com",
        "order_date": (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d'),
    },
    {
        "order_id": 2,
        "customer_id": 102,
        "customer_email": "user2@example.com",
        "total_price": 3500.00,  # Anomaly: High price
        "order_status": "processing",
        "delivery_location": "456 Oak St, City",
        "order_date": datetime.now().strftime('%Y-%m-%d'),
        "order_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
]

@app.route('/api/order-anomalies', methods=['GET'])
def get_order_anomalies():
    mock_orders = [
        # Example mock orders
        {'order_id': 1, 'total_price': 100},
        {'order_id': 2, 'total_price': 200},
        # Add more mock orders as needed
    ]
    
    try:
        avg_price = sum(order['total_price'] for order in mock_orders if 'total_price' in order) / len(mock_orders)
    except ZeroDivisionError:
        avg_price = 0  # Handle case where mock_orders is empty

    return jsonify({'average_price': avg_price})

@app.route('/api/add-test-order')
def add_test_order():
    new_order = {
        "order_id": len(mock_orders) + 1,
        "customer_id": random.randint(101, 105),
        "customer_email": f"user{random.randint(1,5)}@example.com",
        "total_price": random.uniform(100, 5000),
        "order_status": random.choice(["pending", "processing", "completed"]),
        "delivery_location": f"{random.randint(100,999)} Test St, City",
        "order_date": datetime.now().strftime('%Y-%m-%d'),
        "order_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    mock_orders.append(new_order)
    return jsonify({"message": "Test order added", "order": new_order})

@app.route('/api/investigate-order/<int:order_id>', methods=['POST'])
def investigate_order(order_id):
    for order in mock_orders:
        if order['order_id'] == order_id:
            order['order_status'] = 'Under Investigation'
            return jsonify({
                'success': True,
                'message': f'Order #{order_id} is now under investigation',
                'order': order
            })
    
    return jsonify({
        'success': False,
        'message': f'Order #{order_id} not found'
    }), 404

@app.route('/api/complete-investigation/<int:order_id>', methods=['POST'])
def complete_investigation(order_id):
    for order in mock_orders:
        if order['order_id'] == order_id:
            action = request.json.get('action', 'approved')  # 'approved' or 'flagged'
            order['order_status'] = f'Investigation {action}'
            order['investigation_notes'] = request.json.get('notes', '')
            order['investigation_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                'success': True,
                'message': f'Order #{order_id} investigation completed: {action}',
                'order': order
            })
    
    return jsonify({
        'success': False,
        'message': f'Order #{order_id} not found'
    }), 404


@app.route('/sales_trends', methods=['GET', 'POST'])
def sales_trends():
    if request.method == 'POST':
        period = request.form.get('period', 'monthly')
        chart_type = request.form.get('chart_type', 'line')
        email = request.form.get('email')
        download = request.form.get('download', 'false')

        # Validate email
        if not is_valid_email(email):
            return "Invalid email address", 400

        # Generate the chart
        pdf_buffer, img_buffer = generate_sales_trend_line_chart(period)

        if pdf_buffer is None:
            return "Failed to generate chart", 500

        # Save the PDF to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp:
            tmp.write(pdf_buffer.getvalue())
            tmp_path = tmp.name

        # Send the email with the attachment
        send_email_with_attachment(email, tmp_path)

        # Check if the user clicked the download button
        if download == 'true':
            return send_file(io.BytesIO(pdf_buffer.getvalue()), 
                             mimetype='application/pdf',
                             as_attachment=True,
                             download_name='sales_trend_chart.pdf')

        # Otherwise, show the generated chart
        plot_url = base64.b64encode(img_buffer.getvalue()).decode()
        return render_template('sales_trends.html', plot_url=plot_url)

    # For GET requests, render the form
    return render_template('sales_trends.html')


def send_email_with_attachment(recipient_email, attachment_path):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email
    msg['Subject'] = "Sales Report"

    # Attach PDF file
    part = MIMEBase('application', 'octet-stream')
    with open(attachment_path, 'rb') as attachment:
        part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f'attachment; filename="sales_report.pdf"')
    msg.attach(part)

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

@app.route('/download_sales_report')
def download_sales_report():
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Fetch sales data
    period = request.args.get('period', 'monthly')  # Get the period from query params (daily, weekly, monthly)
    chart_type = request.args.get('chart_type', 'line')  # Get the chart type from query params (line, bar)
    sales_data = fetch_sales_data(period)
    df = pd.DataFrame(sales_data, columns=['period', 'total_sales'])
    
    # Add title and sales data table to the PDF
    p.setFont("Helvetica", 14)
    p.drawString(30, height - 40, f"Sales Report ({period.capitalize()})")
    
    p.setFont("Helvetica", 10)
    x, y = 30, height - 60
    for index, row in df.iterrows():
        p.drawString(x, y, f"{row['period']}: {row['total_sales']}")
        y -= 12

    # Generate the chart and save as a temporary file
    plot_url, img_buffer = generate_sales_trend_chart_with_peaks(period, chart_type)
    temp_file_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    with open(temp_file_path, 'wb') as f:
        f.write(img_buffer.getvalue())
    
    # Add the chart image to the PDF
    p.drawImage(temp_file_path, x, y - 200, width - 2 * x, 200)
    
    p.showPage()
    p.save()
    
    # Save the buffer content to a temporary PDF file
    pdf_temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    with open(pdf_temp_file.name, 'wb') as f:
        f.write(buffer.getvalue())
    
    # Send email with PDF attachment
    recipient_email = "recipient_email@gmail.com"  # Replace with recipient email address
    send_email_with_attachment(recipient_email, pdf_temp_file.name)
    
    # Clean up the temporary files
    buffer.seek(0)
    os.remove(temp_file_path)
    os.remove(pdf_temp_file.name)
    
    return send_file(buffer, as_attachment=True, download_name="sales_report.pdf", mimetype='application/pdf')

def highlight_peaks(df, ax):
    peak_threshold = df['total_sales'].mean() + df['total_sales'].std()  # Example threshold
    peaks = df[df['total_sales'] > peak_threshold]
    
    for idx, row in peaks.iterrows():
        ax.annotate('Peak', xy=(row['period'], row['total_sales']), xytext=(row['period'], row['total_sales'] + 5),
                    arrowprops=dict(facecolor='red', shrink=0.05),
                    horizontalalignment='center', verticalalignment='bottom')
        
def generate_sales_trend_chart_with_peaks(period='monthly', chart_type='line'):
    data = fetch_sales_data(period)
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    
    # Convert period to datetime
    try:
        if period == 'daily':
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m-%d')
        elif period == 'weekly':
            df['period'] = pd.to_datetime(df['period'] + '-1', format='%Y-%W-%w')  # Monday as start of the week
        else:  # monthly
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m')
    except ValueError as e:
        print(f"Error parsing dates: {e}")
        return None  # Handle the error gracefully
    
    plt.figure(figsize=(10, 6))
    
    if chart_type == 'bar':
        ax = df.plot(x='period', y='total_sales', kind='bar', color='skyblue')
    else:  # line chart
        ax = df.plot(x='period', y='total_sales', marker='o', linestyle='-', color='skyblue')
    
    highlight_peaks(df, ax)
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    
    # Set date format on x-axis
    if period == 'daily':
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    elif period == 'weekly':
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%W'))
    else:  # monthly
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    plot_url = base64.b64encode(img_buffer.getvalue()).decode()
    
    return plot_url, img_buffer


def generate_sales_trend_chart(period='monthly', chart_type='line'):
    data = fetch_sales_data(period)
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    
    plt.figure(figsize=(10, 6))
    if chart_type == 'bar':
        plt.bar(df['period'], df['total_sales'], color='skyblue')
    else:  # Default to line chart
        plt.plot(df['period'], df['total_sales'], marker='o', linestyle='-', color='skyblue')
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    
    return plot_url

def fetch_sales_data(period='monthly'):
    conn = get_db()
    cursor = conn.cursor()
    
    if period == 'daily':
        query = '''
        SELECT strftime('%Y-%m-%d', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM Orders o
        GROUP BY period
        ORDER BY period;
        '''
    elif period == 'weekly':
        query = '''
        SELECT strftime('%Y-%W', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM Orders o
        GROUP BY period
        ORDER BY period;
        '''
    else:  # Default to monthly
        query = '''
        SELECT strftime('%Y-%m', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM Orders o
        GROUP BY period
        ORDER BY period;
        '''
    
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    
    return data

import pandas as pd
import matplotlib.pyplot as plt
import io
from matplotlib.backends.backend_pdf import PdfPages

def generate_sales_trend_line_chart(period='monthly'):
    data = fetch_sales_data(period)
    if not data:
        return None, None
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    try:
        if period == 'daily':
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m-%d')
        elif period == 'weekly':
            df['period'] = pd.to_datetime(df['period'] + '-1', format='%Y-%W-%w')
        else:  # monthly
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m')
    except ValueError as e:
        print(f"Error parsing dates: {e}")
        return None, None

    plt.figure(figsize=(10, 6))
    ax = df.plot(x='period', y='total_sales', marker='o', linestyle='-', color='skyblue')
    
    highlight_peaks(df, ax)
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    pdf_buffer = io.BytesIO()
    with PdfPages(pdf_buffer) as pdf:
        pdf.savefig(plt.gcf())
    pdf_buffer.seek(0)
    
    return pdf_buffer, img_buffer

import re

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def fetch_top_selling_items_by_month(month):
    # Connect to the database
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()

    # Query to fetch top-selling items for the given month
    query = '''
    SELECT mi.Name, SUM(oi.quantity) as total_quantity_sold
    FROM Order_Items oi
    JOIN Orders o ON oi.order_id = o.order_id
    JOIN MenuItems mi ON oi.item_id = mi.MenuItemID
    WHERE strftime('%m', o.order_date) = ?
    GROUP BY mi.Name
    ORDER BY total_quantity_sold DESC
    '''
    
    # Execute the query with the month parameter
    cursor.execute(query, (month,))
    data = cursor.fetchall()
    
    # Close the database connection
    conn.close()
    
    # Return the fetched data
    return [{'name': row[0], 'total_quantity_sold': row[1]} for row in data]

def generate_top_selling_items_pie_chart(month):
    data = fetch_top_selling_items_by_month(month)
    
    if not data:
        print(f"No data found for month: {month}")
        return None  # Handle case when there is no data for the selected month

    df = pd.DataFrame(data, columns=['name', 'total_quantity_sold'])
    most_sold_item = df.loc[df['total_quantity_sold'].idxmax()]
    explode = [0.1 if name == most_sold_item['name'] else 0 for name in df['name']]
    plt.figure(figsize=(10, 8))
    plt.pie(df['total_quantity_sold'], labels=df['name'], labeldistance=0.8, explode=explode, autopct='%1.1f%%', startangle=140, colors=sns.color_palette('viridis', len(df)))
    plt.title(f'Top Selling Items for {month}')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

@app.route('/top_selling_items', methods=['GET', 'POST'])
def top_selling_items():
    if request.method == 'POST':
        month = request.form.get('month')
        print(f"Form submitted with month: {month}")
        img_buffer = generate_top_selling_items_pie_chart(month)
        if img_buffer:
            plot_url = base64.b64encode(img_buffer.getvalue()).decode()
            print(f"Generated plot URL: {plot_url[:30]}...")  # Print the first 30 characters of the plot URL
        else:
            plot_url = None
            print("No plot URL generated.")
        return render_template('top_selling_items.html', plot_url=plot_url, selected_month=month)
    
    return render_template('top_selling_items.html', plot_url=None, selected_month=None)

from flask import Flask, render_template, request, g
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

app.secret_key = 'ce2d0b836d67ded3da8d9170896a014d' 
def get_db():
    conn = sqlite3.connect('existing_database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/feedback-form")
def feedback_form():
    return render_template("feedback_form.html")


@app.route("/submit-feedback", methods=["POST"])
def submit_feedback():
    order_id = request.form.get("order_id")
    rating = request.form.get("rating")
    comment = request.form.get("comment")

    if not (order_id and rating):
        return jsonify({"error": "Missing required fields!"}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT customer_id FROM Orders WHERE order_id = ?", (order_id,))
        result = cursor.fetchone()

        if not result:
            return jsonify({"error": f"Order ID {order_id} not found!"}), 404
        
        customer_id = result["customer_id"]
        cursor.execute(
            "INSERT INTO feedback (order_id, customer_id, rating, comment) VALUES (?, ?, ?, ?)",
            (order_id, customer_id, rating, comment)
        )
        db.commit()
        return jsonify({"message": "Thank you for your feedback!"}), 200
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

@app.route("/feedback-analysis")
def feedback_analysis():
    analysis_results = generate_feedback_analysis('existing_database.db')
    return render_template('feedback_visualization.html', **analysis_results)


import sqlite3
import pandas as pd



def get_sentiment_category(sentiment_polarity):
    if sentiment_polarity > 0:
        return 'Positive'
    elif sentiment_polarity < 0:
        return 'Negative'
    else:
        return 'Neutral'

def generate_feedback_analysis(db_path):
    conn = sqlite3.connect(db_path)
    feedback_df = pd.read_sql_query('SELECT * FROM feedback', conn)
    conn.close()

    # Calculate the average rating
    average_rating = feedback_df['rating'].mean()

    # Perform sentiment analysis on comments
    def get_sentiment(comment):
        analysis = TextBlob(comment)
        return analysis.sentiment.polarity

    feedback_df['sentiment'] = feedback_df['comment'].apply(get_sentiment)
    feedback_df['sentiment_category'] = feedback_df['sentiment'].apply(get_sentiment_category)

    # Plot rating distribution
    rating_counts = feedback_df['rating'].value_counts().sort_index()
    rating_distribution = go.Figure([go.Bar(x=rating_counts.index, y=rating_counts.values)])
    rating_distribution.update_layout(title='Rating Distribution', xaxis_title='Rating', yaxis_title='Count')
    rating_plot_div = pio.to_html(rating_distribution, full_html=False)

    # Plot sentiment distribution
    sentiment_distribution = go.Figure([go.Histogram(x=feedback_df['sentiment'], nbinsx=20)])
    sentiment_distribution.update_layout(
        title='Sentiment Distribution',
        xaxis=dict(
            title='Sentiment Polarity',
            tickvals=[-1, 0, 1],
            ticktext=['Negative', 'Neutral', 'Positive']
        ),
        yaxis_title='Count'
    )
    sentiment_plot_div = pio.to_html(sentiment_distribution, full_html=False)

    # Plot average sentiment per rating
    avg_sentiment_per_rating = feedback_df.groupby('rating')['sentiment'].mean()
    avg_sentiment_plot = go.Figure([go.Bar(x=avg_sentiment_per_rating.index, y=avg_sentiment_per_rating.values)])
    avg_sentiment_plot.update_layout(title='Average Sentiment per Rating', xaxis_title='Rating', yaxis_title='Average Sentiment')
    avg_sentiment_plot_div = pio.to_html(avg_sentiment_plot, full_html=False)

    # Plot pie chart for sentiment categories using Plotly
    sentiment_counts = feedback_df['sentiment_category'].value_counts()
    sentiment_pie_chart = go.Figure(data=[
        go.Pie(labels=sentiment_counts.index, values=sentiment_counts.values, 
               marker=dict(colors=['lightgreen', 'lightcoral', 'lightgrey']), 
               hoverinfo='label+percent', textinfo='value', textfont_size=20)
    ])
    sentiment_pie_chart.update_layout(title='Distribution of Sentiments in Feedback')
    sentiment_pie_chart_path = pio.to_html(sentiment_pie_chart, full_html=False)

    # Display the pie chart using Streamlit
    st.plotly_chart(sentiment_pie_chart)

    return {
        'average_rating': average_rating,
        'rating_plot_div': rating_plot_div,
        'sentiment_plot_div': sentiment_plot_div,
        'avg_sentiment_plot_div': avg_sentiment_plot_div,
        'sentiment_pie_chart_path': 'static/sentiment_pie_chart.png'
    }



def fetch_customer_data():
    conn = sqlite3.connect('existing_database.db')  # Update with your database path
    cursor = conn.cursor()

    query = '''
    SELECT customer_id, order_date, COUNT(order_id) as order_count, SUM(total_price) as total_spent 
    FROM Orders 
    GROUP BY customer_id, order_date;
    '''
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return data

def plot_order_frequency_spending():
    data = fetch_customer_data()
    df = pd.DataFrame(data, columns=['customer_id', 'order_date', 'order_count', 'total_spent'])

    # Convert order_date to datetime
    df['order_date'] = pd.to_datetime(df['order_date'])

    # Group data by date to calculate daily totals for frequency and spending
    daily_data = df.groupby(df['order_date'].dt.date).agg(
        total_orders=('order_count', 'sum'),
        total_spent=('total_spent', 'sum')
    ).reset_index()

    daily_data['order_date'] = pd.to_datetime(daily_data['order_date'])

    # Create a figure
    fig = go.Figure()

    # Add bar plot for order frequency
    fig.add_trace(
        go.Bar(
            x=daily_data['order_date'],
            y=daily_data['total_orders'],
            name='Order Frequency',
            marker=dict(color='blue'),
            opacity=0.6
        )
    )

    # Add line plot for total spending
    fig.add_trace(
        go.Scatter(
            x=daily_data['order_date'],
            y=daily_data['total_spent'],
            mode='lines+markers',
            name='Total Spending',
            line=dict(color='orange')
        )
    )

    # Update layout
    fig.update_layout(
        title='Order Frequency and Total Spending Over Time',
        xaxis_title='Date',
        yaxis_title='Count / Spending',
        barmode='overlay',
        xaxis=dict(
            tickformat='%Y-%m-%d',  # Format x-axis for date display
            tickangle=-45           # Angle for better readability
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )

    return pio.to_html(fig, full_html=False)


@app.route('/order_frequency_spending', methods=['GET'])
def order_frequency_spending():
    chart_html = plot_order_frequency_spending()
    return render_template('order_frequency_spending.html', chart_html=chart_html)



def fetch_customers():
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()
    query = 'SELECT DISTINCT customer_id FROM Orders'
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return [row[0] for row in data]

def fetch_customer_purchases(customer_id):
    conn = sqlite3.connect('existing_database.db')
    cursor = conn.cursor()

    query = '''
    SELECT order_date, total_price
    FROM Orders
    WHERE customer_id = ?
    ORDER BY order_date
    '''
    cursor.execute(query, (customer_id,))
    data = cursor.fetchall()
    conn.close()
    return data

def plot_customer_purchases(customer_id):
    data = fetch_customer_purchases(customer_id)
    df = pd.DataFrame(data, columns=['order_date', 'total_price'])

    fig = go.Figure()

    # Scatter plot for purchases over time
    fig.add_trace(go.Scatter(x=df['order_date'], y=df['total_price'], mode='lines+markers', 
                             name='Total Price', line=dict(color='royalblue')))

    fig.update_layout(title=f'Purchase History for Customer {customer_id}',
                      xaxis_title='Order Date',
                      yaxis_title='Total Price')

    return pio.to_html(fig, full_html=False)

@app.route('/customer_purchases', methods=['GET', 'POST'])
def customer_purchases():
    customers = fetch_customers()
    selected_customer = request.form.get('customer_id')
    chart_html = ''

    if request.method == 'POST' and selected_customer:
        chart_html = plot_customer_purchases(selected_customer)

    return render_template('customer_purchases.html', customers=customers, chart_html=chart_html)


app.jinja_env.filters['zfill'] = lambda s: str(s).zfill(2)

@app.route('/revenue_metrics', methods=['GET', 'POST'])
def revenue_metrics():
    selected_year = request.form.get('year', '2024')
    
    monthly_revenue_data = fetch_monthly_revenue_for_year(selected_year)
    months = [row['month'] for row in monthly_revenue_data]
    revenues = [row['revenue'] for row in monthly_revenue_data]
    
    gains, losses = calculate_revenue_metrics(revenues)

    # Generate bar and line charts
    revenue_line_chart = generate_revenue_line_chart(months, gains, losses)
    revenue_bar_chart = generate_revenue_bar_chart(months, gains, losses)
    
    revenue_line_chart_url = base64.b64encode(revenue_line_chart.getvalue()).decode()
    revenue_bar_chart_url = base64.b64encode(revenue_bar_chart.getvalue()).decode()
    
    return render_template('revenue_metrics.html', 
                           revenue_line_chart_url=revenue_line_chart_url, 
                           revenue_bar_chart_url=revenue_bar_chart_url, 
                           selected_year=selected_year)

def fetch_monthly_revenue_for_year(year):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    SELECT strftime('%Y-%m', order_date) as month, SUM(total_price) as revenue
    FROM Orders
    WHERE strftime('%Y', order_date) = ?
    GROUP BY month
    ORDER BY month;
    '''
    cursor.execute(query, (year,))
    data = cursor.fetchall()
    conn.close()
    
    return data

def calculate_revenue_metrics(revenues):
    average_revenue = sum(revenues) / len(revenues)
    gains = [revenue - average_revenue if revenue > average_revenue else 0 for revenue in revenues]
    losses = [average_revenue - revenue if revenue < average_revenue else 0 for revenue in revenues]
    return gains, losses

def generate_revenue_line_chart(months, gains, losses):
    fig, ax = plt.subplots(figsize=(10, 6))
    dates = pd.to_datetime(months, format='%Y-%m')
    
    ax.plot(dates, gains, marker='o', linestyle='-', color='green', label='Gain')
    ax.plot(dates, losses, marker='o', linestyle='-', color='red', label='Loss')
    
    plt.xlabel('Month')
    plt.ylabel('Revenue Difference')
    plt.title('Revenue Trend (Line Chart)')
    plt.legend()
    plt.xticks(rotation=45)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

def generate_revenue_bar_chart(months, gains, losses):
    fig, ax = plt.subplots(figsize=(10, 6))
    dates = pd.to_datetime(months, format='%Y-%m')
    
    ax.bar(dates, gains, color='green', label='Gain')
    ax.bar(dates, losses, color='red', label='Loss')
    
    plt.xlabel('Month')
    plt.ylabel('Revenue Difference')
    plt.title('Revenue Trend (Bar Chart)')
    plt.legend()
    plt.xticks(rotation=45)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

# # Function to analyze sentiment
# def analyze_sentiment(comment):
#     analysis = TextBlob(comment)
#     return analysis.sentiment.polarity  # Returns a value between -1 (negative) and 1 (positive)

# # Function to detect anomalies using ML
# def detect_feedback_anomalies_ml():
#     conn = get_db()
#     cursor = conn.cursor()

#     # Fetch feedback data
#     cursor.execute('''
#         SELECT 
#             feedback.feedback_id, 
#             feedback.order_id, 
#             feedback.customer_id, 
#             feedback.rating, 
#             feedback.comment, 
#             orders.total_price, 
#             orders.delivery_location, 
#             orders.order_time
#         FROM feedback
#         JOIN orders ON feedback.order_id = orders.order_id
#     ''')
#     feedback_data = cursor.fetchall()

#     # Prepare data for ML
#     features = []
#     feedback_list = []
#     for row in feedback_data:
#         sentiment_score = analyze_sentiment(row['comment'])
#         features.append([row['rating'], sentiment_score])
#         feedback_list.append({
#             "feedback_id": row["feedback_id"],
#             "order_id": row["order_id"],
#             "customer_id": row["customer_id"],
#             "rating": row["rating"],
#             "comment": row["comment"],
#             "total_price": row["total_price"],
#             "delivery_location": row["delivery_location"],
#             "order_time": row["order_time"],
#             "sentiment_score": sentiment_score
#         })

#     # Normalize data
#     scaler = StandardScaler()
#     features = scaler.fit_transform(features)

#     # Apply K-Means clustering
#     kmeans = KMeans(n_clusters=2, random_state=42)  # Assume 2 clusters (normal and anomalous)
#     labels = kmeans.fit_predict(features)

#     # Mark anomalies based on clustering
#     anomalies = []
#     for i, label in enumerate(labels):
#         if label == 1:  # Assuming label 1 indicates anomalies
#             anomalies.append(feedback_list[i])

#     return anomalies

# @app.route('/feedback_form', methods=['GET'])
# def feedback_anomalies():
#     try:
#         # Fetch feedback data
#         anomalies = detect_feedback_anomalies_ml()  # Detect anomalies using ML
#         return jsonify({"success": True, "anomalies": anomalies}), 200  # Return anomalies
#     except Exception as e:
#         return jsonify({"success": False, "message": str(e)}), 500


# @app.route('/')
# def anoma():
#     return render_template('anomalies.html')

# Function to detect anomalies using ML
def detect_feedback_anomalies_ml():
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Fetch feedback data
        cursor.execute(''' 
            SELECT 
                feedback.feedback_id, 
                feedback.order_id, 
                feedback.customer_id, 
                feedback.rating, 
                feedback.comment, 
                orders.total_price, 
                orders.delivery_location, 
                orders.order_time
            FROM feedback
            JOIN orders ON feedback.order_id = orders.order_id
        ''')
        feedback_data = cursor.fetchall()

        # Prepare data for ML
        features = []
        feedback_list = []
        for row in feedback_data:
            sentiment_score = TextBlob(row['comment']).sentiment.polarity
            features.append([row['rating'], sentiment_score])
            feedback_list.append({
                "feedback_id": row["feedback_id"],
                "order_id": row["order_id"],
                "customer_id": row["customer_id"],
                "rating": row["rating"],
                "comment": row["comment"],
                "total_price": row["total_price"],
                "delivery_location": row["delivery_location"],
                "order_time": row["order_time"],
                "sentiment_score": sentiment_score
            })

        # Normalize data
        scaler = StandardScaler()
        features = scaler.fit_transform(features)

        # Apply K-Means clustering
        kmeans = KMeans(n_clusters=2, random_state=42)  # Assume 2 clusters (normal and anomalous)
        labels = kmeans.fit_predict(features)

        # Mark anomalies based on clustering and sentiment analysis
        anomalies = []
        for i, label in enumerate(labels):
            if label == 1:  # Assuming label 1 indicates anomalies
                anomaly = feedback_list[i]
                # Classify anomaly type based on sentiment and rating
                anomaly_type = "Unknown"
                if anomaly["rating"] <= 2 and anomaly["sentiment_score"] < 0:
                    anomaly_type = "Poor Quality or Service"  # Poor rating + Negative sentiment
                elif anomaly["sentiment_score"] < 0:
                    anomaly_type = "Negative Sentiment"
                elif anomaly["rating"] <= 2:
                    anomaly_type = "Low Rating"

                anomaly["anomaly_type"] = anomaly_type
                anomalies.append(anomaly)

        return anomalies

    except Exception as e:
        print(f"Error occurred during anomaly detection: {e}")
        raise e

# Flask route to display anomalies on anomalies.html
@app.route('/anomalies', methods=['GET'])
def show_anomalies():
    try:
        # Fetch anomalies using the machine learning detection function
        anomalies = detect_feedback_anomalies_ml()

        # Return JSON data for frontend
        return jsonify({"anomalies": anomalies})

    except Exception as e:
        return jsonify({"error": "Error occurred while fetching anomalies", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
 