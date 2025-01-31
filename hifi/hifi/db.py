import sqlite3
import bcrypt
from datetime import datetime

# Database connection
conn = sqlite3.connect('existing_database.db')
cursor = conn.cursor()

# Ensure the admin role exists
role_name = 'admin'
role_description = 'Administrator with full access'
created_at = datetime.now()

cursor.execute("SELECT role_id FROM roles WHERE role_name = ?", (role_name,))
role = cursor.fetchone()

if role is None:
    cursor.execute("""
        INSERT INTO roles (role_name, role_description, created_at)
        VALUES (?, ?, ?)
    """, (role_name, role_description, created_at))
    conn.commit()
    cursor.execute("SELECT role_id FROM roles WHERE role_name = ?", (role_name,))
    role = cursor.fetchone()

role_id = role[0]

# User data
email = 'admin@example.com'
raw_password = 'Gokul@123'
password_hash = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt())
full_name = 'Admin User'
phone_number = '1234567890'
created_at = datetime.now()
updated_at = datetime.now()
last_login = None
is_active = True
is_admin = 1
is_delivery_boy = 0

# Insert the new admin user
cursor.execute("""
    INSERT INTO users (
        email, password_hash, full_name, phone_number, created_at, updated_at, last_login, is_active, is_admin, is_delivery_boy, role_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (email, password_hash, full_name, phone_number, created_at, updated_at, last_login, is_active, is_admin, is_delivery_boy, role_id))

# Commit the changes and close the connection
conn.commit()
conn.close()

print("Admin user added successfully!")