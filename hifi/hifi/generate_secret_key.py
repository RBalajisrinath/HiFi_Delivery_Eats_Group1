import secrets

# Generates a 32-character hex string
secret_key = secrets.token_hex(16)
print(secret_key)
