import hashlib
import base64
import secrets

def pbkdf2_sha256_hash(password, salt=None, iterations=36000):
    # If no salt is provided, generate a new one
    if salt is None:
        salt = secrets.token_urlsafe(12)[:12]  # Django uses a 12 character salt

    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    # Generate the PBKDF2 hash
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, iterations)
    hash_base64 = base64.b64encode(hash_bytes).decode('ascii').strip()
    
    # Password output to match Django's format
    hashed_password = f"pbkdf2_sha256${iterations}${salt}${hash_base64}"
    
    return hashed_password

hashed_password = pbkdf2_sha256_hash("john123@#")
print(hashed_password)
