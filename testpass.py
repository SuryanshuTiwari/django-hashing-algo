import hashlib
import base64

def verify_password(stored_hash, input_password):
    algorithm, iterations, salt, stored_hash_value = stored_hash.split('$')
    
    # Ensure the input password is in byte form (required for hashing)
    password_bytes = input_password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    # Perform PBKDF2 hashing using the same salt, iterations, and algorithm
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, int(iterations))
    
    new_hash_base64 = base64.b64encode(hash_bytes).decode('ascii').strip()
    
    return new_hash_base64 == stored_hash_value
def test_password():
    stored_hash = input("Enter the stored hashed password: ")
    
    input_password = input("Enter the password to test: ")
    
    if verify_password(stored_hash, input_password):
        print("Password is correct.")
    else:
        print("Password is incorrect.")

test_password()
