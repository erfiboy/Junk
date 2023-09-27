import hashlib
import os

SECRET_PEPPER = b'SecretPepperValue'
def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    
    # salted_password = SECRET_PEPPER + password.encode('utf-8') + salt
    salted_password = hashlib.sha256(SECRET_PEPPER + password.encode('utf-8')).digest()
    salted_password = str(salted_password) + salt
    salted_password = hashlib(salted_password)
    hashed_password = hashlib.sha256(salted_password).hexdigest()

    return hashed_password

if __name__ == "__main__":
    password = input("Enter your password:")
    salt = generate_salt()

    hashed_password = hash_password(password, salt)
    
    print("Password:", password)
    print("Salt:", salt.hex())
    print("Papper:", SECRET_PEPPER.hex())
    print("Hashed Password:", hashed_password)