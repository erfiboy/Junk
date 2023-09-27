import hashlib
import os

def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    salted_password = password.encode('utf-8') + salt

    hashed_password = hashlib.sha256(salted_password).hexdigest()

    return hashed_password

if __name__ == "__main__":
    password = input("Enter your password:")
    salt = generate_salt()

    hashed_password = hash_password(password, salt)
    
    print("Password:", password)
    print("Salt:", salt.hex())
    print("Hashed Password:", hashed_password)