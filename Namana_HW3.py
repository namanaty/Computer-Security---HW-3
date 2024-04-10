from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from tinydb import TinyDB, Query
import hashlib
import getpass
import base64

# This function creates a cryptographic key 
# Input: Password and Salt
# Output: Cryptographic key encoded in Base-64
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


# This function encrypts a secret using the password 
# Input: Secret and Password
# Output: Encrypted Secret
def encrypt(secret, password):
    salt = b'Pv+/RFgsqBw='  
    key = derive_key(password.encode(), salt)
    cipher = Fernet(key)
    encrypted_secret = cipher.encrypt(secret.encode())
    # print(encrypted_secret)
    return encrypted_secret.decode()


# This function decrypts a secret using the ciphertext and password
# Input: Ciphertext and Password
# Output: Decrypted Secret / Plaintext
def decrypt(encrypted_secret, password):
    salt = b'Pv+/RFgsqBw='  
    key = derive_key(password.encode(), salt)
    cipher = Fernet(key)
    decrypted_secret = cipher.decrypt(encrypted_secret).decode()
    return decrypted_secret


# Main Function
def main():
    # Initialize a tinydb.json to store ciphertext and passwords
    db = TinyDB('tinydb.json')

    # Prompt the user to choose either encryption or decryption
    print("Enter 1 to Encrypt or 2 to Decrypt")
    choice = int(input())
    
    # For encryption
    if choice == 1:
        secret = input("Enter the plaintext to be encrypted: ")
        password = input("Enter the password to encrypt your plaintext: ")
        # Encrypt the secret 
        encrypted_secret = encrypt(secret, password)
        # Store the ciphertext in tinydb.json along with the hashed password
        db.insert({encrypted_secret: hashlib.md5(password.encode()).hexdigest()})

        print("Your secret is stored in DB.")
        print("Your ciphertext is: " + encrypted_secret)
        
    # For decryption
    elif choice == 2:
        cipher = input("Enter the ciphertext to decrypt your secret: ")
        password = input("Enter the password which was used for encryption: ")
        query = Query()

        # Check if the ciphertext and hashed password match in the tinydb.json
        is_found = db.search(query[cipher] == hashlib.md5(password.encode()).hexdigest())
        if is_found:
            # Decrypt the ciphertext and print the plaintext
            secret = decrypt(cipher, password)
            print("Your plaintext or secret is : " + str(secret))
        else:
            print("Incorrect Ciphertext or Password. Try again!")
    else:
        print("Wrong Choice. Please Try Again.")

if __name__ == "__main__":
    main()