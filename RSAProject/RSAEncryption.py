#Used this to help me create or find a path for either my public or private keys or for my password.csv file
import os
#Used this to validate usernames and passwords with specific criteria using regular expressions
import re
# Used this to manage and write data into the CSV file for storing usernames and passwords
import pandas as pd

#Used this to generate more secure hashes for my admins since I am storing it on the same CSV as the other encrypted passwords.
from hashlib import sha256

#All these are the same from lab 04 but serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

#Using rsa to generate the public and private keys to encrypt the passwords.
def genKeys():
    # Using RSA to generate the public and private keys to encrypt the passwords.
    if os.path.exists('private_key.pem') and os.path.exists('public_key.pem'):
        # Load the keys if they already exist
        with open('private_key.pem', 'rb') as priv_file:
            privateK = serialization.load_pem_private_key(priv_file.read(), password=None)
        with open('public_key.pem', 'rb') as pub_file:
            publicK = serialization.load_pem_public_key(pub_file.read())
    else:
        # Generate new keys if they don't exist
        privateK = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        publicK = privateK.public_key()

        # Save the keys to files
        with open('private_key.pem', 'wb') as priv_file:
            priv_file.write(privateK.private_bytes(
                # Serializing the private key in PEM format using PKCS8 standard without encryption for easier access during development
                # PEM is a text-based encoding format that stores cryptographic data with headers and footers for easy identification.
                # PKCS8 is a standard format for private keys, supporting both encrypted and unencrypted storage.
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open('public_key.pem', 'wb') as pub_file:
            pub_file.write(publicK.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    return publicK, privateK

#If username parameter meets the following criteria (Between 4 and 12 characters long & contains only lowercase letters and numbers) return True
#Otherwise, it will return false
def verify_username(username):
    regex = r"^[a-z0-9]{4,12}$"
    return re.match(regex, username)

# If password parameter meets the following criteria (min 8 characters long, at least 1 uppercase and lowercase letter, 1 number, and one special character)
# return true otherwise returns false.
def verify_pw(password):
    regex = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[@$!%*#^&_()+])[A-Za-z0-9~@$!%*#^&_()+]{8,}$"
    return re.match(regex, password)

# Encrypting the password with RSA public key
def encryptPw(password, public_key):
    password = password.encode()
    ciphertext = public_key.encrypt(
        password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()

# Decrypting the password with RSA private key
def decyptPw(ciphertext, private_key):
    ciphertext_bytes = bytes.fromhex(ciphertext)
    try:
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError as e:
        print("Decryption failed:", e)
        return None

    return plaintext.decode()

# Storing the encrypted password without salt (I tried to use salt and gave up after not figuring out how to get it to work)
def storePw(username, password, public_key):
    encryptedPw = encryptPw(password, public_key)
    data = {'Username': [username], 'Encrypted Password': [encryptedPw]}
    df = pd.DataFrame(data)
    # The mode 'a' here is to append, which can create the CSV if not already made to write to or if already made it will open the file to write in
    df.to_csv('passwords.csv', mode='a', index=False, header=None)

# Loading the encrypted password from the CSV
def loadPw(username):
    df = pd.read_csv('passwords.csv', dtype=str, header=None)
    df.columns = ['Username', 'Encrypted Password']
    # Filters for rows that match the username given
    filtered_df = df[df['Username'] == username]
    #If not empty then that means theres at least one row matching the username
    if not filtered_df.empty:
        encryptedPw = filtered_df['Encrypted Password'].values[0]
        return encryptedPw
    return None

# Produces a hash from the password that kinda looks like this 'cc4a5ce1b3df48aec5d22d1f16b894a0b894eccc' a hex string from the binary hash
def hashPw(password):
    return sha256(password.encode()).hexdigest()

#checks if we have created password.csv and have creds to store creds
#checking user input by hashing the password the users gives and sees if it matchs the hash in the csv
def checkAdminsCred(username, password):
    #The if statement uses os.path.exists which checks if there is a file called passwords.csv and using the not before to return true if the csv file doesnt exist,
    #which we need at least for my first time running this to write admin credentials as the first entry (not good practice in a real situation to store admins cred in the same csv)
    #After file is created we will not use this if statement anymore.
    csv_path = 'passwords.csv'
    if not os.path.exists(csv_path):
        print("Admin credentials needed, please enter the following: ")
        # First run, store admin credentials
        if verify_username(username) and verify_pw(password):
            adminHashPw = hashPw(password)
            data = {'Username': [username], 'Encrypted Password': [adminHashPw]}
            df = pd.DataFrame(data)
            df.to_csv(csv_path, mode='a', index=False, header=True)
            return True
        else:
            print("Invalid admin credentials. Must meet username and password requirements")
            return False

    #checks if the password entered matchs the password saved by an admin
    df = pd.read_csv(csv_path, dtype=str)
    df.columns = ['Username', 'Encrypted Password']
    filtered_df = df[df['Username'] == username]
    if not filtered_df.empty:
        storedHashPw = filtered_df['Encrypted Password'].values[0]
        hashPass = hashPw(password)
        return hashPass == storedHashPw
    else:
        return False

# Generate public and private keys
public_key, private_key = genKeys()

# Main loop for user input
while True:
    print("1. Login as Admin")
    print("2. User Access")
    print("3. Exit")
    choice = input("Enter your choice: ")
    if choice == '1':
        username = input("Enter admin username: ")
        password = input("Enter admin password: ")
        if checkAdminsCred(username, password):
            print("Admin login successful.")
            df = pd.read_csv('passwords.csv', dtype=str)
            for index, row in df.iterrows():
                if index == 0:  # Skip the admin row
                    continue
                username = row['Username']
                encrypted_password = loadPw(username)
                decrypted_password = decyptPw(encrypted_password, private_key)
                print(f"Username: {username}, Password: {decrypted_password}")
        else:
            print("Admin login unsuccessful. Invalid admin credentials")
    elif choice == '2':
        username = input("Enter username: ")
        password = input("Enter password: ")

        if verify_username(username) and verify_pw(password):
            storePw(username, password, public_key)
            print("Password stored securely.")
        else:
            print("Invalid username or password.")

    elif choice == '3':
        break
    else:
        print("Invalid choice. Please try again.")
