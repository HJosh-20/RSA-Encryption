# RSA-Encryption
Principles of Cybersecurity Final Project:
Overview -
This program provides a secure way to store and manage user credentials using RSA encryption for password protection and SHA-256 hashing for admin authentication. It validates usernames and passwords based on predefined security criteria and stores credentials in a CSV file.

Features -
-RSA Encryption & Decryption: Public-private key encryption ensures password security.
-Username & Password Validation: Enforces strict format rules for better security.
-Secure Storage: Passwords are encrypted before being stored in passwords.csv.
-Admin Authentication: Uses SHA-256 hashing for added security.
-Key Management: Automatically generates or loads RSA keys from private_key.pem and public_key.pem.
-User & Admin Access: Supports secure password entry, storage, and retrieval.

How It Works -
1. Admin Setup: If passwords.csv does not exist, an admin must create credentials.
2. Admin Login: Admins can view decrypted passwords (except their own, which is hashed).
3. User Access: Users can securely store their credentials after validation.
4. Exit: The program runs in a loop until the user chooses to exit.


Usage -
Run the script.
Follow on-screen prompts to log in as an admin or store user credentials.
Ensure private_key.pem and public_key.pem are in the same directory for encryption to function.


