# RSA-Encryption
Principles of Cybersecurity Final Project:
Overview -
This program provides a secure way to store and manage user credentials using RSA encryption for password protection and SHA-256 hashing for admin authentication. It validates usernames and passwords based on predefined security criteria and stores credentials in a CSV file.

Features -
1. RSA Encryption & Decryption: Public-private key encryption ensures password security.
2. Username & Password Validation: Enforces strict format rules for better security.
3. Secure Storage: Passwords are encrypted before being stored in passwords.csv.
4. Admin Authentication: Uses SHA-256 hashing for added security.
5. Key Management: Automatically generates or loads RSA keys from private_key.pem and public_key.pem.
6. User & Admin Access: Supports secure password entry, storage, and retrieval.

How It Works -
1. Admin Setup: If passwords.csv does not exist, an admin must create credentials.
2. Admin Login: Admins can view decrypted passwords (except their own, which is hashed).
3. User Access: Users can securely store their credentials after validation.
4. Exit: The program runs in a loop until the user chooses to exit.


Usage -
1. Run the script.
2. Follow on-screen prompts to log in as an admin or store user credentials.
3. Ensure private_key.pem and public_key.pem are in the same directory for encryption to function.


