# FUTURE_CS_03
This is my Internship repository For a internship from Future interns Cyber security and task THREE.

is about updloading file to the internet in a encrypted format


# Commads to run the assignment
pip install -r requirements.txt
python app.py

# Secure File Sharing System

## Project Overview
This project was completed as part of Cyber Security Task 3 from Future Interns. The objective of this project is to build a secure file sharing system that allows users to upload and download files through a web interface. All files are encrypted before being stored on the server and automatically decrypted during download.

---

## Features Implemented
- File upload via web interface
- File download with automatic decryption
- AES-256 encryption (CBC mode) with PKCS7 padding
- Per-file random AES key generation
- Envelope encryption (AES key wrapped using Fernet master key)
- SHA-256 integrity check before download
- Secure filename handling using `secure_filename`
- File type validation
- Maximum 100 MB file size limit
- Temporary file cleanup
- Error handling and flash message notifications

---

## Encryption Process

1. User uploads a file.
2. A temporary file is stored.
3. A random 32-byte AES key and 16-byte IV are generated.
4. File is encrypted using AES-256-CBC with PKCS7 padding.
5. The AES key is encrypted (wrapped) using a master Fernet key.
6. The encrypted file and wrapped key are stored.
7. During download, the AES key is unwrapped and file is decrypted.
8. A SHA-256 hash of the decrypted data is compared with the original file hash.
9. If the hash matches, the file is sent to the user.

---

## Tools and Technologies Used
- Python
- Flask
- Cryptography library (for AES and Fernet encryption)
- HTML (basic templates)
- dotenv (for environment variable handling)
- Werkzeug (for secure filename processing)
- Git and GitHub for version control

Note: The `cryptography` library was used instead of the suggested PyCryptodome because it provides high-level and secure encryption support. This choice was made for reliability and clarity.

---

## Project Directory Structure

