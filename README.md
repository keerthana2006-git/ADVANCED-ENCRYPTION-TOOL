# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: KEERTHANA SASIKUMAR

*INTERN ID*: CT04DF1796

*DOMAIN*: CYBER SECURITY AND ETHICAL HACKING

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

DESCRIPTION OF ADVANCED ENCRYPTION TOOL:
This is a secure file encryption and decryption tool built with Python using the AES-256 algorithm, powered by the cryptography library. The application features a simple and intuitive Tkinter-based GUI to allow users to safely encrypt or decrypt any file with a user-defined password.

FEATURES:
->AES-256 Encryption & Decryption:
Utilizes AES encryption (via Fernet) with a 256-bit key derived using PBKDF2 and SHA-256.

->Password-Based Key Derivation:
Converts your password into a strong encryption key with a random salt using PBKDF2HMAC.

->Secure Salt Handling:
Random 16-byte salt is generated per encryption and stored with the encrypted file.

->File Picker GUI:
Simple interface for selecting files and entering passwords without command-line complexity.

->No Re-entry of Password Needed:
Password is entered once and used for either encryption or decryption through button-based actions.

->Error Handling:
Built-in alerts for missing input, incorrect passwords, or corrupted files.

HOW IT WORKS:
It mainly works on these 2 steps that is ENCRYPTION and DECRYPTION
1)Encryption:
Select a file.
Enter a password.
Click "Encrypt File".
Output: A '.enc' encrypted file is created securely using AES-256.

2)Decryption:
Select the .enc file.
Enter the same password used during encryption.
Click "Decrypt File".
Output: A '.dec' decrypted version of the original file.

APPLICATIONS:
1)Personal File Security
2)Data Transfer
3)Academic & Professional Use
4)Offline Encryption

TECHNOLOGIES USED:
->Python
->Tkinter (GUI)
->cryptography (Fernet, AES, PBKDF2HMAC, SHA256)

PLEASE NOTE THAT YOU MUST REMEMBER THE PASSWORD USED DURING ENCRYPTION. FORGOTTEN PASSWORDS CANNOT BE RECOVERED.







