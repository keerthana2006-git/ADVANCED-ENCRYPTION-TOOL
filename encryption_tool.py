import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64, os

# Derive a Fernet key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt the file
def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(filepath + ".enc", 'wb') as f:
        f.write(salt + encrypted)

# Decrypt the file
def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()
    salt, encrypted = data[:16], data[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted)
        with open(filepath.replace('.enc', '.dec'), 'wb') as f:
            f.write(decrypted)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed: Incorrect password or corrupted file.")

# GUI Functions
def choose_file(mode):
    file = filedialog.askopenfilename()
    password = password_entry.get()
    if not file or not password:
        messagebox.showwarning("Missing Info", "Please select a file and enter a password.")
        return
    try:
        if mode == 'encrypt':
            encrypt_file(file, password)
            messagebox.showinfo("Success", f"File encrypted: {file}.enc")
        else:
            decrypt_file(file, password)
            messagebox.showinfo("Success", f"File decrypted: {file.replace('.enc', '.dec')}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("Advanced Encryption Tool (AES-256)")
root.geometry("400x200")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(root, width=30, show="*")
password_entry.pack()

tk.Button(root, text="Encrypt File", width=20, command=lambda: choose_file('encrypt')).pack(pady=10)
tk.Button(root, text="Decrypt File", width=20, command=lambda: choose_file('decrypt')).pack()

root.mainloop()
