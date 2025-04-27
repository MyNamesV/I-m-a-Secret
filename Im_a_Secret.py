import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import os
import threading
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# === Search for files on the drive ===
def find_file(filename, drives=["C:\\", "D:\\"]):
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            if filename in files:
                return os.path.join(root, filename)
    return None

# === Search for background and icon ===
BACKGROUND_FILENAME = "Im_a_secret4.png"
ICON_FILENAME = "smile.ico"

BACKGROUND_PATH = find_file(BACKGROUND_FILENAME)
ICON_PATH = find_file(ICON_FILENAME)

# === AES-256 encryption key ===
AES_KEY = hashlib.sha256(b"SECRETKEY").digest()  # 32 bytes for AES-256

# === AES-256 encryption and decryption functions ===
def pad(s):
    padding_len = AES.block_size - len(s) % AES.block_size
    return s + bytes([padding_len] * padding_len)

def unpad(s):
    return s[:-s[-1]]

def encrypt_aes(plaintext):
    iv = get_random_bytes(16)  # Initialization vector for CBC mode
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8')))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_aes(ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext.decode('utf-8')

# === Button functions ===
def on_encrypt():
    text = text_entry.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "Enter text to encrypt!")
        return
    try:
        encrypted = encrypt_aes(text)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, encrypted)
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def on_decrypt():
    text = text_entry.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "Enter text to decrypt!")
        return
    try:
        decrypted = decrypt_aes(text)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, decrypted)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def copy_to_clipboard():
    text = result_text.get("1.0", tk.END).strip()
    if text:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        messagebox.showinfo("Copied", "Text copied to clipboard!")

def paste_from_clipboard():
    try:
        clipboard_content = root.clipboard_get()
        text_entry.delete("1.0", tk.END)
        text_entry.insert(tk.END, clipboard_content)
    except tk.TclError:
        messagebox.showerror("Error", "Clipboard is empty!")

# === GUI Setup ===
root = tk.Tk()
root.title("I'm a Secret")
root.geometry("650x800")
root.resizable(False, False)
root.configure(bg="black")

# Set window icon
if ICON_PATH:
    try:
        root.iconbitmap(ICON_PATH)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set icon:\n{e}")
else:
    messagebox.showwarning("Warning", f"Icon file '{ICON_FILENAME}' not found on C: or D:")

# Set background image
if BACKGROUND_PATH:
    try:
        bg_image = Image.open(BACKGROUND_PATH)
        bg_image = bg_image.resize((650, 800), Image.LANCZOS)
        bg_photo = ImageTk.PhotoImage(bg_image)
        bg_label = tk.Label(root, image=bg_photo)
        bg_label.place(x=0, y=0, relwidth=1, relheight=1)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load background:\n{e}")
else:
    messagebox.showwarning("Warning", f"Background image '{BACKGROUND_FILENAME}' not found on C: or D:")

# Text input label
tk.Label(root, text="Enter text:", font=("Helvetica", 12), bg="#ff00bf", fg="yellow").place(x=30, y=20)
text_entry = tk.Text(root, height=8, width=72, font=("Helvetica", 11), bg="white", fg="black", insertbackground="black")
text_entry.place(x=30, y=50)

# Encrypt/Decrypt buttons
btn_frame = tk.Frame(root, bg="#ff00bf")
btn_frame.place(x=30, y=280)

encrypt_btn = tk.Button(btn_frame, text="Encrypt", command=on_encrypt, bg="yellow", fg="blue", font=("Helvetica", 12))
encrypt_btn.grid(row=0, column=0, padx=10)

decrypt_btn = tk.Button(btn_frame, text="Decrypt", command=on_decrypt, bg="yellow", fg="black", font=("Helvetica", 12))
decrypt_btn.grid(row=0, column=1, padx=10)

# Clipboard buttons
clipboard_frame = tk.Frame(root, bg="#ff00bf")
clipboard_frame.place(x=30, y=340)

copy_btn = tk.Button(clipboard_frame, text="Copy result", command=copy_to_clipboard, bg="yellow", fg="green", font=("Helvetica", 12))
copy_btn.grid(row=0, column=0, padx=10)

paste_btn = tk.Button(clipboard_frame, text="Paste from clipboard", command=paste_from_clipboard, bg="yellow", fg="red", font=("Helvetica", 12))
paste_btn.grid(row=0, column=1, padx=10)

# Result output
tk.Label(root, text="Result:", font=("Helvetica", 12), bg="#ff00bf", fg="yellow").place(x=30, y=410)
result_text = tk.Text(root, height=8, width=72, font=("Helvetica", 11), bg="white", fg="black", insertbackground="black")
result_text.place(x=30, y=440)

# Start the application
root.mainloop()
