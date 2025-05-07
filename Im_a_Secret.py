import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import webbrowser
import os
from Crypto.Cipher import AES
import base64

# === Search for files on disk ===
def find_file(filename, drives=["C:\\", "D:\\"]):
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            if filename in files:
                return os.path.join(root, filename)
    return None

# === File names ===
BACKGROUND_FILENAME = "Im_a_secret4.png"
ICON_FILENAME = "smile.ico"

BACKGROUND_PATH = find_file(BACKGROUND_FILENAME)
ICON_PATH = find_file(ICON_FILENAME)

# === Vigenère encryption ===
def encrypt_vigenere(plaintext, key):
    ciphertext = ""
    key = key.upper()
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            key_char = key[i % key_length]
            key_shift = ord(key_char) - 65
            encrypted_char = chr((ord(char) - offset + key_shift) % 26 + offset)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def decrypt_vigenere(ciphertext, key):
    plaintext = ""
    key = key.upper()
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            key_char = key[i % key_length]
            key_shift = ord(key_char) - 65
            decrypted_char = chr((ord(char) - offset - key_shift) % 26 + offset)
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext

# === AES encryption ===
def pad(text):
    return text + (16 - len(text) % 16) * chr(16 - len(text) % 16)

def unpad(text):
    return text[:-ord(text[-1])]

def encrypt_aes(text, key):
    key = key[:16].ljust(16)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_text = pad(text)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_aes(ciphertext, key):
    key = key[:16].ljust(16)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted.decode('utf-8'))

# === Global data storage ===
app_data = {}

# === Password window ===
def show_password_window():
    global password_window, password_entry
    password_window = tk.Tk()
    password_window.title("Create Access Key")
    password_window.geometry("400x200")
    password_window.configure(bg="black")

    if ICON_PATH:
        try:
            password_window.iconbitmap(ICON_PATH)
        except Exception as e:
            print(f"Failed to set icon: {e}")

    tk.Label(password_window, text="Enter access key:", bg="black", fg="white", font=("Helvetica", 12)).pack(pady=20)
    password_entry = tk.Entry(password_window, show="*", width=30)
    password_entry.pack(pady=10)

    tk.Button(password_window, text="Next", command=show_method_window, bg="yellow", fg="black", font=("Helvetica", 12)).pack(pady=10)
    password_window.mainloop()

# === Encryption method selection window ===
def show_method_window():
    key = password_entry.get().strip()
    if not key:
        messagebox.showerror("Error", "Please enter access key!")
        return
    app_data["key"] = key
    password_window.destroy()

    global method_window, method_var
    method_window = tk.Tk()
    method_window.title("Choose Encryption Method")
    method_window.geometry("400x200")
    method_window.configure(bg="black")

    if ICON_PATH:
        try:
            method_window.iconbitmap(ICON_PATH)
        except Exception as e:
            print(f"Failed to set icon: {e}")

    method_var = tk.StringVar(method_window)
    method_var.set("Vigenere")

    tk.Label(method_window, text="Select encryption method:", bg="black", fg="white", font=("Helvetica", 12)).pack(pady=20)
    ttk.Radiobutton(method_window, text="Vigenère", variable=method_var, value="Vigenere").pack()
    ttk.Radiobutton(method_window, text="AES", variable=method_var, value="AES").pack()

    tk.Button(method_window, text="Let's Go!", command=show_main_window, bg="yellow", fg="black", font=("Helvetica", 12)).pack(pady=20)
    method_window.mainloop()

# === Main encryption/decryption window ===
def show_main_window():
    method_window.destroy()
    root = tk.Tk()
    root.title("I'm a Secret")
    root.geometry("650x800")
    root.resizable(False, False)
    root.configure(bg="black")

    if ICON_PATH:
        try:
            root.iconbitmap(ICON_PATH)
        except Exception as e:
            print(f"Failed to set icon: {e}")

    if BACKGROUND_PATH:
        try:
            bg_image = Image.open(BACKGROUND_PATH)
            bg_image = bg_image.resize((650, 800), Image.LANCZOS)
            bg_photo = ImageTk.PhotoImage(bg_image)
            bg_label = tk.Label(root, image=bg_photo)
            bg_label.image = bg_photo
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except Exception as e:
            print(f"Failed to load background: {e}")

    def on_encrypt():
        text = text_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter text!")
            return
        key = app_data["key"]
        method = method_var.get()
        try:
            if method == "Vigenere":
                result = encrypt_vigenere(text, key)
            elif method == "AES":
                result = encrypt_aes(text, key)
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def on_decrypt():
        text = text_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter text!")
            return
        key = app_data["key"]
        method = method_var.get()
        try:
            if method == "Vigenere":
                result = decrypt_vigenere(text, key)
            elif method == "AES":
                result = decrypt_aes(text, key)
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, result)
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
        except:
            messagebox.showerror("Error", "Clipboard is empty!")

    tk.Label(root, text="Enter text:", font=("Helvetica", 12), bg="#ff00bf", fg="yellow").place(x=30, y=20)
    text_entry = tk.Text(root, height=8, width=72, font=("Helvetica", 11), bg="white", fg="black", insertbackground="black")
    text_entry.place(x=30, y=50)

    btn_frame = tk.Frame(root, bg="#ff00bf")
    btn_frame.place(x=30, y=280)
    tk.Button(btn_frame, text="Encrypt", command=on_encrypt, bg="yellow", fg="blue", font=("Helvetica", 12)).grid(row=0, column=0, padx=10)
    tk.Button(btn_frame, text="Decrypt", command=on_decrypt, bg="yellow", fg="black", font=("Helvetica", 12)).grid(row=0, column=1, padx=10)

    clipboard_frame = tk.Frame(root, bg="#ff00bf")
    clipboard_frame.place(x=30, y=340)
    tk.Button(clipboard_frame, text="Copy result", command=copy_to_clipboard, bg="yellow", fg="green", font=("Helvetica", 12)).grid(row=0, column=0, padx=10)
    tk.Button(clipboard_frame, text="Paste from clipboard", command=paste_from_clipboard, bg="yellow", fg="red", font=("Helvetica", 12)).grid(row=0, column=1, padx=10)

    tk.Label(root, text="Result:", font=("Helvetica", 12), bg="#ff00bf", fg="yellow").place(x=30, y=410)
    result_text = tk.Text(root, height=8, width=72, font=("Helvetica", 11), bg="white", fg="black", insertbackground="black")
    result_text.place(x=30, y=440)

    def open_btc_link(event):
        btc_address = "1EYseVCyKX6xkev3YKFEVZ5nN44T4NBhWA"
        telegram_link = f"https://t.me/share/url?url=bitcoin:{btc_address}"
        webbrowser.open(telegram_link)

    btc_label = tk.Label(root, text="Donate BTC", font=("Helvetica", 12, "underline"), fg="red", bg="black", cursor="hand2")
    btc_label.place(x=30, y=620)
    btc_label.bind("<Button-1>", open_btc_link)

    root.mainloop()

# === Start the app ===
show_password_window()
