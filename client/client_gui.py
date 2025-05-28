#AIO gui client

import tkinter as tk
from tkinter import messagebox
import requests
import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

SERVER = "http://localhost:5000"
DEVICE_PATH = "../usb_device"
RSA_PATH = "rsa_keys"

def init_rsa():
    if not os.path.exists(RSA_PATH):
        os.makedirs(RSA_PATH)
    if not os.path.exists(f"{RSA_PATH}/client_private.pem"):
        from cryptography.hazmat.primitives.asymmetric import rsa
        client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        client_public_key = client_private_key.public_key()
        with open(f"{RSA_PATH}/client_private.pem", "wb") as f:
            f.write(client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(f"{RSA_PATH}/client_public.pem", "wb") as f:
            f.write(client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def load_usb():
    # Loading rng token from usb_device and saving it to rng_token.txt
    if not os.path.exists(os.path.join(DEVICE_PATH, "rng_token.txt")):
        raise FileNotFoundError("rng_token.txt non trovato.")
    with open(os.path.join(DEVICE_PATH, "rng_token.txt"), "r") as f:
        rng_token = f.read().strip()
    with open("rng_token.txt", "w") as f:
        f.write(rng_token)
        
    # Loading server public key from usb_device and saving it to server_public.pem
    if not os.path.exists(os.path.join(DEVICE_PATH, "server_public.pem")):
        raise FileNotFoundError("server_public.pem non trovato.")
    with open(os.path.join(DEVICE_PATH, "server_public.pem"), "rb") as f:
        server_public_key = f.read()
    with open("server_public.pem", "wb") as f:
        f.write(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def register(username):
    try:
        with open("rng_token.txt", "r") as f:
            rng_token = f.read().strip()

        with open("server_public.pem", "rb") as f:
            server_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        encrypted_rng = server_public_key.encrypt(
            rng_token.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(f"{RSA_PATH}/client_private.pem", "rb") as f:
            client_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        signature = client_private_key.sign(
            encrypted_rng,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        with open(f"{RSA_PATH}/client_public.pem", "rb") as f:
            client_public_key = f.read()

        response = requests.post(f"{SERVER}/register", json={
            "username": username,
            "encrypted_rng_token": base64.b64encode(encrypted_rng).decode(),
            "signature": base64.b64encode(signature).decode(),
            "public_key": client_public_key.decode()
        })

        return response.json().get("message", "Errore nella registrazione.")
    except Exception as e:
        return f"Errore: {str(e)}"

def login(username):
    try:
        response = requests.post(f"{SERVER}/login_challenge", json={"username": username})
        if response.status_code != 200:
            return f"Errore challenge: {response.json()['message']}"

        challenge = response.json()["challenge"]

        with open(f"{RSA_PATH}/client_private.pem", "rb") as f:
            client_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        signature = client_private_key.sign(
            challenge.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        response = requests.post(f"{SERVER}/login", json={
            "username": username,
            "signature": base64.b64encode(signature).decode()
        })

        if response.status_code != 200:
            return f"❌ Login fallito: {response.json().get('message', 'Errore')}"
        return f"✅ Login riuscito per {username}"
    except Exception as e:
        return f"Errore: {str(e)}"

# ------------------ GUI ------------------

def start_gui():
    def handle_register():
        user = username_var.get().strip()
        if not user:
            messagebox.showwarning("Attenzione", "Inserisci un nome utente.")
            return
        status_label.config(text="Registrazione in corso...", fg="orange")
        root.update()
        msg = register(user)
        status_label.config(text=msg, fg="green" if "success" in msg.lower() else "red")

    def handle_login():
        user = username_var.get().strip()
        if not user:
            messagebox.showwarning("Attenzione", "Inserisci un nome utente.")
            return
        status_label.config(text="Login in corso...", fg="orange")
        root.update()
        msg = login(user)
        status_label.config(text=msg, fg="green" if msg.startswith("✅") else "red")

    def handle_logout():
        status_label.config(text="Stato: Disconnesso", fg="black")
        username_var.set("")

    root = tk.Tk()
    root.title("Passwordless Client")
    root.geometry("512x512")
    root.resizable(False, False)

    tk.Label(root, text="Nome utente:", font=("Arial", 11)).pack(pady=(10, 0))
    username_var = tk.StringVar()
    tk.Entry(root, textvariable=username_var, width=30).pack(pady=5)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Registrati", command=handle_register, width=15).grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Login", command=handle_login, width=15).grid(row=0, column=1, padx=5)
    tk.Button(button_frame, text="Logout", command=handle_logout, width=15).grid(row=1, column=0, columnspan=2, pady=10)

    global status_label
    status_label = tk.Label(root, text="Stato: In attesa", font=("Arial", 11))
    status_label.pack()

    root.mainloop()

# Entry point
if __name__ == "__main__":
    try:
        init_rsa()
        load_usb()
        start_gui()
    except Exception as e:
        print(f"Errore all'avvio: {e}")
