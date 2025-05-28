#AIO client

import requests
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os

username = ""
SERVER = "http://localhost:5000"
DEVICE_PATH = "../usb_device"

# Generate client RSA key pair if not present in /rsa_keys
def init_rsa():
    if not os.path.exists("rsa_keys"):
        os.makedirs("rsa_keys")
    if not os.path.exists("rsa_keys/client_private.pem"):
        from cryptography.hazmat.primitives.asymmetric import rsa
        client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        client_public_key = client_private_key.public_key()
        
        # Save server private key
        with open("rsa_keys/client_private.pem", "wb") as f:
            f.write(client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save server public key
        with open("rsa_keys/client_public.pem", "wb") as f:
            f.write(client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Client RSA key pair generated and saved.")


# Load usb_device data
def load_usb():
    # Loading rng token from usb_device
    if not os.path.exists(os.path.join(DEVICE_PATH, "rng_token.txt")):
        raise FileNotFoundError("RNG token file not found in usb_device.")
    with open(os.path.join(DEVICE_PATH, "rng_token.txt"), "r") as f:
        rng_token = f.read().strip()
    # Loading server public key from usb_device
    if not os.path.exists(os.path.join(DEVICE_PATH, "server_public.pem")):
        raise FileNotFoundError("Server public key file not found in usb_device.")
    with open(os.path.join(DEVICE_PATH, "server_public.pem"), "rb") as f:
        server_public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    # Save loaded data to files
    with open("rng_token.txt", "w") as f:
        f.write(rng_token)
    with open("server_public.pem", "wb") as f:
        f.write(server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("USB device data loaded successfully.")


# ask to user for username
def get_username():
    global username
    username = input("Enter your username: ").strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    print(f"Username set to: {username}")


# Registration
def registration():
    # read usb device for new rng token and server public key
    load_usb()
    """Register the user with the server sending RNG token and client public key, encrypted with server public key."""
    # Read RNG token
    with open("rng_token.txt", "r") as f:
        rng_token = f.read().strip()
    
    # Load client public key
    with open("rsa_keys/client_public.pem", "rb") as f:
        client_public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    # Encrypt RNG token with server public key
    with open("server_public.pem", "rb") as f:
        server_public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    encrypted_rng_token = server_public_key.encrypt(
        rng_token.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Sign the encrypted RNG token with client private key
    with open("rsa_keys/client_private.pem", "rb") as f:
        client_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    signature = client_private_key.sign(
        encrypted_rng_token,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Send registration request to server
    response = requests.post(SERVER + "/register", json={
        "username": username,
        "encrypted_rng_token": base64.b64encode(encrypted_rng_token).decode(),
        "signature": base64.b64encode(signature).decode(),
        "public_key": client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    })
    print(response.json())
    # if response.status_code = 200, delete rng_token.txt
    if response.status_code == 200:
        print("Registration successful.")
        os.remove("rng_token.txt")
    else:
        print("Registration failed:", response.text)


# Login
def login():
    """ Sending login request to server with signed challenge."""
    # Get login challenge from server
    response = requests.post(SERVER + "/login_challenge", json={"username": username})
    if response.status_code != 200:
        print("Error getting login challenge:", response.json())
        return
    
    challenge = response.json()["challenge"]
    print(f"Received challenge: {challenge}")
    
    # Load client private key
    with open("rsa_keys/client_private.pem", "rb") as f:
        client_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Sign the challenge
    signature = client_private_key.sign(
        challenge.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Send login request to server
    response = requests.post(SERVER + "/login", json={
        "username": username,
        "signature": base64.b64encode(signature).decode()
    })
    if response.status_code != 200:
        print("Login failed:", response.text)
    else:
        print(response.json())


# Main function to run the client
def main():
    init_rsa()
    load_usb()
    global username
    get_username()
    while( True ):
        choice = input("Do you want to register (r) or login (l)? ").strip().lower()
        if choice == 'r':
            registration()
        elif choice == 'l':
            login()
        else:
            print("Invalid choice. Please enter 'r' for register or 'l' for login.")
        cont = input("Do you want to continue? (y/n): ").strip().lower()
        if cont != 'y':
            break
if __name__ == "__main__":
    main()
