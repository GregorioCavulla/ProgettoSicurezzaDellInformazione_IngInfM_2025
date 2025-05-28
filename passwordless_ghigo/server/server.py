from flask import Flask, request, jsonify
import json
import base64
import os
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__) # Initialize Flask app
USER_DB = "users.json"
RNG_DB = "rng.json"

# Load databases
def load_json(file): # load json file or return empty dict if not exists
    return json.load(open(file, "r")) if os.path.exists(file) else {}


# Save databases
def save_json(file, data): # save json file
    with open(file, "w") as f:
        json.dump(data, f, indent=2)

        
# Generate server RSA key pair if not present in /rsa_keys
def init_rsa():
    if not os.path.exists("rsa_keys"):
        os.makedirs("rsa_keys")
    if not os.path.exists("rsa_keys/server_private.pem"):
        from cryptography.hazmat.primitives.asymmetric import rsa
        server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        server_public_key = server_private_key.public_key()
        
        # Save server private key
        with open("rsa_keys/server_private.pem", "wb") as f:
            f.write(server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save server public key
        with open("rsa_keys/server_public.pem", "wb") as f:
            f.write(server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
init_rsa()

# Initialize databases
def init_databases():
    if not os.path.exists(USER_DB):
        with open(USER_DB, "w") as f:
            json.dump({}, f)
    if not os.path.exists(RNG_DB):
        with open(RNG_DB, "w") as f:
            json.dump({}, f)
    # If RNG database is empty, generate a new RNG token
    rng_data = load_json(RNG_DB)
    if not rng_data:
        rng_token = secrets.token_hex(16)
        rng_data[rng_token] = "available"
        save_json(RNG_DB, rng_data)
init_databases()

# Generate new usb device
def init_usb_device():
    if not os.path.exists("../usb_device"):
        os.makedirs("../usb_device")
    # Empty the usb device directory
    for file in os.listdir("../usb_device"):
        file_path = os.path.join("../usb_device", file)
        if os.path.isfile(file_path):
            os.remove(file_path)
    # Simulate writing to USB
    rng_data = load_json(RNG_DB)
    rng_token = list(rng_data.keys())[0]
    # rng token
    with open("../usb_device/rng_token.txt", "w") as f:
        f.write(rng_token)
    print("Generated RNG token and saved to simulated USB device.")
    with open("rsa_keys/server_public.pem", "rb") as f:
        public_key = f.read()
    # public key
    with open("../usb_device/server_public.pem", "wb") as f:
        f.write(public_key)
init_usb_device()

users = load_json(USER_DB)
rng_data = load_json(RNG_DB)

# Endpoints

# Register endpoint
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    """ 
    User sends:
    {
        "username": "xxx",
        "encrypted_rng_token": "base64_encoded_encrypted_rng_token",
        "signature": "base64_encoded_signature",
        "public_key": "public_key"
    }
    """
    e_rng_token = data["encrypted_rng_token"]
    signature = base64.b64decode(data["signature"])
    public_key_pem = data["public_key"].encode()
    username = data["username"]
    
    # Load user public key
    user_public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    # Decrypt RNG token with server private key
    with open("rsa_keys/server_private.pem", "rb") as f:
        server_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    try:
        rng_token = server_private_key.decrypt(
            base64.b64decode(e_rng_token),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    except Exception as e:
        return jsonify({"status": "error", "message": "Decryption failed"}), 400
    # Check if RNG token is valid
    if rng_token not in rng_data or rng_data[rng_token] != "available":
        return jsonify({"status": "error", "message": "Invalid or expired token"}), 400
    # Verify signature
    try:
        user_public_key.verify(
            signature,
            base64.b64decode(e_rng_token),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        return jsonify({"status": "error", "message": "Signature verification failed"}), 400
    # Token is valid and signature correct
    users[username] = {
        "public_key": public_key_pem.decode(),
        "rng_token": rng_token
    }
    del rng_data[rng_token]
    save_json(USER_DB, users)
    save_json(RNG_DB, rng_data)
    init_databases()  # Ensure databases are initialized after registration
    print(f"User {username} registered successfully with RNG token {rng_token} and public key {public_key_pem.decode()}.")
    return jsonify({"status": "success", "message": f"User {username} registered successfully."})


# Login endpoint
@app.route("/login", methods=["POST"])
def login():
    """
    User sends:
    {
        "username": "xxx",
        "signature": "base64_encoded_signature"
    }
    """
    data = request.json
    username = data["username"]
    signature = base64.b64decode(data["signature"])

    # Ricarica users aggiornato
    users = load_json(USER_DB)

    # Check if user is registered
    if username not in users:
        return jsonify({"status": "error", "message": "Unknown user"}), 400

    # Load user's public key
    user_public_key = serialization.load_pem_public_key(
        users[username]["public_key"].encode(),
        backend=default_backend()
    )
    
    # Get challenge from user
    users = load_json(USER_DB)
    challenge = users[username].get("challenge")
    if not challenge:
        return jsonify({"status": "error", "message": "No challenge found for user"}), 400
    
    # Verify signature
    try:
        user_public_key.verify(
            signature,
            challenge.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        return jsonify({"status": "error", "message": "Signature verification failed"}), 400
    
    print(f"User {username} logged in successfully.")
    return jsonify({"status": "success", "message": f"User {username} logged in successfully."})



# Challenge endpoint
@app.route("/login_challenge", methods=["POST"])
def login_challenge():
    """
    User sends:
    {
        "username": "xxx"
    }
    """
    username = request.json["username"]
    print(f"Received login challenge request for user: {username}")
    users = load_json(USER_DB)
    # Check if user is registered
    if username not in users:
        return jsonify({"status": "error", "message": "Unknown user"}), 400
    # Generate a challenge
    challenge = base64.b64encode(secrets.token_bytes(32)).decode()
    users[username]["challenge"] = challenge
    save_json(USER_DB, users)
    print(f"Login challenge generated for user: {username}, challenge: {challenge}")
    return jsonify({"challenge": challenge})



def init_server():
    """ Initialize the server by loading databases and generating keys. """
    init_rsa()  # Ensure RSA keys are initialized
    init_databases()  # Ensure databases are initialized
    init_usb_device()  # Initialize USB device with RNG token and public key
init_server()

#main function
def main():
    """ Main function to run the server. """
    app.run(host="localhost", port=5000, debug=True)
if __name__ == "__main__":
    # Ensure the server is initialized before running
    init_server()
    # Start the server
    print("Starting server...")
    print("Server initialized successfully.")
    print("Listening on http://localhost:5000")
    print("Press Ctrl+C to stop the server.")
main()
