from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path

# === CONFIG ===
DIR = Path(__file__).parent
PRIVATE_KEY_FILE = DIR / "client_private.pem"
PUBLIC_KEY_FILE = DIR / "client_public.pem"
RNG_TOKEN_FILE = DIR / "rng_token.txt"
SIGNED_TOKEN_FILE = DIR / "signed_token.bin"
SIGNED_CHALLENGE_FILE = DIR / "signed_challenge.bin"

# === LOAD KEYS ===
def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        return key_file.read()  # For upload, not for signature

# === REGISTRAZIONE ===
def register():
    private_key = load_private_key()

    with open(RNG_TOKEN_FILE, "rb") as f:
        token = f.read()

    signed_token = private_key.sign(
        token,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(SIGNED_TOKEN_FILE, "wb") as f:
        f.write(signed_token)

    print("✅ Token firmato salvato in:", SIGNED_TOKEN_FILE)
    print("📤 Da caricare:")
    print("  -", RNG_TOKEN_FILE.name)
    print("  -", PUBLIC_KEY_FILE.name)
    print("  -", SIGNED_TOKEN_FILE.name)

# === LOGIN ===
def login(challenge_file_path):
    private_key = load_private_key()

    with open(challenge_file_path, "rb") as f:
        challenge = f.read()

    signed_challenge = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(SIGNED_CHALLENGE_FILE, "wb") as f:
        f.write(signed_challenge)

    print("🔐 Challenge firmata salvata in:", SIGNED_CHALLENGE_FILE)

# === ESEMPIO USO ===
if __name__ == "__main__":
    import sys

    if len(sys.argv) == 1:
        print("Usa:")
        print("  python script.py register")
        print("  python script.py login <challenge_file>")
    elif sys.argv[1] == "register":
        register()
    elif sys.argv[1] == "login" and len(sys.argv) == 3:
        login(sys.argv[2])
    else:
        print("Argomenti non validi.")
