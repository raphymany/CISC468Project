import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_session_key(shared_secret):
    """Derive a session key from the shared secret using PBKDF2."""
    salt = b"secure_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)

def encrypt_file_data(data, session_key):
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    encryptor = Cipher(
        algorithms.AES(session_key),
        modes.GCM(nonce),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def decrypt_file_data(nonce, tag, ciphertext, session_key):
    print(f"[DEBUG] Decrypting chunk: Nonce={nonce.hex()}, Tag={tag.hex()}, Ciphertext={ciphertext.hex()[:64]}...")
    decryptor = Cipher(
        algorithms.AES(session_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print(f"[DEBUG] Decrypted plaintext: {plaintext[:64]}...")
    return plaintext

def list_files():
    shared_dir = "shared_files"

    # Ensure the directory exists
    if not os.path.exists(shared_dir):
        os.makedirs(shared_dir)
        print(f"Shared directory '{shared_dir}' created. No files to list yet.")
        return

    # List files in the directory
    files = os.listdir(shared_dir)
    if files:
        print("\nFiles you are sharing:")
        for file in files:
            print(f"  - {file}")
    else:
        print("No files are currently being shared.")