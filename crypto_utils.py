import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Pad plaintext to 16 bytes
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    output = salt + iv + ciphertext
    with open(file_path + ".encrypted", "wb") as f:
        f.write(output)

    print(f"Encrypted: {file_path}.encrypted")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len]

    out_file = file_path.replace(".encrypted", ".decrypted")
    with open(out_file, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted: {out_file}")
