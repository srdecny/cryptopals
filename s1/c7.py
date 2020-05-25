from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def decrypt_aes_ecb(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()) 
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def encrypt_aes_ecb(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()) 
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def test():
    contents = open("c7_data.txt", "r").read()
    contents = base64.b64decode(contents)
    decrypt_aes_ecb(contents, b"YELLOW SUBMARINE")
