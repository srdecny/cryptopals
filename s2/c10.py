from utils.utils import chunks
from .c9 import pkcs7padding
from s1.c2 import fixed_xor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import pathlib

CHUNK_SIZE = 16

def decrypt_aes_cbc(ciphertext, key, iv):
    assert len(iv) == CHUNK_SIZE

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()) 
    plaintext = b""
    for chunk in chunks(ciphertext, CHUNK_SIZE):
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(chunk) + decryptor.finalize()
        plaintext += fixed_xor(decrypted, iv) 
        iv = chunk
        
    return plaintext

def encrypt_aes_cbc(plaintext, key, iv):
    assert len(iv) == CHUNK_SIZE

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()) 
    ciphertext = b""
    for chunk in chunks(plaintext, CHUNK_SIZE):
        if len(chunk) < CHUNK_SIZE:
            chunk = pkcs7padding(chunk, CHUNK_SIZE)
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(fixed_xor(chunk, iv))
        iv = encrypted
        ciphertext += encrypted

    return ciphertext

def test():
    with open(pathlib.Path(__file__).parent / "c10_data.txt") as f:
        ciphertext = base64.b64decode(f.read())
        plaintext = decrypt_aes_cbc(ciphertext, b"YELLOW SUBMARINE", b"\x00"*16)
        print(plaintext)