import random
from .c10 import encrypt_aes_cbc
from .c9 import pkcs7padding
from s1.c7 import encrypt_aes_ecb
from utils.utils import chunks, random_bytearray
import pathlib
import base64


def aes_oracle(plaintext):
    rng = random.Random()
    prefix = random_bytearray(rng.randint(5, 10))
    suffix = random_bytearray(rng.randint(5, 10))
    plaintext = prefix + plaintext + suffix
    
    plain_chunks = list(chunks(plaintext, 16))
    last_chunk = pkcs7padding(plain_chunks[-1], 16)
    padded_chunks = plain_chunks[:-1] + [last_chunk]
    padded_plaintext = b""
    for chunk in padded_chunks:
        padded_plaintext += chunk

    aes_key = random_bytearray(16)

    if (rng.randint(0,1) == 0): # ECB mode
        print("Encrypting in ECB mode...")
        return encrypt_aes_ecb(padded_plaintext, aes_key)
    else: # CBC mode
        aes_iv = random_bytearray(16)
        print("Encrypting in CBC mode...")
        return encrypt_aes_cbc(padded_plaintext, aes_key, aes_iv)

def aes_detect(encryption_function):
    plaintext = b"A"*100
    ciphertext = encryption_function(plaintext)
    ciphertext_chunks = list(chunks(ciphertext, 16))    
    if len(ciphertext_chunks) != len(set(ciphertext_chunks)):
        print("ECB detected")
    else:
        print("CBC detected")

def test():
    for _ in range(1,10):
        aes_detect(aes_oracle)
