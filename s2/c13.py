import json
from urllib.parse import parse_qs, urlencode, quote
import html
from s1.c7 import encrypt_aes_ecb, decrypt_aes_ecb
from s2.c9 import pkcs7padding
from utils.utils import random_bytearray, pkcs7_pad, pkcs7_strip, chunks, flatten

AES_KEY = random_bytearray(16)

def parse_querystring(params):
    return json.dumps(parse_qs(params))

def profile_for(email):
    if "&" in email or "=" in email:
        raise Exception("Invalid characters in email")

    json = {
        "email": email,
        "uid": 10,
        "role": "user"
    }

    return "&".join(f"{key}={value}" for (key, value) in json.items()).encode()

def encrypt(email):
    plaintext = profile_for(email)
    plaintext = pkcs7_pad(plaintext)
    return encrypt_aes_ecb(plaintext, AES_KEY)

def decrypt(ciphertext):
    plaintext = decrypt_aes_ecb(ciphertext, AES_KEY)
    plaintext = pkcs7_strip(plaintext).decode()
    return parse_querystring(plaintext)

def cutnpaste(oracle):
    # find the breakpoint for padding
    pad_len = 0
    for pad in range(32, 100):
        oracle_chunks = list(chunks(oracle("A"*pad), 16))
        if oracle_chunks[1] == oracle_chunks[2]:
            pad_len = pad % 16
            break
    payload = "A"*(pad_len) + "admin" + "\v"*11
    payload_chunk = list(chunks(oracle(payload)))[1]

    cut_payload = "A"*(3+pad_len)
    cut_chunks = list(chunks(oracle(cut_payload)))[:-1]
    cut_chunks.append(payload_chunk)

    print(decrypt(flatten(cut_chunks)))

def test():
    cutnpaste(encrypt)
