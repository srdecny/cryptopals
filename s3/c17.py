from utils.utils import random_bytearray, pkcs7_pad, chunks
from s2.c15 import validate_pkcs7
from s2.c10 import encrypt_aes_cbc, decrypt_aes_cbc
import random
import base64

inputs = [
    b"iMDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]

AES_KEY = random_bytearray(16)
INITIAL_VECTOR = random_bytearray(16)

def encrypt():
    message = inputs[random.randint(0, 9)]
    message = pkcs7_pad(base64.b64decode(message))
    print(message)
    return encrypt_aes_cbc(message, AES_KEY, INITIAL_VECTOR)
    
def validate_padding(ciphertext):
    plaintext = decrypt_aes_cbc(ciphertext, AES_KEY, INITIAL_VECTOR)
    try:
        validate_pkcs7(plaintext)
        return True
    except Exception:
        return False 

def cbc_padding_oracle_attack(ciphertext):
    blocks = list(chunks(ciphertext))
    plaintext = b""

    # Pairs of blocks, the second one is decrypted
    for o1, o2 in zip(blocks, blocks[1:]):
        decryptedchunk = bytearray(len(o1))
        plainchunk = bytearray(len(o1))
        c1 = bytearray(o1)
        c2 = bytearray(o2)

        # Indexes of characters to decrypt
        indexes = list(reversed(range(0, len(c1))))
        for index in indexes:
            # How many characters are already decrypted
            solved_count = len(c1) - index - 1
            for solved in indexes[:solved_count]:
                # Set the characters so they result in "proper" padding
                c1[solved] = decryptedchunk[solved] ^ (solved_count + 1)
            for byte in range(0, 256):
                c1[index] = byte
                if (validate_padding(bytes(c1 + c2))):
                    decryptedchunk[index] = byte ^ (solved_count + 1)
                    plainchunk[index] = decryptedchunk[index] ^ o1[index]
                    break
                else:
                    continue
        plaintext += bytes(plainchunk)
    return plaintext
