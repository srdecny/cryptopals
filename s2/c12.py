import random
from .c10 import encrypt_aes_cbc
from .c11 import random_bytearray
from .c9 import pkcs7padding
from s1.c7 import encrypt_aes_ecb
from utils.utils import chunks
import pathlib
import string

import base64

STATIC_AES_KEY = random_bytearray(16)

def aes_oracle(plaintext):

    secret = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""

    plaintext += base64.b64decode(secret)
    
    plain_chunks = list(chunks(plaintext, 16))
    last_chunk = pkcs7padding(plain_chunks[-1], 16)
    padded_chunks = plain_chunks[:-1] + [last_chunk]
    padded_plaintext = b""
    for chunk in padded_chunks:
        padded_plaintext += chunk

    return encrypt_aes_ecb(padded_plaintext, STATIC_AES_KEY)

def crack_aes(aes_function):
    b_size = 0
    # last bytes are going to be padding bytes + last character of ciphertext
    # a cycle in the last bytes is the block size
    last_bytes = [cipher[-2] for cipher in map(lambda i: aes_function(b"A"*i), range(1, 100))]
    last_two_bytes = last_bytes[-2:]
    for possible_block_size in range(2, 100):
        if last_bytes[ -(2 + possible_block_size) : -(possible_block_size)] == last_two_bytes:
            b_size = possible_block_size
            break
    print(f"Block size: {b_size}")

    # given two same plaintext blocks, check if the ciphertext is also the same
    ciphertext_chunks = list(chunks(aes_function(b"A"*2*b_size), b_size))
    if ciphertext_chunks[0] == ciphertext_chunks[1]:
        print("ECB detected...")
    else:
        print("First two blocks do not match, aborting...")
        return
    
    mapping = {}
    secret = b""

    byte_index = 0
    block_index = 0

    def cipher_block(plaintext, idx):
        return list(chunks(aes_function(plaintext), b_size))[idx]

    while True:
        padding = b_size - 1 - (byte_index % (b_size))
        leak_query = (b"A"* padding)
        leak_cipher = cipher_block(leak_query, block_index)

        if leak_cipher in mapping:
            secret += mapping[leak_cipher]

        else:
            found = False
            for byte in range(0, 256):
                test_block = leak_query + secret[:len(secret)] + bytes([byte]) 
                test_cipher = cipher_block(test_block, block_index)
                if test_cipher == leak_cipher:
                    mapping[test_cipher] = bytes([byte]) 
                    secret += bytes([byte])
                    print(f"\r{secret}", end="")
                    found = True
                    break
            if not found:
                print("\nFailed to find next byte")
                return

        byte_index += 1
        block_index = byte_index // b_size



def test():
    crack_aes(aes_oracle)

test()