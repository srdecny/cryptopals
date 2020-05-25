
from .c11 import random_bytearray
from .c9 import pkcs7padding
from utils.utils import chunks
import base64
from s1.c7 import encrypt_aes_ecb

STATIC_AES_KEY = random_bytearray(16)
RANDOM_PREFIX = random_bytearray(random_bytearray(1)[0])

def aes_oracle(plaintext):

    secret = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""
    plaintext = RANDOM_PREFIX + plaintext
    plaintext += base64.b64decode(secret)
    plain_chunks = list(chunks(plaintext, 16))

    last_chunk = pkcs7padding(plain_chunks[-1], 16)
    padded_chunks = plain_chunks[:-1] + [last_chunk]
    padded_plaintext = b""
    for chunk in padded_chunks:
        padded_plaintext += chunk

    return encrypt_aes_ecb(padded_plaintext, STATIC_AES_KEY)


def crack_aes(oracle):

    # find the breakpoint in padding
    # this is in a function so we can break from the nested loops cleanly
    def find_breakpoint():
        for pad in range(32, 100):
            encrypted_chunks = list(chunks(oracle(b"A"*pad)))
            # found a duplicating block
            if len(encrypted_chunks) > len(set(encrypted_chunks)):
                for i in range(1, len(encrypted_chunks)):
                    if encrypted_chunks[i - 1] == encrypted_chunks[i]:
                        # index of chunk containing the last bits of the prefix
                        last_prefix = i -2
                        # how many bytes we need to fill out that chunk
                        fill_bytes = pad - 32
                        return (last_prefix, fill_bytes)

    last_prefix, fill_bytes = find_breakpoint()
    print(f"Last block with prefix: {last_prefix}; {fill_bytes} to pad")

    # Just reuse the c12 code

def test():
   crack_aes(aes_oracle) 

test()