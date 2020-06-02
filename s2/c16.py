from utils.utils import random_bytearray, pkcs7_pad, chunks
from .c10 import encrypt_aes_cbc, decrypt_aes_cbc

AES_KEY = random_bytearray(16)
INITIAL_VECTOR = random_bytearray(16)

def create_cookie(input):
    input = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon"
    return encrypt_aes_cbc(pkcs7_pad(input.encode("ascii", "replace")), AES_KEY, INITIAL_VECTOR)

def check_admin(ciphertext):
    plaintext = decrypt_aes_cbc(ciphertext, AES_KEY, INITIAL_VECTOR)
    print(plaintext)
    return b";admin=true;" in plaintext

def bruteforce():
    base_ciphertext = list(chunks(create_cookie("XadminXtrue")))

    for x in range(0, 256):
        for y in range(0, 256):
            c = bytearray()
            c[:] = base_ciphertext[1]
            c[0] = x
            c[6] = y

            if (check_admin(base_ciphertext[0] + c + base_ciphertext[2] + base_ciphertext[3])):
                print("Obtained admin rights")
                exit() 

def test():
    bruteforce()

test()

   