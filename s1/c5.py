def repeating_xor(plaintext, key):
    plaintext = plaintext.encode()
    key = key.encode()

    ciphertext = bytearray()
    for index, char in enumerate(plaintext):
        xored_char = char ^ key[index % len(key)]
        ciphertext.append(xored_char)
    return ciphertext.hex() 
    
def test():
    print(repeating_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))
    print("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

test()