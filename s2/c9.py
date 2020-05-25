def pkcs7padding(b, length):
    padded_bytes = length - len(b)
    if padded_bytes < 1:
        return b
    return b + (bytes([padded_bytes]) * padded_bytes)

def test():
    print(pkcs7padding("YELLOW SUBMARINE".encode(), 20))
