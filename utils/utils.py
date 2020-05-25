import random

def chunks(lst, n=16):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

# Flattens a list of bytearrays
def flatten(lst):
    res = b""
    for arr in lst:
        res += arr
    return res

def random_bytearray(length):
    rng = random.Random()
    return bytearray(rng.getrandbits(8) for _ in range(0, length))

def pkcs7_pad(text, size=16):
   pad_count = size - (len(text) % size)
   if pad_count == 0:
       pad_count = size
   return text + (bytes([pad_count]) * pad_count)

def pkcs7_strip(text):
    return text[:-(text[-1])]

