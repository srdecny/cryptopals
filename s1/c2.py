def fixed_xor(buf1, buf2):
    res = bytearray([x ^ y for (x, y) in zip(buf1, buf2)])
    return res

def test():
    res = fixed_xor("1c0111001f010100061a024b53535009181c", 
            "686974207468652062756c6c277320657965")
    return res == b"746865206b696420646f6e277420706c6179"