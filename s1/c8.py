import base64
from collections import Counter
def detect_aes(byte_lines):
    most_duplicates = 0
    ciphered_line = ""
    for line in byte_lines:
        blocks = list(split_to_blocks(line, 16))
        duplicates = len(blocks) - len(set(blocks))
        if duplicates > most_duplicates:
            most_duplicates = duplicates
            ciphered_line = line
    print(most_duplicates)
    return ciphered_line


def split_to_blocks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def test():
    with open("c8_data.txt") as f:
        lines = f.read().splitlines()
        byte_lines = list(map(base64.b64decode, lines))
        print(detect_aes(byte_lines))

test()
