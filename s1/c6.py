import base64
import itertools
from c3 import crack_xor

def hamming_distance(first, second):
    differences = 0
    for (f, s) in zip(first, second):
        differences += bin(f ^ s).count("1")
    return differences

def break_repeating_xor(bytes):
        best_keysize = 0
        smallest_distance = 100_000
        for keysize in range(2, 41):
            distance = 0
            block_count = len(bytes) // keysize
            first_blocks = split_to_blocks(bytes, keysize)
            second_blocks = itertools.islice(split_to_blocks(bytes, keysize), 1, None) 
            for first_block, second_block in zip(first_blocks, second_blocks):
                # Check pairs of neighbouring split_to_blocks
                distance += hamming_distance(first_block, second_block) / keysize
            distance = distance / block_count
            if distance < smallest_distance:
                smallest_distance = distance
                best_keysize = keysize

        print(f"Determined key size is {best_keysize}")

        blocks = list(split_to_blocks(bytes, best_keysize))
        transposed_blocks = list(itertools.zip_longest(*blocks, fillvalue=0))
        key = ""
        for block in transposed_blocks:
            key += chr(crack_xor(block))
        print(key)
            

def split_to_blocks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def test():
    contents = open("c6_data.txt", "r").read()
    contents = base64.b64decode(contents)
    break_repeating_xor(contents)

test()