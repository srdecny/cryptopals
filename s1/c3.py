import functools
import codecs

letterFrequency = {
    ' ' : 17.1,
    ',' : 1.7,
    '.' : 0.7,
    '1' : 2.2,
    '2' : 2.2,
    '3' : 2.2,
    '4' : 2.2,
    '5' : 2.2,
    '6' : 2.2,
    '7' : 2.2,
    '8' : 2.2,
    '9' : 2.2,
    '0' : 2.2,
    'E' : 11.16,
    'T' : 9.3,
    'A' : 8.49,
    'O' : 7.5,
    'I' : 7.54,
    'N' : 6.74,
    'S' : 6.32,
    'R' : 7.58,
    'H' : 6.09,
    'D' : 4.25,
    'L' : 4.02,
    'U' : 2.75,
    'C' : 2.20,
    'M' : 2.40,
    'F' : 2.22,
    'Y' : 1.99,
    'W' : 2.56,
    'G' : 2.01,
    'P' : 1.92,
    'B' : 1.49,
    'V' : 0.97,
    'K' : 1.29,
    'X' : 0.15,
    'Q' : 0.09,
    'J' : 0.15,
    'Z' : 0.07 
}

def score_string(string):
    score = 0
    for letter in string:
        letter = letter.upper()
        if letter in letterFrequency:
            score += letterFrequency[letter]
    return score

def xor_string(string, key):
    return "".join([chr(char ^ key) for char in string])

def crack_xor(ciphertext):
    top_score = 0
    top_string = ""
    top_key = ""

    for candidate_key in range(256): # all possible byte values
        decoded_string = xor_string(ciphertext, candidate_key)
        score = score_string(decoded_string)
        if score > top_score:
            top_score = score
            top_string = decoded_string 
            top_key = candidate_key
    return top_key

def test():
    print(crack_xor(codecs.decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", hex)))