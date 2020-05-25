from c3 import crack_xor, score_string

def detect_xor(filename):
    top_score = 0
    top_message = ""
    with open(filename) as file:
        for message in file.read().splitlines():
            decoded_message = crack_xor(message)
            score = score_string(decoded_message)
            if score > top_score:
                top_score = score
                top_message = decoded_message
    return top_message

def test():
    print(detect_xor("c4_data.txt"))
