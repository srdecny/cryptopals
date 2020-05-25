def validate_pkcs7(string):
    padding_size = string[-1]
    padding_block = string[-(padding_size):]
    if padding_block.count(padding_block[0]) != len(padding_block):
        raise Exception("Invalid PKCS7 padding")
    return string[:-(padding_size)]