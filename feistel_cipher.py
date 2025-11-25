def feistel_function(val, key_char):
    return (val*11 + ord(key_char)) % 256

def feistel_encrypt(text, key, rounds = 4):
    if len(text) % 2 != 0: text += " "
    ciphertext = ''

    for i in range(0, len(text), 2):
        L = ord(text[i])
        R = ord(text[i + 1])

        for i in range(0, len(text), 2 ):
            L = ord(text[i])
            R = ord(text[i+1])

            for r in range(rounds):
                k_char = key[r % len(key)]

                temp = R
                func_output = feistel_function(R, k_char)
                R = L ^ func_output
                L = temp

            ciphertext += f'{L:02X}{R:02X}'
        return ciphertext
    
def feistel_decrypt(hex_text, key, rounds = 4):
    plaintext = ""

    for i in range(0, len(hex_text), 4):
        L = int(hex_text[i:i+2], 16)
        R = int(hex_text[i+2 : i+4], 16)

        for r in reversed(range(rounds)):
            k_char = key[r % len(key)]

            temp = L 
            func_output = feistel_function(L, k_char)
            L = R ^ func_output
            R = temp

        plaintext += chr(L) + chr(R)

    return plaintext

