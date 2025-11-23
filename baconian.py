def baconian_encrypt(text):
    text = text.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lookup = {}

    for i in range(26):
        binary = bin(i)[2:].zfill(5)
        code = binary.replace('0', 'A').replace('1', 'B')
        lookup[alphabet[i]] = code

    ciphertext = ""
    for char in text:
        if char in lookup:
            ciphertext += lookup[char]
        else:
            pass

    return ciphertext

def baconian_decrypt(ciphertext):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lookup = {}
    for i in range(26):
        binary = bin(i)[2:].zfill(5)
        code = binary.replace("0", "A").replace('1', 'B')
        lookup[code] = alphabet[i]

    plaintext = ""

    cleaned_cipher = ciphertext.replace(" ", "").upper()

    for i in range(0, len(cleaned_cipher), 5):
        chunk = cleaned_cipher[i:i +5]
        if chunk in lookup:
            plaintext += lookup[chunk]
        else:
            plaintext += "?"
    return plaintext

msg = "CODE"
enc = baconian_encrypt(msg)
print(msg)
print(enc)
print(f" / {baconian_decrypt(enc)}")