def rc4_encrypt(text, key):
    S = list(range(256))
    j = 0
    key_bytes = [ord(c) for c in key]

    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    ciphertext = []

    for char in text:
        i = (i + 1) %256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]

        k = S[(S[i] + S[j]) % 256]

        cipher_byte = ord(char) ^ k
        ciphertext.append(cipher_byte)

    return ''.join(f'{byte:02x}' for byte in ciphertext)

def rc4_decrypt(hex_text, key):
    ciphertext_bytes = bytes.fromhex(hex_text)

    S = list(range(256))
    j = 0
    key_bytes = [ord(c) for c in key]

    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    plaintext = ''

    for byte in ciphertext_bytes:
        i = (i + 1 )% 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]

        k = S[(S[i] + S[j]) % 256]

        plain_char = chr(byte ^ k)
        plaintext += plain_char

    return plaintext

