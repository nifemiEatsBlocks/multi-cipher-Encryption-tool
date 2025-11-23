def beaufort_cipher(text, key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    text = text.upper()
    key = key.upper()

    result = ""
    key_index = 0 

    for char in text:
        if char.isalpha():
            p_val = alphabet.index(char)

            k_char = key[key_index % len(key)]
            k_val = alphabet.index(k_char)

            c_val = (k_val - p_val) % 26

            result += alphabet[c_val]
            key_index += 1
        else:
            result += char

    return result

key = 'KEY'
text = "HELLO WORLD"

encrypted = beaufort_cipher(text, key)
print(f"Plain: {text}")
print(f"Encrypted: {encrypted}")

decrypted = beaufort_cipher(encrypted, key)
print(f"Decrypted: {decrypted}")
