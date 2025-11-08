def xor_cipher(text, key):
    if isinstance(text, str):
        text = text.encode()

    if len(key) < len (text):
        key = key * (len(text) // len(key) + 1)
        key = key[:len(text)]

    return bytes( [x ^ y for x, y in zip(text,key)])


original_text = "blah blah tr"

key = b'secret'

encrypted = xor_cipher(original_text, key )

print(encrypted)

decrypted  = xor_cipher(encrypted, key)
print(decrypted)