def autokey_encrypt(text, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    key_chars = list(key.upper())
    plain_letters = [c.upper() for c in text if c.isalpha()]
    full_key_stream = key_chars + plain_letters
    result = ''
    key_index = 0

    for char in text:
        if char.isalpha():
            is_upper = char.isupper()

            p_val = alphabet.index(char.upper())
            k_val = alphabet.index(full_key_stream[key_index])
            c_val = (p_val + k_val) % 26
            new_char = alphabet[c_val]

            if not is_upper:
                new_char = new_char.lower()

            result += new_char
            key_index += 1
        else:
            result += char
    return result

def autokey_decrypt(ciphertext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    current_key_queue = list (key.upper())

    result = ''
    for char in ciphertext:
        if char.isalpha():
            is_upper = char.isupper()
            k_char = current_key_queue.pop(0)
            c_val = alphabet.index(char.upper())
            k_val = alphabet.index(k_char)
            p_val = (c_val - k_val) % 26
            p_char = alphabet[p_val]
            current_key_queue.append(p_char)

            if not is_upper:
                p_char = p_char.lower()

            result += p_char
        else:
            result += char
    return result

key = 'FORTRESS'
message = 'Attack at dawn, troops!'

print(message)
print(key)

encrypted = autokey_encrypt(message, key)
print(encrypted)

decrypted = autokey_decrypt(encrypted, key)
print(decrypted)