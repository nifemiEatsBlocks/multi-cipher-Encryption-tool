def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m ==1:
            return x 
    return None


def affine_encrypt(text, a, b):
    if mod_inverse(a,26) is None:
        return "Error: 'a' value is not valid. 'a' must be coprime with 26."
    
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            p = ord(char) - base
            c = (a * p + b) % 26
            encrypted_text += chr(c + base)
        else:
            encrypted_text += char
    return encrypted_text

def affine_decrypt(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "Error : 'a' value is not valid. cannot decrypt."
    
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord ('A') if char.isupper() else ord('a')
            c = ord(char) - base
            p = (a_inv * (c - b)) % 26
            decrypted_text += chr(p + base)
        else:
            decrypted_text += char
    return decrypted_text


# Example:
plaintext = "Hello World"
a = 5
b = 8

print(f"Original Text: {plaintext}")

# --- Encryption ---
encrypted = affine_encrypt(plaintext, a, b)
print(f"Encrypted Text:  {encrypted}")

# --- Decryption ---
decrypted = affine_decrypt(encrypted, a, b)
print(f"Decrypted Text:  {decrypted}")