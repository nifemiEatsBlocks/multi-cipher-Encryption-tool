def generate_bifid_grid(key):
    key = key.upper().replace(' ','').replace('J','I')
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'

    key_set = []
    for char in key:
        if char not in key_set:
            key_set.append(char)
    for char in alphabet:
        if char not in key_set:
            key_set.append(char)
    
    return key_set

def bifid_encrypt(text, key):
    grid = generate_bifid_grid(key)

    plain_chars = [c.upper().replace('J','I') for c in text if c.isalpha()]

    row_coords = []
    col_coords = []

    for char in plain_chars:
        index = grid.index(char)
        row = index // 5
        col = index % 5
        row_coords.append(row)
        col_coords.append(col)
    mixed_coords = row_coords + col_coords

    ciphertext = ''
    for i in range(0, len(mixed_coords), 2):
        r = mixed_coords[i]
        c = mixed_coords[i+1]

        new_index = (r * 5) + c 
        ciphertext += grid[new_index]

    return ciphertext

def bifid_decrypt(ciphertext, key):
    grid = generate_bifid_grid(key)
    cipher_chars = [c for c in ciphertext if c.isalpha()]

    mixed_coords = []
    for char in cipher_chars:
        index = grid.index(char)
        r = index // 5 
        c = index % 5
        mixed_coords.append(r)
        mixed_coords.append(c)

    split_point = len(mixed_coords) // 2

    orig_rows = mixed_coords[:split_point]
    orig_cols = mixed_coords[split_point:]

    plaintext = ''
    for i in range(len(orig_rows)):
        r = orig_rows[i]
        c = orig_cols[i]

        index = (r * 5) + c
        plaintext += grid[index]
    return plaintext 

key = 'SECRET'
message = 'HELLO WORLD'

print(key)
print(message)

encrypted = bifid_encrypt(message, key)
print(encrypted)

decrypted = bifid_decrypt(encrypted, key)
print(decrypted)

