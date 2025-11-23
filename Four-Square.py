def generate_foursquare_grid(key=""):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = key.upper().replace("J", "I").replace(" ","")

    grid = ""
    for char in key + alphabet:
        if char not in grid and char in alphabet:
            grid += char 
    return grid 

def foursquare_encrypt(text, key1, key2):
    std_alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    grid_TL = std_alpha
    grid_BR = std_alpha
    grid_TR = generate_foursquare_grid(key1)
    grid_BL = generate_foursquare_grid(key2)

    text = text.upper().replace("J", "I").replace(" ","")
    if len(text) % 2==1: text += "X"

    ciphertext = ""
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i+1]


        idx_a = grid_TL.index(a)
        row_a, col_a = divmod(idx_a, 5)

        idx_b = grid_BR.index(b)
        row_b, col_b = divmod(idx_b, 5)


        c1 = grid_TR[row_a * 5 + col_b]
        c2 = grid_BL[row_b * 5 + col_a]

        ciphertext += c1 + c2

    return ciphertext

def foursquare_decrypt(ciphertext, key1, key2):
    std_alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    grid_TL = std_alpha
    grid_BR = std_alpha
    grid_TR = generate_foursquare_grid(key1)
    grid_BL = generate_foursquare_grid(key2)

    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        c1 = ciphertext[i]
        c2 = ciphertext[i + 1]

        idx_c1 = grid_TR.index(c1)
        row_a, col_b = divmod(idx_c1, 5)

        idx_c2 = grid_BL.index(c2)
        row_b, col_a = divmod(idx_c2, 5)

        p1 = grid_TL[row_a * 5 + col_a]
        p2 = grid_BR[row_b * 5 + col_b]

        plaintext += p1 + p2

    return plaintext

k1 = "SECRET"
k2 = "PASSWORD"
msg = "ATTACKATDAWN"

enc = foursquare_encrypt(msg, k1, k2)
print(f"Encrypted: {enc}")
print(f"Decrypted: {foursquare_decrypt(enc, k1, k2)}")

