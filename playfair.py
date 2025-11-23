def generate_playfair_grid(key):
    key = key.upper().replace(" ", "")
    key = key.replace("J", "I")

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    key_set = []
    for char in key:
        if char not in key_set:
            key_set.append(char)

    for char in alphabet:
        if char not in key_set:
            key_set.append(char)

    grid = []
    for i in range(5):
        grid.append(key_set[i*5 : (i +1)*5])
    return grid


def get_char_coords(char, grid):
    for r in range(5):
        for c in range(5):
            if grid[r][c] == char :
                return r, c
    return None

def prepare_plaintext(text):
    text = text.upper().replace(" ", "")
    text = text.replace("J","I")

    prepared = []
    i = 0
    while i< len(text):
        if i == len(text) - 1:
            prepared.append(text[i] + "X")
            i += 1
        elif text[i] == text[i + 1]:
            prepared.append(text[i] + "X")
            i += 1
        else:
            prepared.append(text[i] + text[i +1 ])
            i += 2

    return prepared

def playfair_encrypt(plaintext, key):
    grid = generate_playfair_grid(key)
    prepared_pairs = prepare_plaintext(plaintext)

    ciphertext = ""
    for pair in prepared_pairs:
        char1, char2 = pair[0], pair[1]
        r1, c1 = get_char_coords(char1, grid)
        r2, c2 = get_char_coords(char2, grid)

        if r1 == r2:
            new_char1 = grid[r1][(c1 + 1) % 5]
            new_char2 = grid[r2][(c2 + 1) % 5]

        elif c1 == c2:
            new_char1 = grid[(r1 + 1 ) % 5][c1]
            new_char2 = grid[(r2 + 1) % 5][c2]

        else:
            new_char1 = grid[r1][c2]
            new_char2 = grid [r2][c1]

        ciphertext += new_char1 + new_char2

    return ciphertext

def playfair_decrypt(ciphertext, key):
    grid = generate_playfair_grid(key)

    decrypted_text = ""
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i+1]
        r1, c1 = get_char_coords(char1, grid)
        r2, c2 = get_char_coords(char2, grid)

        if r1 == r2:
            new_char1 = grid[r1][(c1 - 1 +5) % 5]
            new_char2 = grid[r2][(c2 - 1 +5 ) % 5]

        elif c1== c2:
            new_char1 = grid[(r1 -1 +5) % 5][c1]
            new_char2 = grid[(r2 -1 +5) % 5][c2]
        else:
            new_char1 = grid[r1][c2]
            new_char2 = grid[r2][c1]

        decrypted_text += new_char1 + new_char2

    final_text = []
    i = 0
    while i < len(decrypted_text):
        if i < len(decrypted_text) - 1 and decrypted_text[i+1] == 'X':
            if (i + 2 < len(decrypted_text) and decrypted_text[i] == decrypted_text[i+2]) or \
                (i + 2 == len(decrypted_text) and decrypted_text[i] != 'X'):
                final_text.append(decrypted_text[i])
                i += 2

            else:
                final_text.append(decrypted_text[i])
                final_text.append(decrypted_text[i+1])
                i += 2
        else:
            final_text.append(decrypted_text[i])
            i += 1

    if final_text and final_text[-1] == 'X':
        final_text.pop()

    return "".join(final_text)
            