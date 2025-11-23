import math

def columnar_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ","").upper()
    key=key.upper()

    num_cols = len(key)
    num_rows = math.ceil(len(plaintext) / num_cols)
    padded_text = plaintext.ljust(num_rows * num_cols, 'X')

    grid = []
    for i in range(num_rows):
        row = padded_text[i * num_cols : (i + 1) * num_cols]
        grid.append(list(row))

    key_order = sorted([(char, i) for i, char in enumerate(key)])
    ciphertext = ""
    for char, col_index in key_order:
        for row_index in range (num_rows):
            ciphertext += grid[row_index][col_index]
    return ciphertext

def columnar_decrypt(ciphertext, key):
    ciphertext = ciphertext.replace(" ","").upper()
    key = key.upper()

    num_cols = len(key)
    num_rows = math.ceil(len(ciphertext) / num_cols)

    key_order = sorted([(char, i ) for i, char in enumerate(key)])

    num_shadow_cells = (num_rows * num_cols) - len (ciphertext)

    grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]

    shadow_col_indices = [index for char, index in sorted(key_order, reverse = True)]

    for i in range(num_shadow_cells):
        col_index = shadow_col_indices[i]
        grid[num_rows - 1][col_index] = None

    text_index = 0
    for char, col_index in key_order:
        for row_index in range(num_rows):
            if grid[row_index][col_index] is not None:
                grid[row_index][col_index] = ciphertext[text_index]
                text_index += 1

    plaintext = ""
    for row in grid:
        for char in row:
            if char is not None:
                plaintext += char

    return plaintext

