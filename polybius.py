def polybius_encrypt(text):
    text = text.upper().replace('J', 'I')
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'

    ciphertext = ''

    for char in text:
        if char in alphabet:
            index = alphabet.index(char)

            row = (index // 5) + 1
            col = (index % 5) + 1
            ciphertext += f"{row}{col} "
    return ciphertext.strip()

def polybius_decrypt(ciphertext):
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    numbers = ciphertext.replace(" ", "")

    plaintext = ""
    for i in range(0, len(numbers), 2):
        try:
            row = int(numbers[i])
            col = int(numbers[i + 1])

            index = (row - 1) *5 + (col - 1)

            plaintext += alphabet[index]
        except (ValueError, IndexError):
            pass
    return plaintext


