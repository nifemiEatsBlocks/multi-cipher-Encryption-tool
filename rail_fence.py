
def cipher_encryption(text, rails):
    if rails == 1:
        print("Encrypted Text : ({})".format(text.replace(" ","")))
        return

    msg = text.replace(" ","")
    
    railMatrix = [['.' for _ in range(len(msg))] for _ in range(rails)]

    row = 0
    direction = 1

    for i in range(len(msg)):
        
        railMatrix[row][i] = msg[i]
        
        
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
            
        
        row += direction

    
    encrypt_text = ''
    for r in range(rails):
        encrypt_text += "".join(railMatrix[r])
    
    
    encrypt_text = encrypt_text.replace(".", "")

    print("Encrypted Text : ({})".format(encrypt_text))


def cipher_decryption(text, rails):
    if rails == 1:
        print("decryptrd text:({})".format(text))
        return
    msg_len = len(text)

    railMatrix = [['.' for _ in range(msg_len)] for _ in range(rails)]

    row = 0
    direction = 1

    for i in range(msg_len):
        railMatrix[row][i] = '*'

        if row == 0:
            direction = 1
        elif row == rails -1:
            direction = -1

        row += direction 

    text_index = 0
    for r in range(rails):
        for c in range(msg_len):
            if railMatrix[r][c] == '*' and text_index < msg_len:
                railMatrix[r][c] = text[text_index]
                text_index += 1
    decrypted_text = ''
    row = 0
    direction = 1

    for i in range(msg_len):
        decrypted_text += railMatrix[row][i]

        if row == 0:
            direction = 1
        elif row == rails -1:
            direction =-1

        row += direction
    print("Decrypted text: ({})".format(decrypted_text))


print("--- Encryption ---")
# Using the corrected encryption function from before
cipher_encryption("HELLO WORLD", 3)
cipher_encryption("blah blah blah", 2)

print("\n--- Decryption ---")
# Decrypting the outputs
cipher_decryption("HOLELWRDLO", 3)
cipher_decryption("bababalhlhlh", 2)