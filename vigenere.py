letters = "abcdefghijklmnopqrstuvwxyz"


def vigenere (key, text, mode):
    result = ''
    key = key.lower()
    key_index = 0 

    for letter in text.lower():
        if letter in letters:
            text_index = letters.find(letter)
            shift = letters.find(key[key_index % len(key)])


            if mode == 'encrypt':
                new_index = (text_index + shift) % 26
            else:
                new_index = (text_index - shift + 26) % 26
                
            result += letters[new_index]
            key_index += 1 
        else:
            result += letter

    return result
