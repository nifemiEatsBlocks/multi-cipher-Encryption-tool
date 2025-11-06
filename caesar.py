letters = "abcdefghijklmnopqrstuvwxyz"


def caesar(key, text, mode):
    result= ""
    if mode == 'decrypt':
        key = -key
    elif mode == 'encrypt':
        key = key
    for letter in text :
        letter = letter.lower()
        if not letter == " ":
            index = letters.find(letter)
            if index == -1:
                result += letter
            else:
                new_index = index + key
                if new_index < 0 :
                    new_index += 26
                elif new_index >= 26:
                    new_index -= 26
                result += letters[new_index]
        else:
            result += letter
    return result


