def atbash_cipher(text):
    result = ''
    for char in text:
        if char.isalpha():
            if char.isupper():
                flipped = chr(90 - (ord(char) - 65))
                result += flipped
            else:
                flipped = chr(122 - (ord(char) -97))
                result += flipped

        else:
            result += char 
    return result


