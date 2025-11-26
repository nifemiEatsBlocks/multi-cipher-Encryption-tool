MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '1': '.----',  '2': '..---', '3': '...--', '4': '....-', '5': '.....',
    '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----',
    ',': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.', '-': '-....-',
    '(': '-.--.', ')': '-.--.-'
}

REVERSE_DICT = {value: key for key, value in MORSE_CODE_DICT.items()}

def encrypt(text):
    text = text.upper()
    cipher = ''
    for letter in text:
        if letter != ' ':
            cipher += MORSE_CODE_DICT.get(letter, letter) + ' '
        else:
            cipher += '/'

    return cipher.strip()

def decrypt(text):
    text += ' '
    decipher = ''
    citext = ''

    for letter in text:
        if letter != ' ':
            i = 0
            citext += letter
        else:
            i += 1
            if i == 2:
                decipher += ' '
            else:
                if citext == '/':
                    decipher += ' '
                else:
                    decipher += REVERSE_DICT.get(citext, '')
                    citext = ''
    return decipher.strip()
            

