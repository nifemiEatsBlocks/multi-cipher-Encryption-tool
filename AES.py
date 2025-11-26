from cryptography.fernet import Fernet

def generate_aes_key():

    return Fernet.generate_key()

def aes_encrypt(text, key):
    f = Fernet(key)
    token =f.encrypt(text.encode('utf-8'))
    return token.decode('utf-8')

def aes_decrypt(token, key):
    f = Fernet(key)
    try:
        plaintext = f.decrypt(token.encode('utf-8'))
        return plaintext.decode('utf-8')
    except Exception:
        return "Error: Invalid key or corrupted Data"
    
    