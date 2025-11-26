
import random

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n ** 0.5) + 1):
        if n% i == 0: return False
    return True

def generate_rsa_keys(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    
    n = p*q
    phi = (p -1) * (q-1)

    e = random.randrange(1, phi)

    g = 0
    while g != 1:
        e = random.randrange(1,phi)
        a, b = e, phi
        while b:
            a, b=b, a % b
        g =a

    d =mod_inverse(e, phi)

    return((e,n), (d, n))

def rsa_encrypt(message, public_key):
    e, n  = public_key
    encrypted = [pow(ord(char), e, n) for char in message]
    return encrypted

def rsa_decrypt(encrypted_list, private_key):
    d, n = private_key
    decrypted = [chr(pow(char,d ,n)) for char in encrypted_list]
    return ''.join(decrypted)


p=61
q = 53

