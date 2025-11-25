from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def ecc_sign(message, private_key):
    signature = private_key.sign(
        message.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

def ecc_verify(message, signature_hex, public_key):
    try:
        signature = bytes.fromhex(signature_hex)
        public_key.verify(
            signature,
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())

        )
        return True
    except Exception:
        return False
    


