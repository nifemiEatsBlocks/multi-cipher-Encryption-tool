def xor_encrypt(text, key):
    if not key: return "Error: Key cannot be empty"
    
    result = []
    for i, char in enumerate(text):
        key_char = key[i % len(key)]
        xor_val = ord(char) ^ ord(key_char)
        result.append(f"{xor_val:02x}")
        
    return "".join(result)

def xor_decrypt(hex_text, key):
    if not key: return "Error: Key cannot be empty"
    
    try:
        raw_bytes = bytes.fromhex(hex_text)
        
        result = []
        for i, byte_val in enumerate(raw_bytes):
            key_char = key[i % len(key)]
            original_char = chr(byte_val ^ ord(key_char))
            result.append(original_char)
            
        return "".join(result)
        
    except ValueError:
        return "Error: Input must be a valid Hex string (e.g., '1a2b3c')"