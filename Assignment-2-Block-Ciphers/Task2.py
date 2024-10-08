from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import urllib.parse # quote

def pkcs_padding(data, block_size): # pkcs_padding
    padding_size = block_size - len(data) % block_size
    padding = bytes([padding_size]) * padding_size
    return data + padding

def pkcs_unpadding(data): # pkcs_unpadding
    padding_size = data[-1]
    return data[:-padding_size]

key = get_random_bytes(16)  # Generate a random 16-byte key
iv = get_random_bytes(16)  # Generate a random 16-byte initialization vector


def submit(user_input, modified_iv):
    url_input = urllib.parse.quote(user_input) # URL-encode the user input
    data = f"userid=456;userdata={url_input};session-id=31337"

    padded_data = pkcs_padding(data.encode(), 16)  # Add padding to the data
    cipher = AES.new(key, AES.MODE_CBC, modified_iv)  # Create a new cipher object
    ciphertext = cipher.encrypt(padded_data)  # Encrypt the data using CBC mode
    return modified_iv, ciphertext  # Return the modified IV and the encrypted ciphertext

def verify(ciphertext, modified_iv):
    cipher = AES.new(key, AES.MODE_CBC, modified_iv)  # Create a new cipher object
    decrypted_data = cipher.decrypt(ciphertext)  # Decrypt the ciphertext using CBC mode
    
    try:
        unpadded_data = pkcs_unpadding(decrypted_data) #
        decrypted_data = unpadded_data.decode()  # Try to decode the decrypted data
        print("Decrypted data: ", decrypted_data)
    except UnicodeDecodeError as e:
        print("Decryption error: ", str(e))
        return False

    if ";admin=true;" in decrypted_data:  # Check if the decrypted data contains the admin flag
        return True
    else:
        return False
    
def tamper_ciphertext(ciphertext, iv):
    target_str = ";admin=true;" # The target we are looking for
    original_str = "@admin$true*" # The string we want to replace the target with
    target_bytes = target_str.encode() # The target string as bytes
    original_str_bytes = original_str.encode() # The original string as bytes

    tampered_iv = bytearray(iv) # Create a mutable bytearray of the IV

    for i in range(len(target_bytes)): # XOR each byte of the IV with the original and target strings
        tampered_iv[i] ^= original_str_bytes[i] ^ target_bytes[i]

    return bytes(tampered_iv), ciphertext # Return the tampered IV and the tampered ciphertext

#EXAMPLE USAGE
user_input = "You're the man now, dog"

iv, original_ciphertext = submit(user_input, iv)
print(f"Original cipher text: {original_ciphertext}")

tampered_iv, tampered_ciphertext = tamper_ciphertext(original_ciphertext, iv)

if verify(tampered_ciphertext, tampered_iv):
    print("Tampered ciphertext successful!")
else:
    print("Tampered ciphertext failed!")