from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# Task 1
def ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(data), 16):
        # Encrypt each 16-byte block separately
        encrypted_block = cipher.encrypt(data[i:i+16])
        ciphertext += encrypted_block
    return ciphertext

def cbc_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = b""
    for i in range(0, len(data), 16):
        # Encrypt each 16-byte block separately
        encrypted_block = cipher.encrypt(data[i:i+16])
        ciphertext += encrypted_block
    return ciphertext

def pkcs_padding(data, block_size): # pkcs_padding
    padding_size = block_size - len(data) % block_size
    padding = bytes([padding_size]) * padding_size
    return data + padding

def generate_key_iv():
    key = get_random_bytes(16)  # Generate a random 16-byte key
    iv = get_random_bytes(16)  # Generate a random 16-byte initialization vector
    return key, iv

def main():
    # Open the BMP file and read the header and plaintext
    header_size = 54 # Change to 138 if using mac
    text_file = "cp_mustang.bmp"
    with open(text_file, "rb") as file:
        header = file.read(header_size)
        plaintext = file.read()

    # Add padding to the plaintext
    plaintext = pkcs_padding(plaintext, 16)

    # Generate a random key and initialization vector
    key, iv = generate_key_iv()

    # Encrypt the plaintext using ECB mode
    encrypted_ecb = ecb_encrypt(plaintext, key)

    # Encrypt the plaintext using CBC mode
    encrypted_cbc = cbc_encrypt(plaintext, key, iv)

    # Save the encrypted ciphertexts to separate files
    with open("ecb_ciphertext.bmp", "wb") as file:
        file.write(header)
        file.write(encrypted_ecb)

    with open("cbc_ciphertext.bmp", "wb") as file:
        file.write(header)
        file.write(encrypted_cbc)


if __name__ == "__main__":
    main()
