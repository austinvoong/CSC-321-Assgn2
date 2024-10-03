from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
import os

# Task 1


def get_plaintext_file():
    # Prompt the user to enter the name of the plaintext file
    while True:
        plaintext_file = input("Enter the name of the plaintext file: ")
        if os.path.isfile(plaintext_file):
            return plaintext_file
        else:
            print("File does not exist.")


def ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        # Encrypt each 16-byte block separately
        encrypted_block = cipher.encrypt(plaintext[i:i+16])
        ciphertext += encrypted_block
    return ciphertext


def main():
    filename = get_plaintext_file()
    with open(filename, 'rb') as file:
        plaintext = file.read()

    print(plaintext)


if __name__ == "__main__":
    main()
