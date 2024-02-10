from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


def encrypt_aes_256(plain_text, key):
    backend = default_backend()
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Pad the data before encryption
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def decrypt_aes_256(encrypted_data, key):
    backend = default_backend()
    iv = encrypted_data[:16]  # Extract the IV from the encrypted data
    ciphertext = encrypted_data[16:]  # Extract the ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode()


def main():
    print("Welcome to the AES-256 Encryption/Decryption tool!\n")
    while True:
        print("1. Encrypt Last Name")
        print("2. Decrypt Last Name")
        print("3. Exit")
        choice = input("Please enter your choice: ")

        if choice == "1":
            last_name = input("Enter your last name to encrypt: ")
            key = os.urandom(32)  # Generate a random 256-bit key
            encrypted_last_name = encrypt_aes_256(last_name, key)
            print("Encrypted Last Name:", encrypted_last_name.hex())
            print("Encryption Key:", key.hex())
        elif choice == "2":
            encrypted_last_name = bytes.fromhex(
                input("Enter the encrypted last name: "))
            key = bytes.fromhex(input("Enter the encryption key: "))
            decrypted_last_name = decrypt_aes_256(encrypted_last_name, key)
            print("Decrypted Last Name:", decrypted_last_name)
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
