from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Import klassen en modules die nodig zijn voor AES-256 encryptie en decryptie
from cryptography.hazmat.backends import default_backend # Importeer de standaard backend van de cryptography module
from cryptography.hazmat.primitives import padding # Importeer de padding module van de cryptography module
import os


def encrypt_aes_256(plain_text, key): 
    backend = default_backend() # Environment set up waar de encryptie plaatsvindt
    iv = os.urandom(16)  # Gen random 128-bit IV -> random waarde die ervoor zorgt dat er niet 2x dezelfde ciphertext wordt gegenereerd, nodig voor decryptie
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend) # Creeer een AES-256 cipher object met CBC mode
    encryptor = cipher.encryptor() # Creeer een encryptor object

    # Pad de data, padding is nodig omdat block cipher input data moet zijn van een bepaalde grootte
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Encrypt de data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def decrypt_aes_256(encrypted_data, key):
    backend = default_backend() # Environment set up waar de decryptie plaatsvindt
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
