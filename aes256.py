# Import klassen en modules die nodig zijn voor AES-256 encryptie en decryptie
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# Importeer de standaard backend van de cryptography module
from cryptography.hazmat.backends import default_backend
# Importeer de padding module van de cryptography module
from cryptography.hazmat.primitives import padding
import os
import base64


def encrypt_aes_256(plain_text, key):
    backend = default_backend()  # Environment set up waar de encryptie plaatsvindt
    # Gen random 128-bit IV -> random waarde die ervoor zorgt dat er niet 2x dezelfde ciphertext wordt gegenereerd, nodig voor decryptie
    iv = os.urandom(16)
    # Creeer een AES-256 cipher object met CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()  # Creeer een encryptor object

    # Pad de data, padding is nodig omdat block cipher input data moet zijn van een bepaalde grootte
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Encrypt de data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def decrypt_aes_256(encrypted_data, key):
    backend = default_backend()  # Environment set up waar de decryptie plaatsvindt
    # IV extracten, de IV is de eerste 16 bytes, dus ik slice de eerste 16 bytes
    iv = encrypted_data[:16]
    # Ciphertext extracten, de rest van de bytes is de ciphertext
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(
        iv), backend=backend)  # Maak ciphet object
    decryptor = cipher.decryptor()  # Maak decryptor object

    # Decyption, update wordt aangeroepen op de decryptor met de ciphertext als argument, dan de finalize methode om te zorgen dat het wordt afgesloten
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Padding verwijderen
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode()


def main():
    # Main functie om encryptie en decryptie testen
    print("Welcome to the AES-256 Encryption/Decryption tool!\n")
    while True:
        print("1. Encrypt string")
        print("2. Decrypt string")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            last_name = input("Enter your string to encrypt: ")
            key = os.urandom(32)  # Gen een random 256-bit key
            encrypted_last_name = encrypt_aes_256(last_name, key)
            print("Encrypted string:", encrypted_last_name.hex())
            print("Encryption Key:", key.hex())
            # print("Key length in bytes:", len(key))
            # print("Key length in hexadecimal characters:", len(key.hex()))
            # print(base64.b64encode(key).decode())
        elif choice == "2":
            encrypted_last_name = bytes.fromhex(
                input("Enter the encrypted string: "))  # Convert de hex string naar bytes voor de string
            # Convert de hex string naar bytes voor de key
            key = bytes.fromhex(input("Enter the encryption key: "))
            decrypted_last_name = decrypt_aes_256(encrypted_last_name, key)
            print("Decrypted string:", decrypted_last_name)
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
