from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class AESCipher:
    def __init__(self, password):
        self.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)

    def encrypt_text(self, plaintext):
        encrypted_data = self.cipher_suite.encrypt(plaintext.encode())
        return self.salt + encrypted_data

    def decrypt_text(self, ciphertext):
        salt = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(actual_ciphertext)
        return decrypted_data.decode()

    def encrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = self.cipher_suite.encrypt(file_data)
        with open(output_file_path, 'wb') as file:
            file.write(self.salt + encrypted_data)

    def decrypt_file(self, input_file_path, output_file_path):
        with open(input_file_path, 'rb') as file:
            file_data = file.read()
        salt = file_data[:16]
        actual_ciphertext = file_data[16:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(actual_ciphertext)
        with open(output_file_path, 'wb') as file:
            file.write(decrypted_data)