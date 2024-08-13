import os
import base64
import json
import logging
from datetime import datetime
from typing import Any, Dict
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


class HelperError(Exception):
    """Custom exception for helper functions errors."""
    pass


def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographic salt.

    :param length: Length of the salt in bytes.
    :return: Generated salt.
    """
    return os.urandom(length)


def generate_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Generate a cryptographic key from a password and salt using PBKDF2.

    :param password: Password to derive the key from.
    :param salt: Cryptographic salt.
    :param length: Length of the key in bytes.
    :return: Generated key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES encryption.

    :param data: Data to be encrypted.
    :param key: Encryption key.
    :return: Encrypted data.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()


def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES encryption.

    :param encrypted_data: Data to be decrypted.
    :param key: Encryption key.
    :return: Decrypted data.
    """
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data[16:]) + decryptor.finalize()


def save_to_file(data: bytes, filename: str):
    """
    Save data to a file.

    :param data: Data to be saved.
    :param filename: Filename to save the data to.
    """
    with open(filename, 'wb') as file:
        file.write(data)


def load_from_file(filename: str) -> bytes:
    """
    Load data from a file.

    :param filename: Filename to load the data from.
    :return: Loaded data.
    """
    if not os.path.exists(filename):
        raise HelperError(f"File {filename} not found.")

    with open(filename, 'rb') as file:
        return file.read()


def setup_logger(name: str, log_file: str, level: int = logging.INFO) -> logging.Logger:
    """
    Set up a logger with the specified name and log file.

    :param name: Name of the logger.
    :param log_file: Path to the log file.
    :param level: Logging level.
    :return: Configured logger.
    """
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


# Example usage
if __name__ == "__main__":
    password = "secure_password"
    salt = generate_salt()
    key = generate_key(password, salt)

    data = b"Sensitive data that needs encryption"
    encrypted_data = encrypt_data(data, key)
    save_to_file(encrypted_data, "data.enc")

    loaded_encrypted_data = load_from_file("data.enc")
    decrypted_data = decrypt_data(loaded_encrypted_data, key)

    assert data == decrypted_data, "Decryption failed!"
    print(f"Decrypted data: {decrypted_data}")
