import os
import base64
import json
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Dict

from Src.Utils.logger import setup_logger

# Initialize the logger
logger = setup_logger("key_generator_logger")


class KeyGenerator:
    """
    Class to generate cryptographic keys using PBKDF2.
    """

    def __init__(self, config_file: str = "config/encryption_settings.json"):
        self.config_file = config_file
        self.settings = self.load_settings()

    def load_settings(self) -> Dict:
        """Load encryption settings from a configuration file."""
        if not os.path.exists(self.config_file):
            logger.error(f"Configuration file {self.config_file} not found.")
            raise FileNotFoundError(f"Configuration file {self.config_file} not found.")

        with open(self.config_file, 'r') as file:
            settings = json.load(file)
            logger.info(f"Settings loaded from {self.config_file}.")
            return settings

    def get_kdf_params(self) -> Dict:
        """Get key derivation function parameters."""
        kdf_params = self.settings.get("kdf_params", {
            "algorithm": "SHA256",
            "length": 32,
            "salt_length": 16,
            "iterations": 100000
        })
        logger.debug(f"KDF parameters: {kdf_params}")
        return kdf_params

    def generate_salt(self) -> bytes:
        """Generate a cryptographic salt."""
        salt_length = self.get_kdf_params().get("salt_length", 16)
        salt = os.urandom(salt_length)
        logger.debug(f"Generated salt: {base64.urlsafe_b64encode(salt).decode('utf-8')}")
        return salt

    def generate_key(self, password: str, salt: bytes) -> bytes:
        """Generate a cryptographic key using the specified KDF parameters."""
        kdf_params = self.get_kdf_params()
        algorithm = getattr(hashes, kdf_params["algorithm"])()
        kdf = PBKDF2HMAC(
            algorithm=algorithm,
            length=kdf_params["length"],
            salt=salt,
            iterations=kdf_params["iterations"],
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        logger.debug(f"Generated key: {key.decode('utf-8')}")
        return key

    def save_key(self, key: bytes, key_file: str = "key.key"):
        """Save the generated key to a file."""
        with open(key_file, 'wb') as file:
            file.write(key)
        logger.info(f"Key saved to {key_file}.")

    def generate_and_save_key(self, password: str, key_file: str = "key.key"):
        """Generate a cryptographic key and save it to a file."""
        salt = self.generate_salt()
        key = self.generate_key(password, salt)
        self.save_key(key, key_file)
        logger.info(f"Generated and saved key with password: {password}")


def main():
    key_generator = KeyGenerator()
    password = input("Enter a password for key generation: ")
    key_file = "key.key"
    key_generator.generate_and_save_key(password, key_file)


if __name__ == "__main__":
    main()
