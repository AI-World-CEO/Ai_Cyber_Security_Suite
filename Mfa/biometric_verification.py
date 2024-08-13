import base64
import hashlib
import json
import os
from typing import Dict, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class BiometricAuthenticationError(Exception):
    """Custom exception for biometric authentication errors."""
    pass


class BiometricAuthentication:
    """
    Biometric Authentication: Handles biometric data storage, verification, and encryption.
    """

    def __init__(self, key_length=32):
        self.key_length = key_length
        self.biometric_data: Dict[str, Any] = {}  # Stores biometric data with encryption keys
        self.master_key = self.generate_key()

    def generate_key(self) -> bytes:
        """Generate a master cryptographic key."""
        password = base64.urlsafe_b64encode(os.urandom(16))
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password))

    def encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt biometric data with the provided key."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt biometric data with the provided key."""
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    def add_biometric_data(self, user_id: str, biometric_data: bytes):
        """
        Add and encrypt biometric data for a user.
        """
        key = self.generate_key()
        encrypted_data = self.encrypt_data(biometric_data, key)
        self.biometric_data[user_id] = {
            "key": base64.urlsafe_b64encode(key).decode(),
            "data": base64.urlsafe_b64encode(encrypted_data).decode()
        }

    def verify_biometric_data(self, user_id: str, biometric_data: bytes) -> bool:
        """
        Verify the provided biometric data for the given user ID.
        """
        if user_id not in self.biometric_data:
            raise BiometricAuthenticationError("User ID not found.")

        stored_data = self.biometric_data[user_id]
        key = base64.urlsafe_b64decode(stored_data["key"])
        encrypted_data = base64.urlsafe_b64decode(stored_data["data"])

        decrypted_data = self.decrypt_data(encrypted_data, key)

        # In real-world use, proper biometric comparison should be implemented here.
        return hashlib.sha256(decrypted_data).digest() == hashlib.sha256(biometric_data).digest()

    def save_biometric_data(self, filename: str):
        """Save biometric data to a file."""
        with open(filename, 'w') as f:
            json.dump(self.biometric_data, f)

    def load_biometric_data(self, filename: str):
        """Load biometric data from a file."""
        with open(filename, 'r') as f:
            self.biometric_data = json.load(f)


# Example usage
if __name__ == "__main__":
    biometric_auth = BiometricAuthentication()

    # Example biometric data (in reality, this would be complex biometric data like fingerprints, etc.)
    example_biometric_data = b"example_biometric_data_for_user_1"
    user_id = "user_1"

    # Add and encrypt biometric data
    biometric_auth.add_biometric_data(user_id, example_biometric_data)
    print(f"Biometric data added for {user_id}")

    # Verify biometric data
    if biometric_auth.verify_biometric_data(user_id, example_biometric_data):
        print("Biometric data verified successfully!")
    else:
        print("Biometric data verification failed.")

    # Save biometric data to file
    biometric_auth.save_biometric_data("biometric_data.json")
    print("Biometric data saved to file.")

    # Load biometric data from file
    biometric_auth.load_biometric_data("biometric_data.json")
    print("Biometric data loaded from file.")
