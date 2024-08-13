# otp.py

import os
import random
import hashlib
import hmac
import base64
import time
from typing import Dict

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class OTPError(Exception):
    """Custom exception for OTP-related errors."""
    pass


class OTP:
    """
    Handles one-time password (OTP) generation and verification with encryption.
    """

    def __init__(self, length=6, encryption_password: str = None):
        self.length = length
        self.otp_data: Dict[str, str] = {}
        self.key = self.generate_key(encryption_password)
        self.cipher = self.create_cipher(self.key)

    def generate_key(self, password: str) -> bytes:
        """Generate a cryptographic key for encrypting OTPs."""
        if not password:
            password = base64.urlsafe_b64encode(os.urandom(16)).decode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def create_cipher(self, key: bytes):
        """Create a cipher object using the provided key."""
        return Fernet(key)

    def encrypt_otp(self, otp: str) -> str:
        """Encrypt the OTP."""
        return self.cipher.encrypt(otp.encode()).decode()

    def decrypt_otp(self, encrypted_otp: str) -> str:
        """Decrypt the OTP."""
        return self.cipher.decrypt(encrypted_otp.encode()).decode()

    def generate_otp(self, user_id: str) -> str:
        """Generate a one-time password for a user."""
        otp = ''.join([str(random.randint(0, 9)) for _ in range(self.length)])
        encrypted_otp = self.encrypt_otp(otp)
        self.otp_data[user_id] = encrypted_otp
        return otp

    def verify_otp(self, user_id: str, otp: str) -> bool:
        """Verify the provided OTP for the given user ID."""
        if user_id in self.otp_data:
            encrypted_otp = self.otp_data[user_id]
            decrypted_otp = self.decrypt_otp(encrypted_otp)
            if decrypted_otp == otp:
                del self.otp_data[user_id]
                return True
        return False

    def get_data(self) -> Dict[str, str]:
        """Get OTP data."""
        return self.otp_data

    def set_data(self, data: Dict[str, str]):
        """Set OTP data."""
        self.otp_data = data


# Example usage
if __name__ == "__main__":
    otp_manager = OTP(encryption_password="secure_password")

    user_id = "user123"

    # Generate OTP
    generated_otp = otp_manager.generate_otp(user_id)
    print(f"Generated OTP: {generated_otp}")

    # Simulate user input for verification
    user_input_otp = input("Enter the OTP you received: ")
    if otp_manager.verify_otp(user_id, user_input_otp):
        print("OTP verified successfully!")
    else:
        print("Invalid OTP.")
