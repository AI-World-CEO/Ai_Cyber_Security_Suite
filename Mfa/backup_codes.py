# backup_codes.py

import os
import random
import string
from typing import Dict, List
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class BackupCodesError(Exception):
    """Custom exception for Backup Codes-related errors."""
    pass


class BackupCodes:
    """
    Manages backup codes for MFA with encryption.
    """

    def __init__(self, code_length=8, num_codes=10, encryption_password: str = None):
        self.code_length = code_length
        self.num_codes = num_codes
        self.backup_codes: Dict[str, List[str]] = {}
        self.key = self.generate_key(encryption_password)
        self.cipher = Fernet(self.key)

    def generate_key(self, password: str) -> bytes:
        """Generate a cryptographic key for encrypting backup codes."""
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

    def encrypt_code(self, code: str) -> str:
        """Encrypt the backup code."""
        return self.cipher.encrypt(code.encode()).decode()

    def decrypt_code(self, encrypted_code: str) -> str:
        """Decrypt the backup code."""
        return self.cipher.decrypt(encrypted_code.encode()).decode()

    def generate_backup_codes(self, user_id: str) -> List[str]:
        """Generate backup codes for a user."""
        codes = [''.join(random.choices(string.ascii_uppercase + string.digits, k=self.code_length)) for _ in
                 range(self.num_codes)]
        encrypted_codes = [self.encrypt_code(code) for code in codes]
        self.backup_codes[user_id] = encrypted_codes
        return codes

    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Verify the provided backup code for the given user ID."""
        if user_id in self.backup_codes:
            encrypted_codes = self.backup_codes[user_id]
            decrypted_codes = [self.decrypt_code(enc_code) for enc_code in encrypted_codes]
            if code in decrypted_codes:
                encrypted_codes.remove(self.encrypt_code(code))
                self.backup_codes[user_id] = encrypted_codes
                return True
        return False

    def get_data(self) -> Dict[str, List[str]]:
        """Get backup codes data."""
        return self.backup_codes

    def set_data(self, data: Dict[str, List[str]]):
        """Set backup codes data."""
        self.backup_codes = data


# Example usage
if __name__ == "__main__":
    backup_codes_manager = BackupCodes(encryption_password="secure_password")

    user_id = "user123"

    # Generate backup codes
    generated_codes = backup_codes_manager.generate_backup_codes(user_id)
    print(f"Generated backup codes: {generated_codes}")

    # Simulate user input for verification
    user_input_code = input("Enter a backup code you received: ")
    if backup_codes_manager.verify_backup_code(user_id, user_input_code):
        print("Backup code verified successfully!")
    else:
        print("Invalid backup code.")
