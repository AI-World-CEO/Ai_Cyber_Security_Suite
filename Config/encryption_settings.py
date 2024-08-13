import os
import json
import base64
from typing import Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class EncryptionSettingsError(Exception):
    """Custom exception for encryption settings-related errors."""

    def __init__(self, message: str):
        super().__init__(message)


class EncryptionSettings:
    """
    Class to manage encryption settings, including key generation parameters,
    encryption algorithms, and key rotation policies.
    """

    def __init__(self, config_file: str = "config/encryption_settings.json"):
        self.config_file = config_file
        self.settings = self.load_settings()

    def load_settings(self) -> Dict:
        """Load encryption settings from a configuration file."""
        if not os.path.exists(self.config_file):
            raise EncryptionSettingsError(f"Configuration file {self.config_file} not found.")

        with open(self.config_file, 'r') as file:
            return json.load(file)

    def save_settings(self):
        """Save encryption settings to a configuration file."""
        with open(self.config_file, 'w') as file:
            json.dump(self.settings, file, indent=4)

    def get_kdf_params(self) -> Dict:
        """Get key derivation function parameters."""
        return self.settings.get("kdf_params", {
            "algorithm": "SHA256",
            "length": 32,
            "salt_length": 16,
            "iterations": 100000
        })

    def set_kdf_params(self, params: Dict):
        """Set key derivation function parameters."""
        self.settings["kdf_params"] = params
        self.save_settings()

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
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def get_encryption_algorithm(self) -> str:
        """Get the encryption algorithm."""
        return self.settings.get("encryption_algorithm", "AES")

    def set_encryption_algorithm(self, algorithm: str):
        """Set the encryption algorithm."""
        self.settings["encryption_algorithm"] = algorithm
        self.save_settings()

    def get_rotation_policy(self) -> Dict:
        """Get the key rotation policy."""
        return self.settings.get("rotation_policy", {
            "interval": 3600,  # Default to 1 hour
            "immediate_rotation_on_threat": True
        })

    def set_rotation_policy(self, policy: Dict):
        """Set the key rotation policy."""
        self.settings["rotation_policy"] = policy
        self.save_settings()

    def get_salt_length(self) -> int:
        """Get the length of the salt."""
        return self.get_kdf_params().get("salt_length", 16)

    def generate_salt(self) -> bytes:
        """Generate a cryptographic salt."""
        return os.urandom(self.get_salt_length())


# Example usage
if __name__ == "__main__":
    encryption_settings = EncryptionSettings()

    # Print current KDF parameters
    print("Current KDF Parameters:", encryption_settings.get_kdf_params())

    # Update KDF parameters
    new_kdf_params = {
        "algorithm": "SHA256",
        "length": 32,
        "salt_length": 16,
        "iterations": 200000
    }
    encryption_settings.set_kdf_params(new_kdf_params)
    print("Updated KDF Parameters:", encryption_settings.get_kdf_params())

    # Generate a key using the new KDF parameters
    test_password = "secure_password"
    test_salt = encryption_settings.generate_salt()
    generated_key = encryption_settings.generate_key(test_password, test_salt)
    print("Generated Key:", generated_key)

    # Print current encryption algorithm
    print("Current Encryption Algorithm:", encryption_settings.get_encryption_algorithm())

    # Update encryption algorithm
    encryption_settings.set_encryption_algorithm("AES256")
    print("Updated Encryption Algorithm:", encryption_settings.get_encryption_algorithm())

    # Print current rotation policy
    print("Current Rotation Policy:", encryption_settings.get_rotation_policy())

    # Update rotation policy
    new_rotation_policy = {
        "interval": 7200,  # 2 hours
        "immediate_rotation_on_threat": False
    }
    encryption_settings.set_rotation_policy(new_rotation_policy)
    print("Updated Rotation Policy:", encryption_settings.get_rotation_policy())
