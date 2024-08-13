import unittest
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from Config.encryption_settings import EncryptionSettings
from Src.Encryption.key_management import KeyManager
from Src.Encryption.layers import LayeredEncryption


class TestEncryption(unittest.TestCase):

    def setUp(self):
        # Setup KeyManager, LayeredEncryption, and EncryptionSettings for tests
        self.key_manager = KeyManager()
        self.encryption_settings = EncryptionSettings()
        self.layered_encryption = LayeredEncryption(self.key_manager)
        self.password = "secure_password"
        self.salt = os.urandom(16)
        self.key = self.generate_key(self.password, self.salt)
        self.data = b"Sensitive data that needs encryption"

    def generate_key(self, password: str, salt: bytes) -> bytes:
        """Generate a cryptographic key using the specified KDF parameters."""
        kdf_params = self.encryption_settings.get_kdf_params()
        algorithm = getattr(hashes, kdf_params["algorithm"])()
        kdf = PBKDF2HMAC(
            algorithm=algorithm,
            length=kdf_params["length"],
            salt=salt,
            iterations=kdf_params["iterations"],
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def test_key_generation(self):
        """Test key generation using the encryption settings."""
        key = self.generate_key(self.password, self.salt)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(base64.urlsafe_b64decode(key)), self.encryption_settings.get_kdf_params()["length"])

    def test_encryption_decryption(self):
        """Test encryption and decryption of data."""
        encrypted_data = self.layered_encryption.encrypt(self.data)
        decrypted_data = self.layered_encryption.decrypt(encrypted_data)
        self.assertEqual(self.data, decrypted_data)

    def test_encryption_settings_loading(self):
        """Test loading of encryption settings."""
        kdf_params = self.encryption_settings.get_kdf_params()
        self.assertIn("algorithm", kdf_params)
        self.assertIn("length", kdf_params)
        self.assertIn("salt_length", kdf_params)
        self.assertIn("iterations", kdf_params)

    def test_encryption_settings_saving(self):
        """Test saving of encryption settings."""
        new_kdf_params = {
            "algorithm": "SHA512",
            "length": 64,
            "salt_length": 32,
            "iterations": 200000
        }
        self.encryption_settings.set_kdf_params(new_kdf_params)
        saved_params = self.encryption_settings.get_kdf_params()
        self.assertEqual(saved_params, new_kdf_params)

    def test_rotation_policy(self):
        """Test setting and getting rotation policy."""
        new_rotation_policy = {
            "interval": 7200,  # 2 hours
            "immediate_rotation_on_threat": False
        }
        self.encryption_settings.set_rotation_policy(new_rotation_policy)
        rotation_policy = self.encryption_settings.get_rotation_policy()
        self.assertEqual(rotation_policy, new_rotation_policy)


if __name__ == "__main__":
    unittest.main()
