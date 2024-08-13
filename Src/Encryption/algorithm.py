import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


class EncryptionError(Exception):
    """Custom exception for encryption errors."""
    pass


class KeyManager:
    """Manage encryption keys."""

    def __init__(self, key_length=32):
        self.key_length = key_length

    def generate_key(self, password: str, salt: bytes) -> bytes:
        """Generate a key from a password and a salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))


class LayeredEncryption:
    """Class for managing layered encryption."""

    def __init__(self, key_manager: KeyManager, num_layers=3):
        self.key_manager = key_manager
        self.num_layers = num_layers
        self.layers = [self._create_layer() for _ in range(self.num_layers)]

    def _create_layer(self):
        password = base64.urlsafe_b64encode(os.urandom(16)).decode()
        salt = os.urandom(16)
        key = self.key_manager.generate_key(password, salt)
        iv = os.urandom(16)
        return {"password": password, "salt": salt, "key": key, "iv": iv}

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with multiple layers."""
        encrypted_data = data
        for layer in self.layers:
            cipher = Cipher(algorithms.AES(layer["key"]), modes.CFB(layer["iv"]), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(encrypted_data) + encryptor.finalize()
        return encrypted_data

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data with multiple layers."""
        decrypted_data = data
        for layer in reversed(self.layers):
            cipher = Cipher(algorithms.AES(layer["key"]), modes.CFB(layer["iv"]), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(decrypted_data) + decryptor.finalize()
        return decrypted_data

    def rotate_keys(self):
        """Rotate keys for all layers."""
        self.layers = [self._create_layer() for _ in range(self.num_layers)]


class ThreatDetection:
    """Simulate a threat detection system."""

    def __init__(self, encryption_system: LayeredEncryption):
        self.encryption_system = encryption_system

    def detect_threat(self):
        """Simulate threat detection and key rotation."""
        # Simulating threat detection logic
        threat_detected = True
        if threat_detected:
            self.encryption_system.rotate_keys()
            print("Threat detected! Keys rotated.")


# Example usage
if __name__ == "__main__":
    key_manager_instance = KeyManager()
    layered_encryption_instance = LayeredEncryption(key_manager_instance)
    threat_detection_instance = ThreatDetection(layered_encryption_instance)

    data_to_encrypt = b"Sensitive data that needs encryption"
    encrypted_data_example = layered_encryption_instance.encrypt(data_to_encrypt)
    print(f"Encrypted data: {encrypted_data_example}")

    decrypted_data_example = layered_encryption_instance.decrypt(encrypted_data_example)
    print(f"Decrypted data: {decrypted_data_example}")

    # Simulate threat detection
    threat_detection_instance.detect_threat()

    # Re-encrypt data with new keys
    re_encrypted_data_example = layered_encryption_instance.encrypt(data_to_encrypt)
    print(f"Re-encrypted data: {re_encrypted_data_example}")

    re_decrypted_data_example = layered_encryption_instance.decrypt(re_encrypted_data_example)
    print(f"Re-decrypted data: {re_decrypted_data_example}")
