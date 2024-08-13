import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import json
from typing import List


class LayerEncryptionError(Exception):
    """Custom exception for layer encryption errors."""
    pass


class Layer:
    """Class for managing a single encryption layer."""

    def __init__(self, password: str, salt: bytes, key_length=32):
        self.password = password
        self.salt = salt
        self.key_length = key_length
        self.key = self.generate_key(password, salt)
        self.iv = os.urandom(16)

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

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with the layer's key."""
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return self.iv + encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data with the layer's key."""
        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data[16:]) + decryptor.finalize()


class LayeredEncryption:
    """Class for managing multiple encryption layers."""

    def __init__(self, num_layers=3, key_length=32):
        self.num_layers = num_layers
        self.key_length = key_length
        self.layers = self.create_layers()

    def create_layers(self) -> List[Layer]:
        """Create multiple encryption layers."""
        layers = []
        for i in range(self.num_layers):
            password = base64.urlsafe_b64encode(os.urandom(16)).decode()
            salt = os.urandom(16)
            layer = Layer(password, salt, self.key_length)
            layers.append(layer)
        return layers

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data through all layers."""
        for layer in self.layers:
            data = layer.encrypt(data)
        return data

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data through all layers."""
        for layer in reversed(self.layers):
            data = layer.decrypt(data)
        return data

    def rotate_keys(self):
        """Rotate keys for all layers."""
        self.layers = self.create_layers()


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

    def analyze(self, data):
        pass


# Example usage
if __name__ == "__main__":
    layered_encryption = LayeredEncryption()
    threat_detection = ThreatDetection(layered_encryption)

    data = b"Sensitive data that needs encryption"
    encrypted_data = layered_encryption.encrypt(data)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = layered_encryption.decrypt(encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

    # Simulate threat detection
    threat_detection.detect_threat()

    # Re-encrypt data with new keys
    re_encrypted_data = layered_encryption.encrypt(data)
    print(f"Re-encrypted data: {re_encrypted_data}")

    re_decrypted_data = layered_encryption.decrypt(re_encrypted_data)
    print(f"Re-decrypted data: {re_decrypted_data}")
