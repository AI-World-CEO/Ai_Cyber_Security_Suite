import os
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey


class RotationError(Exception):
    """Custom exception for key rotation errors."""
    pass


class KeyManager:
    """Manage encryption keys and key rotation."""

    def __init__(self, key_length=32):
        self.key_length = key_length
        self.keys = {}

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

    def add_key(self, key_id: str, key: bytes):
        """Add a key to the key manager."""
        self.keys[key_id] = key

    def get_key(self, key_id: str) -> bytes:
        """Retrieve a key from the key manager."""
        try:
            return self.keys[key_id]
        except KeyError:
            raise RotationError(f"Key ID {key_id} not found.")

    def rotate_keys(self):
        """Rotate all keys."""
        for key_id in self.keys:
            password = base64.urlsafe_b64encode(os.urandom(16)).decode()
            salt = os.urandom(16)
            new_key = self.generate_key(password, salt)
            self.keys[key_id] = new_key


class Layer:
    """Class for managing a single encryption layer."""

    def __init__(self, key_manager: KeyManager, layer_id: str):
        self.key_manager = key_manager
        self.layer_id = layer_id
        self.key = self.key_manager.get_key(layer_id)
        self.iv = os.urandom(16)

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

    def __init__(self, key_manager: KeyManager, num_layers=3, key_length=32):
        self.key_manager = key_manager
        self.num_layers = num_layers
        self.key_length = key_length
        self.layers = self.create_layers()

    def create_layers(self):
        """Create multiple encryption layers."""
        layers = []
        for i in range(self.num_layers):
            layer_id = f"layer_{i}"
            password = base64.urlsafe_b64encode(os.urandom(16)).decode()
            salt = os.urandom(16)
            key = self.key_manager.generate_key(password, salt)
            self.key_manager.add_key(layer_id, key)
            layers.append(Layer(self.key_manager, layer_id))
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
        self.key_manager.rotate_keys()
        self.layers = self.create_layers()


class ThreatDetection:
    """Simulate a threat detection system."""

    def __init__(self, encryption_system: LayeredEncryption, rotation_interval=timedelta(hours=1)):
        self.encryption_system = encryption_system
        self.rotation_interval = rotation_interval
        self.last_rotation = datetime.now()

    def detect_threat(self):
        """Simulate threat detection and key rotation."""
        # Simulating threat detection logic
        threat_detected = True
        if threat_detected:
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            print("Threat detected! Keys rotated.")

    def periodic_rotation(self):
        """Periodically rotate keys based on the specified interval."""
        if datetime.now() - self.last_rotation > self.rotation_interval:
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            print("Periodic key rotation executed.")


# Example usage
if __name__ == "__main__":
    key_manager = KeyManager()
    layered_encryption = LayeredEncryption(key_manager)
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

    # Simulate periodic key rotation
    threat_detection.periodic_rotation()
