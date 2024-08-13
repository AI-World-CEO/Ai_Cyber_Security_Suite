import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class KeyManagementError(Exception):
    """Custom exception for key management errors."""
    pass


class KeyManager:
    """Manage encryption keys and key rotation."""

    def __init__(self, key_length=32):
        self.key_length = key_length
        self.keys = {}

    def generate_symmetric_key(self, password: str, salt: bytes) -> bytes:
        """Generate a symmetric key from a password and a salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def generate_asymmetric_keys():
        """Generate a pair of RSA keys (private and public)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem_private_key, pem_public_key

    @staticmethod
    def load_private_key(pem_private_key: bytes):
        """Load a private RSA key from PEM format."""
        return serialization.load_pem_private_key(
            pem_private_key,
            password=None,
            backend=default_backend()
        )

    @staticmethod
    def load_public_key(pem_public_key: bytes):
        """Load a public RSA key from PEM format."""
        return serialization.load_pem_public_key(
            pem_public_key,
            backend=default_backend()
        )

    def encrypt_with_public_key(self, pem_public_key: bytes, data_to_encrypt: bytes) -> bytes:
        """Encrypt data using a public RSA key."""
        public_key = self.load_public_key(pem_public_key)
        return public_key.encrypt(
            data_to_encrypt,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_with_private_key(self, pem_private_key: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt data using a private RSA key."""
        private_key = self.load_private_key(pem_private_key)
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def save_keys(self, filename: str):
        """Save keys to a file."""
        with open(filename, 'w') as f:
            json.dump(self.keys, f)

    def load_keys(self, filename: str):
        """Load keys from a file."""
        with open(filename, 'r') as f:
            self.keys = json.load(f)

    def rotate_keys(self):
        """Rotate all keys."""
        for key_id in self.keys:
            password = base64.urlsafe_b64encode(os.urandom(16)).decode()
            salt = os.urandom(16)
            self.keys[key_id] = self.generate_symmetric_key(password, salt)


class EncryptionLayer:
    """Class for managing a single layer of encryption."""

    def __init__(self, key_manager: KeyManager, layer_id: str):
        self.key_manager = key_manager
        self.layer_id = layer_id
        self.key = self.key_manager.keys.get(layer_id)
        if not self.key:
            password = base64.urlsafe_b64encode(os.urandom(16)).decode()
            salt = os.urandom(16)
            self.key = self.key_manager.generate_symmetric_key(password, salt)
            self.key_manager.keys[layer_id] = self.key

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with the layer's key."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(plaintext) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with the layer's key."""
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext[16:]) + decryptor.finalize()


class LayeredEncryption:
    """Class for managing layered encryption."""

    def __init__(self, key_manager: KeyManager, num_layers=3):
        self.key_manager = key_manager
        self.num_layers = num_layers
        self.layers = [EncryptionLayer(key_manager, f"layer_{i}") for i in range(self.num_layers)]

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data with multiple layers."""
        data = plaintext
        for layer in self.layers:
            data = layer.encrypt(data)
        return data

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data with multiple layers."""
        data = ciphertext
        for layer in reversed(self.layers):
            data = layer.decrypt(data)
        return data

    def rotate_keys(self):
        """Rotate keys for all layers."""
        self.key_manager.rotate_keys()
        self.layers = [EncryptionLayer(self.key_manager, f"layer_{i}") for i in range(self.num_layers)]


# Example usage
if __name__ == "__main__":
    key_manager = KeyManager()
    layered_encryption = LayeredEncryption(key_manager)

    # Generate asymmetric keys and store them
    private_key, public_key = key_manager.generate_asymmetric_keys()
    key_manager.keys["private_key"] = private_key.decode()
    key_manager.keys["public_key"] = public_key.decode()

    sensitive_data = b"Sensitive data that needs encryption"

    # Encrypt with layered encryption
    encrypted_data = layered_encryption.encrypt(sensitive_data)
    print(f"Encrypted data: {encrypted_data}")

    # Decrypt with layered encryption
    decrypted_data = layered_encryption.decrypt(encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

    # Simulate key rotation
    key_manager.rotate_keys()
    layered_encryption.rotate_keys()

    # Re-encrypt data with new keys
    re_encrypted_data = layered_encryption.encrypt(sensitive_data)
    print(f"Re-encrypted data: {re_encrypted_data}")

    re_decrypted_data = layered_encryption.decrypt(re_encrypted_data)
    print(f"Re-decrypted data: {re_decrypted_data}")

    # Encrypt data with public key
    encrypted_with_public_key = key_manager.encrypt_with_public_key(public_key.encode(), sensitive_data)
    print(f"Encrypted with public key: {encrypted_with_public_key}")

    # Decrypt data with private key
    decrypted_with_private_key = key_manager.decrypt_with_private_key(private_key.encode(), encrypted_with_public_key)
    print(f"Decrypted with private key: {decrypted_with_private_key}")
