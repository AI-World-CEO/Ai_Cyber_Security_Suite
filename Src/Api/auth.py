import base64
import hmac
import os
from datetime import datetime, timedelta
from typing import Dict, Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from Src.Utils.logger import setup_logger

# Assuming these imports are from the existing modules


# Initialize logger
logger = setup_logger("auth", "logs/auth.log")


class AuthError(Exception):
    """Custom exception for authentication errors."""
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
            raise AuthError(f"Key ID {key_id} not found.")

    def rotate_keys(self):
        """Rotate all keys."""
        for key_id in self.keys:
            password = base64.urlsafe_b64encode(os.urandom(16)).decode()
            salt = os.urandom(16)
            new_key = self.generate_key(password, salt)
            self.keys[key_id] = new_key


class UserAuth:
    """
    Class for managing user authentication and authorization.
    Uses JWT for generating and verifying tokens.
    """

    def __init__(self, key_manager: KeyManager, token_expiration: timedelta = timedelta(hours=1)):
        self.key_manager = key_manager
        self.token_expiration = token_expiration
        self.secret_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        self.users = {}  # Store user credentials

    def hash_password(self, password: str, salt: bytes) -> str:
        """Hash a password with a salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

    def create_user(self, username: str, password: str):
        """Create a new user with a hashed password."""
        if username in self.users:
            raise AuthError("User already exists.")
        salt = os.urandom(16)
        hashed_password = self.hash_password(password, salt)
        self.users[username] = {'password': hashed_password, 'salt': salt}
        logger.info(f"User {username} created.")

    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate a user with username and password."""
        if username not in self.users:
            raise AuthError("User does not exist.")
        salt = self.users[username]['salt']
        hashed_password = self.hash_password(password, salt)
        if hmac.compare_digest(self.users[username]['password'], hashed_password):
            logger.info(f"User {username} authenticated.")
            return True
        logger.warning(f"Authentication failed for user {username}.")
        return False

    def generate_token(self, username: str) -> str:
        """Generate a JWT for an authenticated user."""
        if username not in self.users:
            raise AuthError("User does not exist.")
        payload = {
            'username': username,
            'exp': datetime.utcnow() + self.token_expiration
        }
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        logger.info(f"Token generated for user {username}.")
        return token

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify a JWT."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            logger.info(f"Token verified for user {payload['username']}.")
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired.")
            raise AuthError("Token has expired.")
        except jwt.InvalidTokenError:
            logger.warning("Invalid token.")
            raise AuthError("Invalid token.")

    def rotate_keys(self):
        """Rotate the secret key for token generation."""
        self.secret_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        logger.info("Secret key rotated for token generation.")


# Example usage
if __name__ == "__main__":
    key_manager = KeyManager()
    user_auth = UserAuth(key_manager)

    # Create a new user
    user_auth.create_user("test_user", "secure_password")

    # Authenticate the user
    if user_auth.authenticate_user("test_user", "secure_password"):
        # Generate a token for the user
        token = user_auth.generate_token("test_user")
        print(f"Generated Token: {token}")

        # Verify the token
        payload = user_auth.verify_token(token)
        print(f"Token Payload: {payload}")

        # Rotate the secret key
        user_auth.rotate_keys()

        # Try to verify the token again (should fail due to key rotation)
        try:
            user_auth.verify_token(token)
        except AuthError as e:
            print(f"Token verification failed: {str(e)}")
