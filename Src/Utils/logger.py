import logging
import os
from logging.handlers import RotatingFileHandler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class LoggerError(Exception):
    """Custom exception for logger-related errors."""
    pass


class EncryptedRotatingFileHandler(RotatingFileHandler):
    """A rotating file handler that encrypts log entries before writing them to disk."""

    def __init__(self, filename, key, maxBytes=0, backupCount=0, encoding='utf-8', delay=False):
        os.makedirs(os.path.dirname(filename), exist_ok=True)  # Ensure the directory exists
        super().__init__(filename, maxBytes=maxBytes, backupCount=backupCount, encoding=encoding, delay=delay)
        self.key = key
        self.iv = os.urandom(16)

    def encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return self.iv + encryptor.update(data) + encryptor.finalize()

    def emit(self, record):
        try:
            msg = self.format(record)
            encrypted_msg = self.encrypt(msg.encode(self.encoding or 'utf-8'))
            self.stream = self._open()
            self.stream.write(encrypted_msg + b'\n')
            self.stream.flush()
        except Exception:
            self.handleError(record)


def generate_salt(length=16):
    """Generate a cryptographic salt."""
    return os.urandom(length)


def generate_key(password, salt, length=32, iterations=100000):
    """Generate a cryptographic key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def setup_logger(name, log_file, key, level=logging.INFO):
    """
    Set up a logger with the specified name and log file, with encrypted rotating file handler.

    :param name: Name of the logger.
    :param log_file: Path to the log file.
    :param key: Encryption key.
    :param level: Logging level.
    :return: Configured logger.
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)  # Ensure the directory exists
    logger = logging.getLogger(name)
    logger.setLevel(level)
    handler = EncryptedRotatingFileHandler(log_file, key, maxBytes=1024 * 1024, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


# Example usage
if __name__ == "__main__":
    password = "secure_password"
    salt = generate_salt()
    key = generate_key(password, salt)
    log_file = "logs/encrypted_log.log"

    logger = setup_logger("encrypted_logger", log_file, key)
    logger.info("This is a test log entry.")
