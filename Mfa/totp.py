import hmac
import base64
import os
import struct
import hashlib
import time
from typing import Dict, Any


class TOTPError(Exception):
    """Custom exception for TOTP-related errors."""
    pass


class TOTP:
    """
    Handles time-based one-time password (TOTP) generation and verification.
    """

    def __init__(self, interval: int = 30, length: int = 6):
        self.interval = interval
        self.length = length
        self.totp_data: Dict[str, Any] = {}

    def generate_totp(self, secret: str) -> str:
        """Generate a TOTP for a given secret."""
        time_counter = int(time.time() / self.interval)
        key = base64.b32decode(secret)
        msg = struct.pack(">Q", time_counter)
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        otp = (struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** self.length)
        return str(otp).zfill(self.length)

    def verify_totp(self, secret: str, otp: str) -> bool:
        """Verify the provided TOTP for the given secret."""
        expected_otp = self.generate_totp(secret)
        return hmac.compare_digest(expected_otp, otp)

    def get_data(self) -> Dict[str, Any]:
        """Get TOTP data."""
        return self.totp_data

    def set_data(self, data: Dict[str, Any]):
        """Set TOTP data."""
        self.totp_data = data

    def add_user(self, user_id: str, secret: str):
        """Add a user with a specific TOTP secret."""
        self.totp_data[user_id] = {'secret': secret}

    def remove_user(self, user_id: str):
        """Remove a user and their associated TOTP secret."""
        if user_id in self.totp_data:
            del self.totp_data[user_id]

    def generate_user_totp(self, user_id: str) -> str:
        """Generate a TOTP for a specific user."""
        if user_id not in self.totp_data:
            raise TOTPError("User not found")
        return self.generate_totp(self.totp_data[user_id]['secret'])

    def verify_user_totp(self, user_id: str, otp: str) -> bool:
        """Verify a TOTP for a specific user."""
        if user_id not in self.totp_data:
            raise TOTPError("User not found")
        return self.verify_totp(self.totp_data[user_id]['secret'], otp)


# Example usage
if __name__ == "__main__":
    totp = TOTP()
    user_id = "user123"
    secret = base64.b32encode(os.urandom(10)).decode('utf-8').rstrip('=')

    totp.add_user(user_id, secret)

    # Generate a TOTP for the user
    generated_totp = totp.generate_user_totp(user_id)
    print(f"Generated TOTP: {generated_totp}")

    # Verify the TOTP
    is_valid = totp.verify_user_totp(user_id, generated_totp)
    print(f"TOTP is valid: {is_valid}")

    # Save and load data
    data = totp.get_data()
    print(f"Data before saving: {data}")

    totp.set_data(data)
    loaded_data = totp.get_data()
    print(f"Data after loading: {loaded_data}")
