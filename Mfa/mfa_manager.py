import os
import json
from .otp import OTP
from .totp import TOTP
from .backup_codes import BackupCodes
from .email_verification import EmailVerification


class MFAError(Exception):
    """Custom exception for MFA-related errors."""
    pass


class SMSVerification:
    pass


class MFAManager:
    """
    Manages the different MFA mechanisms and provides a unified interface.
    """

    def __init__(self):
        self.otp = OTP()
        self.totp = TOTP()
        self.backup_codes = BackupCodes()
        self.email_verification = EmailVerification()
        self.sms_verification = SMSVerification()

    def save_mfa_data(self, filename: str):
        """Save MFA data to a file."""
        data = {
            "otp": self.otp.get_data(),
            "totp": self.totp.get_data(),
            "backup_codes": self.backup_codes.get_data(),
            "email_verification": self.email_verification.get_data(),
            "sms_verification": self.sms_verification.get_data()
        }
        with open(filename, 'w') as f:
            json.dump(data, f)

    def load_mfa_data(self, filename: str):
        """Load MFA data from a file."""
        with open(filename, 'r') as f:
            data = json.load(f)
        self.otp.set_data(data["otp"])
        self.totp.set_data(data["totp"])
        self.backup_codes.set_data(data["backup_codes"])
        self.email_verification.set_data(data["email_verification"])
        self.sms_verification.set_data(data["sms_verification"])
