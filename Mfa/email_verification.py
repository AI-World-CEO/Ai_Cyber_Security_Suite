import random
import smtplib
import string
from email.mime.text import MIMEText
from typing import Dict


class EmailVerificationError(Exception):
    """Custom exception for Email Verification-related errors."""
    pass


class EmailVerification:
    """
    Handles email-based verification for MFA.
    """

    def __init__(self, smtp_server: str, smtp_port: int, smtp_user: str, smtp_password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.verification_codes: Dict[str, str] = {}

    def generate_verification_code(self, user_id: str) -> str:
        """Generate a verification code and send it via email."""
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        self.verification_codes[user_id] = code
        self.send_email(user_id, code)
        return code

    def send_email(self, to_email: str, code: str):
        """Send the verification code via email."""
        msg = MIMEText(f"Your verification code is: {code}")
        msg['Subject'] = 'Verification Code'
        msg['From'] = self.smtp_user
        msg['To'] = to_email

        with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
            server.login(self.smtp_user, self.smtp_password)
            server.sendmail(self.smtp_user, [to_email], msg.as_string())

    def verify_code(self, user_id: str, code: str) -> bool:
        """Verify the provided code for the given user ID."""
        return self.verification_codes.get(user_id) == code

    def get_data(self) -> Dict[str, str]:
        """Get email verification data."""
        return self.verification_codes

    def set_data(self, data: Dict[str, str]):
        """Set email verification data."""
        self.verification_codes = data
