"""
Multi-Factor Authentication (MFA) Module

This module provides various mechanisms for implementing multi-factor authentication,
including one-time passwords (OTP), time-based OTP (TOTP), backup codes, email verification,
and SMS verification.

Classes:
    - MFAManager: Manages the different MFA mechanisms.
    - OTP: Handles one-time password generation and verification.
    - TOTP: Handles time-based OTP generation and verification.
    - BackupCodes: Manages backup codes for MFA.
    - EmailVerification: Handles email-based verification for MFA.
    - SMSVerification: Handles SMS-based verification for MFA.

Exceptions:
    - MFAError: Custom exception for MFA-related errors.
"""

from .mfa_manager import MFAManager
from .otp import OTP
from .totp import TOTP
from .backup_codes import BackupCodes
from .email_verification import EmailVerification
from .sms_verification import SMSVerification

__all__ = [
    "MFAManager",
    "OTP",
    "TOTP",
    "BackupCodes",
    "EmailVerification",
    "SMSVerification",
    "MFAError"
]
