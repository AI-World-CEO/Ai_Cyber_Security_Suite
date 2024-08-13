import os
import json
from typing import Dict


class KeyRotationSettingsError(Exception):
    """Custom exception for key rotation settings-related errors."""

    def __init__(self, message: str):
        super().__init__(message)


class KeyRotationSettings:
    """
    Class to manage key rotation settings, including rotation intervals,
    immediate rotation on threat detection, and rotation policies.
    """

    def __init__(self, config_file: str = "config/key_rotation_settings.json"):
        self.config_file = config_file
        self.settings = self.load_settings()

    def load_settings(self) -> Dict:
        """Load key rotation settings from a configuration file."""
        if not os.path.exists(self.config_file):
            raise KeyRotationSettingsError(f"Configuration file {self.config_file} not found.")

        with open(self.config_file, 'r') as file:
            return json.load(file)

    def save_settings(self):
        """Save key rotation settings to a configuration file."""
        with open(self.config_file, 'w') as file:
            json.dump(self.settings, file, indent=4)

    def get_rotation_interval(self) -> int:
        """Get the key rotation interval in seconds."""
        return self.settings.get("rotation_interval", 3600)  # Default to 1 hour

    def set_rotation_interval(self, interval: int):
        """Set the key rotation interval in seconds."""
        self.settings["rotation_interval"] = interval
        self.save_settings()

    def get_immediate_rotation_on_threat(self) -> bool:
        """Check if immediate key rotation on threat detection is enabled."""
        return self.settings.get("immediate_rotation_on_threat", True)

    def set_immediate_rotation_on_threat(self, enabled: bool):
        """Enable or disable immediate key rotation on threat detection."""
        self.settings["immediate_rotation_on_threat"] = enabled
        self.save_settings()

    def get_rotation_policy(self) -> Dict:
        """Get the key rotation policy."""
        return self.settings.get("rotation_policy", {
            "max_rotations": 5,
            "rotation_algorithm": "AES"
        })

    def set_rotation_policy(self, policy: Dict):
        """Set the key rotation policy."""
        self.settings["rotation_policy"] = policy
        self.save_settings()

    def get_all_settings(self) -> Dict:
        """Get all key rotation settings."""
        return self.settings


# Example usage
if __name__ == "__main__":
    key_rotation_settings = KeyRotationSettings()

    # Print current rotation interval
    print("Current Rotation Interval:", key_rotation_settings.get_rotation_interval())

    # Update rotation interval
    key_rotation_settings.set_rotation_interval(7200)  # 2 hours
    print("Updated Rotation Interval:", key_rotation_settings.get_rotation_interval())

    # Print current immediate rotation on threat setting
    print("Immediate Rotation on Threat:", key_rotation_settings.get_immediate_rotation_on_threat())

    # Update immediate rotation on threat setting
    key_rotation_settings.set_immediate_rotation_on_threat(False)
    print("Updated Immediate Rotation on Threat:", key_rotation_settings.get_immediate_rotation_on_threat())

    # Print current rotation policy
    print("Current Rotation Policy:", key_rotation_settings.get_rotation_policy())

    # Update rotation policy
    new_rotation_policy = {
        "max_rotations": 10,
        "rotation_algorithm": "RSA"
    }
    key_rotation_settings.set_rotation_policy(new_rotation_policy)
    print("Updated Rotation Policy:", key_rotation_settings.get_rotation_policy())

    # Print all settings
    print("All Key Rotation Settings:", key_rotation_settings.get_all_settings())
