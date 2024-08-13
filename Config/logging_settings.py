import os
import json
import logging
from typing import Dict


class LoggingSettingsError(Exception):
    """Custom exception for logging settings-related errors."""

    def __init__(self, message: str):
        super().__init__(message)


class LoggingSettings:
    """
    Class to manage logging settings, including log levels, log file paths,
    log formats, and rotation policies.
    """

    def __init__(self, config_file: str = "config/logging_settings.json"):
        self.config_file = config_file
        self.settings = self.load_settings()

    def load_settings(self) -> Dict:
        """Load logging settings from a configuration file."""
        if not os.path.exists(self.config_file):
            raise LoggingSettingsError(f"Configuration file {self.config_file} not found.")

        with open(self.config_file, 'r') as file:
            return json.load(file)

    def save_settings(self):
        """Save logging settings to a configuration file."""
        with open(self.config_file, 'w') as file:
            json.dump(self.settings, file, indent=4)

    def get_log_level(self) -> str:
        """Get the log level."""
        return self.settings.get("log_level", "INFO")

    def set_log_level(self, level: str):
        """Set the log level."""
        self.settings["log_level"] = level
        self.save_settings()

    def get_log_file_path(self) -> str:
        """Get the log file path."""
        return self.settings.get("log_file_path", "logs/application.log")

    def set_log_file_path(self, path: str):
        """Set the log file path."""
        self.settings["log_file_path"] = path
        self.save_settings()

    def get_log_format(self) -> str:
        """Get the log format."""
        return self.settings.get("log_format", "%(asctime)s %(levelname)s %(message)s")

    def set_log_format(self, format: str):
        """Set the log format."""
        self.settings["log_format"] = format
        self.save_settings()

    def get_rotation_policy(self) -> Dict:
        """Get the log rotation policy."""
        return self.settings.get("rotation_policy", {
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5
        })

    def set_rotation_policy(self, policy: Dict):
        """Set the log rotation policy."""
        self.settings["rotation_policy"] = policy
        self.save_settings()

    def setup_logger(self, name: str) -> logging.Logger:
        """Set up and return a logger based on the current settings."""
        logger = logging.getLogger(name)
        logger.setLevel(self.get_log_level())

        log_file_path = self.get_log_file_path()
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

        handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=self.get_rotation_policy()["maxBytes"],
            backupCount=self.get_rotation_policy()["backupCount"]
        )
        formatter = logging.Formatter(self.get_log_format())
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger


# Example usage
if __name__ == "__main__":
    logging_settings = LoggingSettings()

    # Print current log level
    print("Current Log Level:", logging_settings.get_log_level())

    # Update log level
    logging_settings.set_log_level("DEBUG")
    print("Updated Log Level:", logging_settings.get_log_level())

    # Print current log file path
    print("Current Log File Path:", logging_settings.get_log_file_path())

    # Update log file path
    logging_settings.set_log_file_path("logs/new_application.log")
    print("Updated Log File Path:", logging_settings.get_log_file_path())

    # Print current log format
    print("Current Log Format:", logging_settings.get_log_format())

    # Update log format
    logging_settings.set_log_format("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    print("Updated Log Format:", logging_settings.get_log_format())

    # Print current rotation policy
    print("Current Rotation Policy:", logging_settings.get_rotation_policy())

    # Update rotation policy
    new_rotation_policy = {
        "maxBytes": 20971520,  # 20MB
        "backupCount": 10
    }
    logging_settings.set_rotation_policy(new_rotation_policy)
    print("Updated Rotation Policy:", logging_settings.get_rotation_policy())

    # Set up and use logger
    logger = logging_settings.setup_logger("application_logger")
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")
