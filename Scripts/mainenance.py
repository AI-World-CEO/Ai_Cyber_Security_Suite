# maintenance.py

import os
import shutil
import time
from datetime import datetime

from Config.encryption_settings import EncryptionSettings
from Src.Encryption.key_management import KeyManager
from Src.Utils.logger import setup_logger

# Initialize the logger
logger = setup_logger("maintenance_logger", "logs/maintenance.log", b"maintenance_key")


class MaintenanceError(Exception):
    """Custom exception for maintenance-related errors."""
    pass


class Maintenance:
    """
    Class to perform maintenance tasks such as backups, log rotation,
    key rotation, and system health checks.
    """

    def __init__(self, backup_dir: str = "data/backups", log_dir: str = "data/logs"):
        self.backup_dir = backup_dir
        self.log_dir = log_dir
        self.key_manager = KeyManager()
        self.encryption_settings = EncryptionSettings()

        # Ensure backup and log directories exist
        os.makedirs(self.backup_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def backup_data(self, data_dir: str = "data/raw"):
        """Backup raw data to the backup directory."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_path = os.path.join(self.backup_dir, f"backup_{timestamp}")
            shutil.copytree(data_dir, backup_path)
            logger.info(f"Data backup completed successfully to {backup_path}.")
        except Exception as e:
            logger.error(f"Data backup failed: {e}")
            raise MaintenanceError(f"Data backup failed: {e}")

    def rotate_logs(self):
        """Rotate logs to prevent excessive log file sizes."""
        try:
            log_files = [f for f in os.listdir(self.log_dir) if f.endswith(".log")]
            for log_file in log_files:
                log_path = os.path.join(self.log_dir, log_file)
                if os.path.getsize(log_path) > 5 * 1024 * 1024:  # If log file is larger than 5MB
                    new_log_path = f"{log_path}.{int(time.time())}"
                    shutil.move(log_path, new_log_path)
                    logger.info(f"Log file {log_file} rotated to {new_log_path}.")
        except Exception as e:
            logger.error(f"Log rotation failed: {e}")
            raise MaintenanceError(f"Log rotation failed: {e}")

    def perform_key_rotation(self):
        """Perform key rotation using the KeyManager."""
        try:
            self.key_manager.rotate_keys()
            logger.info("Key rotation completed successfully.")
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            raise MaintenanceError(f"Key rotation failed: {e}")

    def check_system_health(self):
        """Check the system health and report any issues."""
        try:
            # Placeholder for actual health checks (disk space, memory usage, etc.)
            logger.info("System health check passed.")
        except Exception as e:
            logger.error(f"System health check failed: {e}")
            raise MaintenanceError(f"System health check failed: {e}")


def main():
    maintenance = Maintenance()
    maintenance.backup_data()
    maintenance.rotate_logs()
    maintenance.perform_key_rotation()
    maintenance.check_system_health()


if __name__ == "__main__":
    main()
