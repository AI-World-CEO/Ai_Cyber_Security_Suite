import json
import os
import time

from Config.encryption_settings import EncryptionSettings
from Src.Encryption.key_management import KeyManager, LayeredEncryption
from Src.Encryption.layers import ThreatDetection
from Src.Utils.logger import setup_logger

# Initialize the logger
logger = setup_logger("monitoring_logger", "logs/monitoring.log", b"monitoring_key")


def send_alert(message: str):
    # Placeholder for sending an alert (e.g., email, SMS, etc.)
    logger.info(f"Alert sent: {message}")


class SystemMonitor:
    """
    Class to monitor system health, detect anomalies and threats,
    and perform automated responses such as key rotation and re-encryption.
    """

    def __init__(self, data_dir: str = "data/raw", log_dir: str = "data/logs"):
        self.data_dir = data_dir
        self.log_dir = log_dir
        self.key_manager = KeyManager()
        self.encryption_settings = EncryptionSettings()
        self.layered_encryption = LayeredEncryption(self.key_manager, num_layers=3)
        self.threat_detection = ThreatDetection(self.layered_encryption)

        # Ensure data and log directories exist
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def monitor_system(self):
        """Monitor the system for anomalies, threats, and health status."""
        try:
            while True:
                self.check_system_health()
                self.detect_threats()
                time.sleep(60)  # Monitor every minute
        except Exception as e:
            logger.error(f"Monitoring failed: {e}")
            raise

    def check_system_health(self):
        """Check the system health and report any issues."""
        try:
            # Placeholder for actual health checks (disk space, memory usage, etc.)
            logger.info("System health check passed.")
        except Exception as e:
            logger.error(f"System health check failed: {e}")
            raise

    def detect_threats(self):
        """Detect threats using the threat detection AI."""
        try:
            data_files = [f for f in os.listdir(self.data_dir) if f.endswith(".json")]
            for data_file in data_files:
                data_path = os.path.join(self.data_dir, data_file)
                with open(data_path, 'r') as file:
                    data = json.load(file)
                threat_detected = self.threat_detection.analyze(data)
                if threat_detected:
                    self.respond_to_threat()
                    send_alert("Threat detected and responded to.")
        except Exception as e:
            logger.error(f"Threat detection failed: {e}")
            raise

    def respond_to_threat(self):
        """Respond to detected threats by rotating keys and re-encrypting data."""
        try:
            # Perform immediate key rotation
            self.key_manager.rotate_keys()
            logger.info("Key rotation completed successfully.")

            # Re-encrypt data with new keys
            self.re_encrypt_data()
            logger.info("Data re-encryption completed successfully.")
        except Exception as e:
            logger.error(f"Threat response failed: {e}")
            raise

    def re_encrypt_data(self):
        """Re-encrypt data with the new encryption keys."""
        try:
            data_files = [f for f in os.listdir(self.data_dir) if f.endswith(".json")]
            for data_file in data_files:
                data_path = os.path.join(self.data_dir, data_file)
                with open(data_path, 'r') as file:
                    data = json.load(file)
                encrypted_data = self.layered_encryption.encrypt(json.dumps(data).encode())
                with open(data_path, 'wb') as file:
                    file.write(encrypted_data)
        except Exception as e:
            logger.error(f"Data re-encryption failed: {e}")
            raise


def main():
    system_monitor = SystemMonitor()
    system_monitor.monitor_system()


if __name__ == "__main__":
    main()
