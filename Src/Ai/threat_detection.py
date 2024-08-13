import os
import time
import logging
from datetime import datetime, timedelta

from Src.Encryption.key_management import LayeredEncryption, KeyManager
from Src.Utils.logger import setup_logger

# Initialize logger
logger = setup_logger("threat_detection", "logs/threat_detection.log", "threat_detection_key")

class ThreatDetectionError(Exception):
    """Custom exception for threat detection errors."""
    pass

class ThreatDetection:
    """
    Simulate a threat detection system that monitors for security breaches
    and triggers key rotation in the LayeredEncryption system.
    """

    def __init__(self, encryption_system: LayeredEncryption, rotation_interval: timedelta = timedelta(hours=1)):
        self.encryption_system = encryption_system
        self.rotation_interval = rotation_interval
        self.last_rotation = datetime.now()
        self.threat_log = "logs/threat_log.txt"
        self.setup_threat_log()

    def setup_threat_log(self):
        """Setup the threat log file."""
        if not os.path.exists(self.threat_log):
            with open(self.threat_log, 'w') as file:
                file.write("Threat Detection Log\n")
                file.write("====================\n\n")

    def log_threat(self, threat_info: str):
        """Log detected threat information."""
        with open(self.threat_log, 'a') as file:
            file.write(f"{datetime.now()}: {threat_info}\n")
        logger.info(threat_info)

    def detect_threat(self) -> bool:
        """
        Simulate threat detection logic.
        In a real system, this method would include comprehensive threat detection logic.
        """
        # For demonstration purposes, we'll simulate threat detection with a random chance
        threat_detected = True  # Simulating a detected threat
        if threat_detected:
            self.log_threat("Simulated threat detected!")
            return True
        return False

    def respond_to_threat(self):
        """Respond to a detected threat by rotating encryption keys."""
        if self.detect_threat():
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            self.log_threat("Encryption keys rotated in response to detected threat.")

    def periodic_rotation(self):
        """Periodically rotate keys based on the specified interval."""
        if datetime.now() - self.last_rotation > self.rotation_interval:
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            self.log_threat("Periodic key rotation executed.")

    def monitor(self):
        """
        Continuously monitor for threats and perform periodic key rotation.
        This method would typically run in its own thread or process in a real system.
        """
        try:
            while True:
                self.respond_to_threat()
                self.periodic_rotation()
                time.sleep(60)  # Sleep for a minute between checks
        except Exception as e:
            logger.error(f"Error in threat monitoring: {str(e)}")
            raise ThreatDetectionError(f"Error in threat monitoring: {str(e)}")

# Example usage
if __name__ == "__main__":
    key_manager = KeyManager()
    layered_encryption = LayeredEncryption(key_manager)
    threat_detection = ThreatDetection(layered_encryption)

    # Simulate the monitoring process
    try:
        threat_detection.monitor()
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
        logger.info("Monitoring stopped by user.")
