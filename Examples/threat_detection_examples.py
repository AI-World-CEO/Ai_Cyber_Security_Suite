from datetime import datetime

from Src.Encryption.key_management import KeyManager
from Src.Encryption.layers import ThreatDetection
from Src.Utils.logger import setup_logger

# Initialize the logger
logger = setup_logger("threat_detection_examples_logger")


class KeyRotation:
    """
    Class to handle key rotation.
    """

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    def rotate_keys(self):
        """
        Rotate the encryption keys.
        """
        try:
            self.key_manager.rotate_keys()
            logger.info("Keys rotated successfully.")
        except Exception as e:
            logger.error(f"Key rotation failed: {str(e)}")


class ThreatDetectionExamples:
    """
    Class to demonstrate various threat detection examples using the Cyber AI Security Suite.
    """

    def __init__(self, key: KeyManager, log_file: str):
        self.threat_detection = ThreatDetection()
        self.key_manager = key
        self.key_rotation = KeyRotation(self.key_manager)
        self.log_file = log_file

    def example_sql_injection(self):
        """Example demonstrating detection of SQL injection attacks."""
        logger.info("Starting SQL injection detection example...")
        data = {"timestamp": datetime.now().timestamp(), "value": "SELECT * FROM users WHERE '1'='1';"}

        # Detect threat
        threat_detected = self.threat_detection.analyze(data)
        if threat_detected:
            logger.info("SQL injection threat detected!")
            self.key_rotation.rotate_keys()
        else:
            logger.info("No threat detected in SQL injection example.")

    def example_xss_attack(self):
        """Example demonstrating detection of XSS (Cross-Site Scripting) attacks."""
        logger.info("Starting XSS attack detection example...")
        data = {"timestamp": datetime.now().timestamp(), "value": "<script>alert('XSS');</script>"}

        # Detect threat
        threat_detected = self.threat_detection.analyze(data)
        if threat_detected:
            logger.info("XSS attack threat detected!")
            self.key_rotation.rotate_keys()
        else:
            logger.info("No threat detected in XSS attack example.")

    def example_ddos_attack(self):
        """Example demonstrating detection of DDoS (Distributed Denial of Service) attacks."""
        logger.info("Starting DDoS attack detection example...")
        data = {"timestamp": datetime.now().timestamp(), "value": "DDoS traffic pattern detected"}

        # Detect threat
        threat_detected = self.threat_detection.analyze(data)
        if threat_detected:
            logger.info("DDoS attack threat detected!")
            self.key_rotation.rotate_keys()
        else:
            logger.info("No threat detected in DDoS attack example.")

    def example_phishing_attack(self):
        """Example demonstrating detection of phishing attacks."""
        logger.info("Starting phishing attack detection example...")
        data = {"timestamp": datetime.now().timestamp(), "value": "http://phishing-site.com"}

        # Detect threat
        threat_detected = self.threat_detection.analyze(data)
        if threat_detected:
            logger.info("Phishing attack threat detected!")
            self.key_rotation.rotate_keys()
        else:
            logger.info("No threat detected in phishing attack example.")

    def run_all_examples(self):
        """Run all threat detection examples."""
        self.example_sql_injection()
        self.example_xss_attack()
        self.example_ddos_attack()
        self.example_phishing_attack()


def main():
    key_manager = KeyManager()
    log_file = "logs/threat_detection_examples.log"
    threat_detection_examples = ThreatDetectionExamples(key=key_manager, log_file=log_file)
    threat_detection_examples.run_all_examples()


if __name__ == "__main__":
    main()
