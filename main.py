import os
import time
from datetime import datetime, timedelta

from flask import Flask, render_template, jsonify

from Src.Encryption.key_management import KeyManager, LayeredEncryption
from Src.Utils.logger import setup_logger

app = Flask(__name__, template_folder='Src/Ui')


@app.route('/')
def home():
    return render_template('interface.html')


@app.route('/encryption_management')
def encryption_management():
    return render_template('encryption_management.html')


@app.route('/threat_detection')
def threat_detection():
    return render_template('threat_detection.html')


@app.route('/user_management')
def user_management():
    return render_template('user_management.html')


@app.route('/logs')
def logs():
    return render_template('logs.html')


@app.route('/settings')
def settings():
    return render_template('settings.html')


@app.route('/biometric_scanning')
def biometric_scanning():
    return render_template('biometric_scanning.html')


@app.route('/start_biometric_scan', methods=['POST'])
def start_biometric_scan():
    # Placeholder for starting the biometric scan
    # This will typically call a backend API that interacts with the biometric device
    try:
        # Simulate a successful scan
        result = {"status": "success", "message": "User verified"}
        return jsonify(result)
    except Exception as e:
        result = {"status": "error", "message": str(e)}
        return jsonify(result), 500


if __name__ == "__main__":
    app.run(debug=True)

# Initialize logger
logger = setup_logger("threat_detection", "logs/threat_detection.log", b"threat_detection_key")


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
    layered_encryption = LayeredEncryption(key_manager, num_layers=3)
    threat_detection = ThreatDetection(layered_encryption)

    # Simulate the monitoring process
    try:
        threat_detection.monitor()
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
        logger.info("Monitoring stopped by user.")
