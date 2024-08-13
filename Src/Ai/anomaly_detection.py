import os
import time
import logging
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Dict

from Src.Encryption.key_management import KeyManager
from Src.Encryption.layers import LayeredEncryption
from Src.Utils.logger import setup_logger

# Initialize logger
logger = setup_logger("anomaly_detection", "logs/anomaly_detection.log")


class AnomalyDetectionError(Exception):
    """Custom exception for anomaly detection errors."""
    def __init__(self, message: str):
        super().__init__(message)


class AnomalyDetector:
    """
    Class for detecting anomalies in data access patterns using machine learning.
    Uses Isolation Forest algorithm to detect outliers in the data.
    """

    def __init__(self, encryption_system: LayeredEncryption, rotation_interval: timedelta = timedelta(hours=1)):
        self.encryption_system = encryption_system
        self.rotation_interval = rotation_interval
        self.last_rotation = datetime.now()
        self.model = IsolationForest(contamination=0.1)
        self.scaler = StandardScaler()
        self.data_points = []
        self.threat_log = "logs/anomaly_threat_log.txt"
        self.setup_threat_log()

    def setup_threat_log(self):
        """Setup the threat log file."""
        if not os.path.exists(self.threat_log):
            with open(self.threat_log, 'w') as file:
                file.write("Anomaly Detection Threat Log\n")
                file.write("===========================\n\n")

    def log_threat(self, threat_info: str):
        """Log detected anomaly information."""
        with open(self.threat_log, 'a') as file:
            file.write(f"{datetime.now()}: {threat_info}\n")
        logger.info(threat_info)

    def collect_data_point(self, data_point: Dict[str, float]):
        """
        Collect a new data point for anomaly detection.
        The data point is a dictionary of feature names and their values.
        """
        self.data_points.append(list(data_point.values()))
        if len(self.data_points) > 1000:  # Keep only the most recent 1000 data points
            self.data_points.pop(0)

    def train_model(self):
        """Train the anomaly detection model with the collected data points."""
        if len(self.data_points) < 50:  # Require at least 50 data points to train
            logger.warning("Not enough data points to train the model.")
            return
        data_array = np.array(self.data_points)
        scaled_data = self.scaler.fit_transform(data_array)
        self.model.fit(scaled_data)
        logger.info("Anomaly detection model trained.")

    def detect_anomaly(self, data_point: Dict[str, float]) -> bool:
        """
        Detect anomalies in a new data point.
        Returns True if an anomaly is detected, False otherwise.
        """
        if not self.model:
            raise AnomalyDetectionError("Anomaly detection model is not trained.")
        scaled_point = self.scaler.transform([list(data_point.values())])
        prediction = self.model.predict(scaled_point)
        if prediction[0] == -1:  # Anomaly detected
            self.log_threat(f"Anomaly detected in data point: {data_point}")
            return True
        return False

    def respond_to_anomaly(self, data_point: Dict[str, float]):
        """Respond to detected anomalies by rotating encryption keys."""
        if self.detect_anomaly(data_point):
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            self.log_threat("Encryption keys rotated in response to detected anomaly.")

    def periodic_rotation(self):
        """Periodically rotate keys based on the specified interval."""
        if datetime.now() - self.last_rotation > self.rotation_interval:
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            self.log_threat("Periodic key rotation executed.")

    def monitor(self):
        """
        Continuously monitor for anomalies and perform periodic key rotation.
        This method would typically run in its own thread or process in a real system.
        """
        try:
            while True:
                # Example data point for demonstration purposes
                data_point = {"feature1": np.random.random(), "feature2": np.random.random()}
                self.collect_data_point(data_point)
                self.respond_to_anomaly(data_point)
                self.periodic_rotation()
                time.sleep(60)  # Sleep for a minute between checks
        except Exception as e:
            logger.error(f"Error in anomaly monitoring: {str(e)}")
            raise AnomalyDetectionError(f"Error in anomaly monitoring: {str(e)}")


# Example usage
if __name__ == "__main__":
    key_manager = KeyManager()
    layered_encryption = LayeredEncryption(key_manager)
    anomaly_detector = AnomalyDetector(layered_encryption)

    # Simulate the monitoring process
    try:
        anomaly_detector.monitor()
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
        logger.info("Monitoring stopped by user.")
