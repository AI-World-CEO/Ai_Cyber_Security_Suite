import os
import time
import logging
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Dict

from Src.Encryption.key_management import KeyManager, LayeredEncryption
from Src.Utils.logger import setup_logger

# Initialize logger
logger = setup_logger("behavior_analysis", "logs/behavior_analysis.log")


class BehaviorAnalysisError(Exception):
    """Custom exception for behavior analysis errors."""
    pass


class UserBehavior:
    """
    Class for analyzing user behavior patterns to detect anomalies.
    Uses machine learning to model normal behavior and identify deviations.
    """

    def __init__(self, encryption_system: LayeredEncryption, rotation_interval: timedelta = timedelta(hours=1)):
        self.encryption_system = encryption_system
        self.rotation_interval = rotation_interval
        self.last_rotation = datetime.now()
        self.model = IsolationForest(contamination=0.1)
        self.scaler = StandardScaler()
        self.behavior_data = []
        self.threat_log = "logs/behavior_threat_log.txt"
        self.setup_threat_log()

    def setup_threat_log(self):
        """Setup the threat log file."""
        if not os.path.exists(self.threat_log):
            with open(self.threat_log, 'w') as file:
                file.write("Behavior Analysis Threat Log\n")
                file.write("===========================\n\n")

    def log_threat(self, threat_info: str):
        """Log detected threat information."""
        with open(self.threat_log, 'a') as file:
            file.write(f"{datetime.now()}: {threat_info}\n")
        logger.info(threat_info)

    def collect_behavior_data(self, behavior_point: Dict[str, float]):
        """
        Collect a new data point for behavior analysis.
        The behavior point is a dictionary of feature names and their values.
        """
        self.behavior_data.append(list(behavior_point.values()))
        if len(self.behavior_data) > 1000:  # Keep only the most recent 1000 data points
            self.behavior_data.pop(0)

    def train_model(self):
        """Train the behavior analysis model with the collected behavior data."""
        if len(self.behavior_data) < 50:  # Require at least 50 data points to train
            logger.warning("Not enough behavior data points to train the model.")
            return
        data_array = np.array(self.behavior_data)
        scaled_data = self.scaler.fit_transform(data_array)
        self.model.fit(scaled_data)
        logger.info("Behavior analysis model trained.")

    def detect_anomaly(self, behavior_point: Dict[str, float]) -> bool:
        """
        Detect anomalies in a new behavior point.
        Returns True if an anomaly is detected, False otherwise.
        """
        if not self.model:
            raise BehaviorAnalysisError("Behavior analysis model is not trained.")
        scaled_point = self.scaler.transform([list(behavior_point.values())])
        prediction = self.model.predict(scaled_point)
        if prediction[0] == -1:  # Anomaly detected
            self.log_threat(f"Anomaly detected in behavior point: {behavior_point}")
            return True
        return False

    def respond_to_anomaly(self, behavior_point: Dict[str, float]):
        """Respond to detected anomalies by rotating encryption keys."""
        if self.detect_anomaly(behavior_point):
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            self.log_threat("Encryption keys rotated in response to detected behavior anomaly.")

    def periodic_rotation(self):
        """Periodically rotate keys based on the specified interval."""
        if datetime.now() - self.last_rotation > self.rotation_interval:
            self.encryption_system.rotate_keys()
            self.last_rotation = datetime.now()
            self.log_threat("Periodic key rotation executed.")

    def monitor(self):
        """
        Continuously monitor user behavior and perform periodic key rotation.
        This method would typically run in its own thread or process in a real system.
        """
        try:
            while True:
                # Example behavior point for demonstration purposes
                behavior_point = {"feature1": np.random.random(), "feature2": np.random.random()}
                self.collect_behavior_data(behavior_point)
                self.respond_to_anomaly(behavior_point)
                self.periodic_rotation()
                time.sleep(60)  # Sleep for a minute between checks
        except Exception as e:
            logger.error(f"Error in behavior monitoring: {str(e)}")
            raise BehaviorAnalysisError(f"Error in behavior monitoring: {str(e)}")


# Example usage
if __name__ == "__main__":
    key_manager = KeyManager()
    layered_encryption = LayeredEncryption(key_manager)
    behavior_analysis = UserBehavior(layered_encryption)

    # Simulate the monitoring process
    try:
        behavior_analysis.monitor()
    except KeyboardInterrupt:
        print("Monitoring stopped by user.")
        logger.info("Monitoring stopped by user.")
