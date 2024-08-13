import json
import os
from typing import Dict


class AISettingsError(Exception):
    """Custom exception for AI settings-related errors."""

    def __init__(self, message: str):
        super().__init__(message)


class AISettings:
    """
    Class to manage AI settings, including threat detection parameters,
    anomaly detection thresholds, and behavior analysis configurations.
    """

    def __init__(self, config_file: str = "config/ai_settings.json"):
        self.config_file = config_file
        self.settings = self.load_settings()

    def load_settings(self) -> Dict:
        """Load AI settings from a configuration file."""
        if not os.path.exists(self.config_file):
            raise AISettingsError(f"Configuration file {self.config_file} not found.")

        with open(self.config_file, 'r') as file:
            return json.load(file)

    def save_settings(self):
        """Save AI settings to a configuration file."""
        with open(self.config_file, 'w') as file:
            json.dump(self.settings, file, indent=4)

    def get_threat_detection_params(self) -> Dict:
        """Get threat detection parameters."""
        return self.settings.get("threat_detection_params", {
            "sensitivity": 0.5,
            "model_type": "IsolationForest"
        })

    def set_threat_detection_params(self, params: Dict):
        """Set threat detection parameters."""
        self.settings["threat_detection_params"] = params
        self.save_settings()

    def get_anomaly_detection_thresholds(self) -> Dict:
        """Get anomaly detection thresholds."""
        return self.settings.get("anomaly_detection_thresholds", {
            "threshold": 0.8,
            "algorithm": "Z-Score"
        })

    def set_anomaly_detection_thresholds(self, thresholds: Dict):
        """Set anomaly detection thresholds."""
        self.settings["anomaly_detection_thresholds"] = thresholds
        self.save_settings()

    def get_behavior_analysis_config(self) -> Dict:
        """Get behavior analysis configuration."""
        return self.settings.get("behavior_analysis_config", {
            "window_size": 10,
            "metric": "euclidean"
        })

    def set_behavior_analysis_config(self, config: Dict):
        """Set behavior analysis configuration."""
        self.settings["behavior_analysis_config"] = config
        self.save_settings()

    def get_all_settings(self) -> Dict:
        """Get all AI settings."""
        return self.settings


# Example usage
if __name__ == "__main__":
    ai_settings = AISettings()

    # Print current threat detection parameters
    print("Current Threat Detection Parameters:", ai_settings.get_threat_detection_params())

    # Update threat detection parameters
    new_threat_params = {
        "sensitivity": 0.7,
        "model_type": "DeepLearning"
    }
    ai_settings.set_threat_detection_params(new_threat_params)
    print("Updated Threat Detection Parameters:", ai_settings.get_threat_detection_params())

    # Print current anomaly detection thresholds
    print("Current Anomaly Detection Thresholds:", ai_settings.get_anomaly_detection_thresholds())

    # Update anomaly detection thresholds
    new_anomaly_thresholds = {
        "threshold": 0.9,
        "algorithm": "IsolationForest"
    }
    ai_settings.set_anomaly_detection_thresholds(new_anomaly_thresholds)
    print("Updated Anomaly Detection Thresholds:", ai_settings.get_anomaly_detection_thresholds())

    # Print current behavior analysis configuration
    print("Current Behavior Analysis Configuration:", ai_settings.get_behavior_analysis_config())

    # Update behavior analysis configuration
    new_behavior_config = {
        "window_size": 15,
        "metric": "manhattan"
    }
    ai_settings.set_behavior_analysis_config(new_behavior_config)
    print("Updated Behavior Analysis Configuration:", ai_settings.get_behavior_analysis_config())

    # Print all settings
    print("All AI Settings:", ai_settings.get_all_settings())
