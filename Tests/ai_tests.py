import unittest

from Config.ai_settings import AISettings
from Tests.integration_tests import AnomalyDetection, BehaviorAnalysis
from Src.Encryption.layers import ThreatDetection


class TestAI(unittest.TestCase):

    def setUp(self):
        """Set up the AI components and configurations for testing."""
        self.ai_settings = AISettings()
        self.threat_detection = ThreatDetection(self.ai_settings)
        self.anomaly_detection = AnomalyDetection(self.ai_settings)
        self.behavior_analysis = BehaviorAnalysis(self.ai_settings)
        self.sample_data = [
            {"timestamp": 1622471123, "value": 10},
            {"timestamp": 1622471183, "value": 20},
            {"timestamp": 1622471243, "value": 30},
            {"timestamp": 1622471303, "value": 40},
            {"timestamp": 1622471363, "value": 50}
        ]

    def test_threat_detection_initialization(self):
        """Test the initialization of the threat detection component."""
        self.assertIsInstance(self.threat_detection, ThreatDetection)
        self.assertEqual(self.threat_detection.sensitivity, self.ai_settings.get_threat_detection_params()["sensitivity"])
        self.assertEqual(self.threat_detection.model_type, self.ai_settings.get_threat_detection_params()["model_type"])

    def test_anomaly_detection_initialization(self):
        """Test the initialization of the anomaly detection component."""
        self.assertIsInstance(self.anomaly_detection, AnomalyDetection)
        self.assertEqual(self.anomaly_detection.threshold, self.ai_settings.get_anomaly_detection_thresholds()["threshold"])
        self.assertEqual(self.anomaly_detection.algorithm, self.ai_settings.get_anomaly_detection_thresholds()["algorithm"])

    def test_behavior_analysis_initialization(self):
        """Test the initialization of the behavior analysis component."""
        self.assertIsInstance(self.behavior_analysis, BehaviorAnalysis)
        self.assertEqual(self.behavior_analysis.window_size, self.ai_settings.get_behavior_analysis_config()["window_size"])
        self.assertEqual(self.behavior_analysis.metric, self.ai_settings.get_behavior_analysis_config()["metric"])

    def test_threat_detection_analysis(self):
        """Test the threat detection analysis functionality."""
        threat_detected = self.threat_detection.analyze(self.sample_data)
        self.assertIn(threat_detected, [True, False])

    def test_anomaly_detection_analysis(self):
        """Test the anomaly detection analysis functionality."""
        anomalies = self.anomaly_detection.analyze(self.sample_data)
        self.assertIsInstance(anomalies, list)
        for anomaly in anomalies:
            self.assertIn("timestamp", anomaly)
            self.assertIn("value", anomaly)

    def test_behavior_analysis_analysis(self):
        """Test the behavior analysis functionality."""
        behavior_report = self.behavior_analysis.analyze(self.sample_data)
        self.assertIsInstance(behavior_report, dict)
        self.assertIn("patterns", behavior_report)
        self.assertIn("anomalies", behavior_report)

    def test_ai_settings_loading(self):
        """Test loading of AI settings."""
        threat_params = self.ai_settings.get_threat_detection_params()
        anomaly_thresholds = self.ai_settings.get_anomaly_detection_thresholds()
        behavior_config = self.ai_settings.get_behavior_analysis_config()

        self.assertIn("sensitivity", threat_params)
        self.assertIn("model_type", threat_params)
        self.assertIn("threshold", anomaly_thresholds)
        self.assertIn("algorithm", anomaly_thresholds)
        self.assertIn("window_size", behavior_config)
        self.assertIn("metric", behavior_config)

    def test_ai_settings_saving(self):
        """Test saving of AI settings."""
        new_threat_params = {
            "sensitivity": 0.8,
            "model_type": "DeepLearning"
        }
        new_anomaly_thresholds = {
            "threshold": 0.9,
            "algorithm": "IsolationForest"
        }
        new_behavior_config = {
            "window_size": 20,
            "metric": "manhattan"
        }

        self.ai_settings.set_threat_detection_params(new_threat_params)
        self.ai_settings.set_anomaly_detection_thresholds(new_anomaly_thresholds)
        self.ai_settings.set_behavior_analysis_config(new_behavior_config)

        self.assertEqual(self.ai_settings.get_threat_detection_params(), new_threat_params)
        self.assertEqual(self.ai_settings.get_anomaly_detection_thresholds(), new_anomaly_thresholds)
        self.assertEqual(self.ai_settings.get_behavior_analysis_config(), new_behavior_config)

if __name__ == "__main__":
    unittest.main()
