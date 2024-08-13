import unittest
import json

from Config.ai_settings import AISettings
from Config.encryption_settings import EncryptionSettings
from Tests.integration_tests import AuthAPI, DataAccessAPI


class TestAPI(unittest.TestCase):

    def setUp(self):
        """Set up the API components and configurations for testing."""
        self.auth_api = AuthAPI()
        self.data_access_api = DataAccessAPI()
        self.ai_settings = AISettings()
        self.encryption_settings = EncryptionSettings()
        self.user_credentials = {
            "username": "test_user",
            "password": "test_password"
        }
        self.auth_token = None

    def test_user_registration(self):
        """Test user registration API."""
        response = self.auth_api.register(self.user_credentials)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json().get("message"), "User registered successfully")

    def test_user_login(self):
        """Test user login API."""
        self.auth_api.register(self.user_credentials)  # Ensure user is registered first
        response = self.auth_api.login(self.user_credentials)
        self.assertEqual(response.status_code, 200)
        self.auth_token = response.json().get("token")
        self.assertIsNotNone(self.auth_token)

    def test_user_login_invalid_credentials(self):
        """Test user login with invalid credentials."""
        invalid_credentials = {
            "username": "invalid_user",
            "password": "invalid_password"
        }
        response = self.auth_api.login(invalid_credentials)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json().get("message"), "Invalid credentials")

    def test_data_access_with_auth(self):
        """Test data access API with authentication."""
        self.auth_api.register(self.user_credentials)
        response = self.auth_api.login(self.user_credentials)
        self.auth_token = response.json().get("token")

        headers = {"Authorization": f"Bearer {self.auth_token}"}
        response = self.data_access_api.get_data(headers)
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), dict)

    def test_data_access_without_auth(self):
        """Test data access API without authentication."""
        response = self.data_access_api.get_data()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json().get("message"), "Authentication required")

    def test_ai_settings_loading(self):
        """Test loading of AI settings via API."""
        response = self.ai_settings.load_settings()
        self.assertIsInstance(response, dict)
        self.assertIn("threat_detection_params", response)
        self.assertIn("anomaly_detection_thresholds", response)
        self.assertIn("behavior_analysis_config", response)

    def test_encryption_settings_loading(self):
        """Test loading of encryption settings via API."""
        response = self.encryption_settings.load_settings()
        self.assertIsInstance(response, dict)
        self.assertIn("kdf_params", response)
        self.assertIn("encryption_algorithm", response)
        self.assertIn("rotation_policy", response)

    def test_encryption_settings_saving(self):
        """Test saving of encryption settings via API."""
        new_encryption_settings = {
            "kdf_params": {
                "algorithm": "SHA512",
                "length": 64,
                "salt_length": 32,
                "iterations": 200000
            },
            "encryption_algorithm": "AES256",
            "rotation_policy": {
                "interval": 7200,  # 2 hours
                "immediate_rotation_on_threat": True
            }
        }
        response = self.encryption_settings.save_settings(new_encryption_settings)
        self.assertIsInstance(response, dict)
        self.assertEqual(response, new_encryption_settings)


if __name__ == "__main__":
    unittest.main()
