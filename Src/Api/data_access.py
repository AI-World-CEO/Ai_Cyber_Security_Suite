import json
import os
from typing import Any

from Src.Api.auth import UserAuth, AuthError
from Src.Encryption.layers import LayeredEncryption
from Src.Utils.logger import setup_logger

# Initialize logger
logger = setup_logger("data_access", "logs/data_access.log")


class DataAccessError(Exception):
    """Custom exception for data access errors."""
    pass


class DataAccess:
    """
    Class for managing secure data access.
    Uses layered encryption for data protection and JWT for user authentication.
    """

    def __init__(self, encryption_system: LayeredEncryption, auth_system: UserAuth):
        self.encryption_system = encryption_system
        self.auth_system = auth_system
        self.data_directory = "data/encrypted"
        os.makedirs(self.data_directory, exist_ok=True)

    def save_data(self, data: Any, filename: str, token: str):
        """
        Save data securely to a file.
        Data is encrypted before being saved.
        """
        try:
            # Verify the token
            payload = self.auth_system.verify_token(token)
            user = payload['username']

            # Serialize the data
            serialized_data = json.dumps(data).encode()

            # Encrypt the data
            encrypted_data = self.encryption_system.encrypt(serialized_data)

            # Save the encrypted data to a file
            filepath = os.path.join(self.data_directory, f"{filename}.enc")
            with open(filepath, 'wb') as file:
                file.write(encrypted_data)

            logger.info(f"Data saved by user {user} to file {filename}.enc")
        except (AuthError, Exception) as e:
            logger.error(f"Error saving data: {str(e)}")
            raise DataAccessError(f"Error saving data: {str(e)}")

    def load_data(self, filename: str, token: str) -> Any:
        """
        Load data securely from a file.
        Data is decrypted after being loaded.
        """
        try:
            # Verify the token
            payload = self.auth_system.verify_token(token)
            user = payload['username']

            # Load the encrypted data from the file
            filepath = os.path.join(self.data_directory, f"{filename}.enc")
            with open(filepath, 'rb') as file:
                encrypted_data = file.read()

            # Decrypt the data
            decrypted_data = self.encryption_system.decrypt(encrypted_data)

            # Deserialize the data
            data = json.loads(decrypted_data)

            logger.info(f"Data loaded by user {user} from file {filename}.enc")
            return data
        except (AuthError, Exception) as e:
            logger.error(f"Error loading data: {str(e)}")
            raise DataAccessError(f"Error loading data: {str(e)}")

    def delete_data(self, filename: str, token: str):
        """
        Delete a data file securely.
        """
        try:
            # Verify the token
            payload = self.auth_system.verify_token(token)
            user = payload['username']

            # Delete the file
            filepath = os.path.join(self.data_directory, f"{filename}.enc")
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.info(f"Data file {filename}.enc deleted by user {user}.")
            else:
                logger.warning(f"Data file {filename}.enc not found for deletion by user {user}.")
                raise DataAccessError(f"File {filename}.enc not found.")
        except (AuthError, Exception) as e:
            logger.error(f"Error deleting data: {str(e)}")
            raise DataAccessError(f"Error deleting data: {str(e)}")


# Example usage
if __name__ == "__main__":
    from Src.Encryption.key_management import KeyManager

    key_manager = KeyManager()
    layered_encryption = LayeredEncryption(key_manager)
    user_auth = UserAuth(key_manager)

    # Create a new user
    user_auth.create_user("test_user", "secure_password")

    # Authenticate the user
    if user_auth.authenticate_user("test_user", "secure_password"):
        # Generate a token for the user
        token = user_auth.generate_token("test_user")
        print(f"Generated Token: {token}")

        data_access = DataAccess(layered_encryption, user_auth)

        # Save data
        data = {"key": "value"}
        data_access.save_data(data, "test_data", token)

        # Load data
        loaded_data = data_access.load_data("test_data", token)
        print(f"Loaded Data: {loaded_data}")

        # Delete data
        data_access.delete_data("test_data", token)
