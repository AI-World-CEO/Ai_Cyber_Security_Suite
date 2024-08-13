import os
import json
import requests
from getpass import getpass
from typing import Dict, Any

from Src.Api.auth import UserAuth, AuthError
from Src.Api.data_access import DataAccess, DataAccessError
from Src.Encryption.key_management import KeyManager
from Src.Encryption.layers import LayeredEncryption


class FrontendError(Exception):
    """Custom exception for frontend errors."""
    pass

class Frontend:
    """
    Class for managing the user interface for the Cyber_Ai_Security_Suite.
    Handles user interactions, authentication, and secure data access.
    """

    def __init__(self, auth_system: UserAuth, data_access_system: DataAccess):
        self.auth_system = auth_system
        self.data_access_system = data_access_system
        self.token = None

    def register_user(self):
        """Register a new user."""
        try:
            username = input("Enter username: ")
            password = getpass("Enter password: ")
            self.auth_system.create_user(username, password)
            print(f"User {username} registered successfully.")
        except AuthError as e:
            print(f"Error registering user: {str(e)}")

    def login(self):
        """Authenticate a user and obtain a token."""
        try:
            username = input("Enter username: ")
            password = getpass("Enter password: ")
            if self.auth_system.authenticate_user(username, password):
                self.token = self.auth_system.generate_token(username)
                print(f"User {username} authenticated successfully.")
            else:
                print("Authentication failed.")
        except AuthError as e:
            print(f"Error during authentication: {str(e)}")

    def save_data(self):
        """Save data securely."""
        try:
            if not self.token:
                raise FrontendError("User not authenticated. Please login first.")
            data = input("Enter data to save (JSON format): ")
            filename = input("Enter filename: ")
            data_dict = json.loads(data)
            self.data_access_system.save_data(data_dict, filename, self.token)
            print(f"Data saved to {filename}.enc successfully.")
        except (FrontendError, DataAccessError, json.JSONDecodeError) as e:
            print(f"Error saving data: {str(e)}")

    def load_data(self):
        """Load data securely."""
        try:
            if not self.token:
                raise FrontendError("User not authenticated. Please login first.")
            filename = input("Enter filename to load: ")
            data = self.data_access_system.load_data(filename, self.token)
            print(f"Data loaded from {filename}.enc: {json.dumps(data, indent=4)}")
        except (FrontendError, DataAccessError) as e:
            print(f"Error loading data: {str(e)}")

    def delete_data(self):
        """Delete data securely."""
        try:
            if not self.token:
                raise FrontendError("User not authenticated. Please login first.")
            filename = input("Enter filename to delete: ")
            self.data_access_system.delete_data(filename, self.token)
            print(f"Data file {filename}.enc deleted successfully.")
        except (FrontendError, DataAccessError) as e:
            print(f"Error deleting data: {str(e)}")

    def main_menu(self):
        """Display the main menu and handle user input."""
        while True:
            print("\nCyber Ai Security Suite")
            print("=======================")
            print("1. Register")
            print("2. Login")
            print("3. Save Data")
            print("4. Load Data")
            print("5. Delete Data")
            print("6. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                self.register_user()
            elif choice == "2":
                self.login()
            elif choice == "3":
                self.save_data()
            elif choice == "4":
                self.load_data()
            elif choice == "5":
                self.delete_data()
            elif choice == "6":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")

# Example usage
if __name__ == "__main__":
    key_manager = KeyManager()
    layered_encryption = LayeredEncryption(key_manager)
    user_auth = UserAuth(key_manager)
    data_access = DataAccess(layered_encryption, user_auth)
    frontend = Frontend(user_auth, data_access)
    frontend.main_menu()
