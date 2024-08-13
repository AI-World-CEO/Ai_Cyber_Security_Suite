import os
import json
from typing import Dict, Any
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

from Src.Api.auth import UserAuth, AuthError
from Src.Api.data_access import DataAccess, DataAccessError
from Src.Encryption.key_management import KeyManager
from Src.Encryption.layers import LayeredEncryption
from Src.Utils.logger import setup_logger

# Initialize logger
logger = setup_logger("backend", "logs/backend.log")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Setup encryption and authentication systems
key_manager = KeyManager()
layered_encryption = LayeredEncryption(key_manager)
user_auth = UserAuth(key_manager)
data_access = DataAccess(layered_encryption, user_auth)


@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    try:
        data = request.json
        username = data['username']
        password = data['password']
        user_auth.create_user(username, password)
        return jsonify({"message": "User registered successfully."}), 201
    except AuthError as e:
        logger.error(f"Error registering user: {str(e)}")
        return jsonify({"error": str(e)}), 400


@app.route('/login', methods=['POST'])
def login():
    """Authenticate a user and obtain a token."""
    try:
        data = request.json
        username = data['username']
        password = data['password']
        if user_auth.authenticate_user(username, password):
            token = user_auth.generate_token(username)
            return jsonify({"token": token}), 200
        else:
            return jsonify({"error": "Authentication failed."}), 401
    except AuthError as e:
        logger.error(f"Error during authentication: {str(e)}")
        return jsonify({"error": str(e)}), 400


@app.route('/save_data', methods=['POST'])
def save_data():
    """Save data securely."""
    try:
        data = request.json
        token = request.headers.get('Authorization')
        data_content = data['data']
        filename = data['filename']
        data_access.save_data(data_content, filename, token)
        return jsonify({"message": f"Data saved to {filename}.enc successfully."}), 200
    except (DataAccessError, AuthError) as e:
        logger.error(f"Error saving data: {str(e)}")
        return jsonify({"error": str(e)}), 400


@app.route('/load_data', methods=['POST'])
def load_data():
    """Load data securely."""
    try:
        data = request.json
        token = request.headers.get('Authorization')
        filename = data['filename']
        loaded_data = data_access.load_data(filename, token)
        return jsonify({"data": loaded_data}), 200
    except (DataAccessError, AuthError) as e:
        logger.error(f"Error loading data: {str(e)}")
        return jsonify({"error": str(e)}), 400


@app.route('/delete_data', methods=['POST'])
def delete_data():
    """Delete data securely."""
    try:
        data = request.json
        token = request.headers.get('Authorization')
        filename = data['filename']
        data_access.delete_data(filename, token)
        return jsonify({"message": f"Data file {filename}.enc deleted successfully."}), 200
    except (DataAccessError, AuthError) as e:
        logger.error(f"Error deleting data: {str(e)}")
        return jsonify({"error": str(e)}), 400


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return make_response(jsonify({"error": "Not found"}), 404)


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(error)}")
    return make_response(jsonify({"error": "Internal server error"}), 500)


# Example usage
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
