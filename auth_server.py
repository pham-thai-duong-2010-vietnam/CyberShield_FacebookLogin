from flask import Flask, request, jsonify, redirect
import uuid
import hashlib
import requests
import os
import logging

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# Simple in-memory user store: username -> hashed_password
users = {
    "user@example.com": hashlib.sha256("password123".encode()).hexdigest()
}

# Simple in-memory token store: token -> username
tokens = {}

# Facebook OAuth tokens store: token -> access_token
import time
from token_manager import TokenManager
import threading

token_manager = TokenManager()

APP_ID = '4008445182755966'
APP_SECRET = '0f4b52d8f16050984e35f79a41dba7bc'
REDIRECT_URI = 'http://localhost:5000/callback'

# Store OAuth states to prevent CSRF attacks
oauth_states = set()
oauth_states_lock = threading.Lock()

def verify_password(stored_password_hash, provided_password):
    return stored_password_hash == hashlib.sha256(provided_password.encode()).hexdigest()

@app.route('/app_login', methods=['POST'])
def app_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    stored_password_hash = users.get(username)
    if not stored_password_hash or not verify_password(stored_password_hash, password):
        return jsonify({"error": "Invalid username or password"}), 401
    token = str(uuid.uuid4())
    tokens[token] = username
    return jsonify({"token": token})

@app.route('/validate_token', methods=['POST'])
def validate_token():
    data = request.json
    token = data.get('token')
    if token in tokens:
        return jsonify({"valid": True, "username": tokens[token]})
    else:
        return jsonify({"valid": False}), 401

import secrets

@app.route('/login', methods=['GET'])
def login_redirect():
    import secrets
    state = secrets.token_urlsafe(16)
    with oauth_states_lock:
        oauth_states.add(state)
    fb_auth_url = f"https://www.facebook.com/v18.0/dialog/oauth?client_id={APP_ID}&redirect_uri={REDIRECT_URI}&state={state}&scope=email,public_profile,user_posts"
    return redirect(fb_auth_url)

@app.route('/facebook/login')
def facebook_login():
    state = secrets.token_urlsafe(16)
    with oauth_states_lock:
        oauth_states.add(state)
    fb_auth_url = f"https://www.facebook.com/v18.0/dialog/oauth?client_id={APP_ID}&redirect_uri={REDIRECT_URI}&state={state}&scope=email,public_profile,user_posts"
    return redirect(fb_auth_url)

@app.route('/callback')
def facebook_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        return "Error: Missing code or state", 400
    with oauth_states_lock:
        if state not in oauth_states:
            return "Error: Invalid state parameter", 400
        oauth_states.remove(state)
    token_url = f"https://graph.facebook.com/v18.0/oauth/access_token?client_id={APP_ID}&redirect_uri={REDIRECT_URI}&client_secret={APP_SECRET}&code={code}"
    token_res = requests.get(token_url).json()
    access_token = token_res.get("access_token")
    expires_in = token_res.get("expires_in", 3600)
    if not access_token:
        return "Error: Failed to get access token", 400

    dummy_token = str(uuid.uuid4())
    token_manager.add_token(dummy_token, access_token, expires_in)

    app.logger.info(f"New Facebook token added for dummy_token: {dummy_token}")

    # Redirect to a safer page with token in query param (better than returning token in body)
    return redirect(f"/success?token={dummy_token}")

@app.route('/success')
def login_success():
    token = request.args.get("token")
    return f"Facebook login successful. Your token is: {token}"

# Token cleanup thread to remove expired tokens periodically
def token_cleanup_worker():
    while True:
        time.sleep(3600)  # Run cleanup every hour
        token_manager.cleanup_expired_tokens()
        app.logger.info("Expired tokens cleaned up.")

cleanup_thread = threading.Thread(target=token_cleanup_worker, daemon=True)
cleanup_thread.start()

@app.route('/facebook/token/<token>')
def get_facebook_token(token):
    access_token = token_manager.get_access_token(token)
    if access_token:
        return jsonify({"access_token": access_token})
    else:
        app.logger.warning(f"Token {token} not found or expired")
        return jsonify({"error": "Invalid or expired token"}), 401

@app.route('/facebook/logout/<token>', methods=['POST'])
def facebook_logout(token):
    if token_manager.is_token_valid(token):
        token_manager.remove_token(token)
        return jsonify({"message": "Logged out successfully"})
    else:
        return jsonify({"error": "Invalid token"}), 404

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    # Run with debug=False in production
    app.run(port=5000, debug=False)
