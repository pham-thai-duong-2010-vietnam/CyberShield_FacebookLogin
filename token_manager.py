import time
import threading

class TokenManager:
    def __init__(self):
        self.tokens = {}
        self.lock = threading.Lock()

    def add_token(self, token, access_token, expires_in):
        expiry_time = time.time() + expires_in
        with self.lock:
            self.tokens[token] = {
                'access_token': access_token,
                'expiry_time': expiry_time
            }

    def get_access_token(self, token):
        with self.lock:
            token_data = self.tokens.get(token)
            if token_data and self.is_token_valid(token):
                return token_data['access_token']
            else:
                return None

    def is_token_valid(self, token):
        with self.lock:
            token_data = self.tokens.get(token)
            if not token_data:
                return False
            return token_data['expiry_time'] > time.time()

    def remove_token(self, token):
        with self.lock:
            if token in self.tokens:
                del self.tokens[token]

    def cleanup_expired_tokens(self):
        with self.lock:
            expired_tokens = [t for t, data in self.tokens.items() if data['expiry_time'] <= time.time()]
            for t in expired_tokens:
                del self.tokens[t]
