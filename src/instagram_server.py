import secrets
import time
import sqlite3
import json

class InstagramServer:
    def __init__(self, db_path="sdi_l.db"):
        self.db_path = db_path
        self.user_devices = {}  # {user_id: [{'device_id': str, 'public_ver_key': int}, ...]}
        self.challenge_timestamps = {}
        self.active_sessions = {}
        self.TTL = 60
        self.SESSION_EXPIRY = 3600
        self._init_db()
        self._load_from_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_devices (
                user_id TEXT,
                device_id TEXT,
                public_ver_key TEXT,
                PRIMARY KEY (user_id, device_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                user_id TEXT PRIMARY KEY,
                token_json TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def _load_from_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT user_id, device_id, public_ver_key FROM user_devices')
        for row in cursor.fetchall():
            user_id, device_id, pub_key_str = row
            pub_key = int(pub_key_str)
            if user_id not in self.user_devices:
                self.user_devices[user_id] = []
            self.user_devices[user_id].append({'device_id': device_id, 'public_ver_key': pub_key})
        cursor.execute('SELECT user_id, token_json FROM active_sessions')
        for row in cursor.fetchall():
            user_id, token_json = row
            self.active_sessions[user_id] = json.loads(token_json)
        conn.close()
        print(f"Loaded {sum(len(devs) for devs in self.user_devices.values())} devices and {len(self.active_sessions)} sessions from DB.")

    def _save_to_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM user_devices')
        for user_id, devices in self.user_devices.items():
            for device in devices:
                pub_key_str = str(device['public_ver_key'])
                cursor.execute('INSERT INTO user_devices VALUES (?, ?, ?)',
                               (user_id, device['device_id'], pub_key_str))
        cursor.execute('DELETE FROM active_sessions')
        for user_id, token in self.active_sessions.items():
            cursor.execute('INSERT INTO active_sessions VALUES (?, ?)',
                           (user_id, json.dumps(token)))
        conn.commit()
        conn.close()

    def register_device(self, user_id, public_ver_key):
        if user_id not in self.user_devices:
            self.user_devices[user_id] = []
        device_id = secrets.token_hex(8)
        device = {'device_id': device_id, 'public_ver_key': public_ver_key}
        self.user_devices[user_id].append(device)
        print(f"Device {device_id[:4]}... registered for user {user_id} with public key {public_ver_key}.")
        print(f"Total devices for {user_id}: {len(self.user_devices[user_id])}")
        self._save_to_db()

    def get_registered_devices(self, user_id):
        if user_id not in self.user_devices:
            return []
        return [d['device_id'] for d in self.user_devices[user_id]]

    def generate_challenge(self, user_id):
        if user_id not in self.user_devices or not self.user_devices[user_id]:
            raise ValueError(f"No devices registered for {user_id}!")
        challenge = secrets.randbelow(2**256)
        timestamp = time.time()
        self.challenge_timestamps[user_id] = timestamp
        print(f"Challenge generated for {user_id}: {challenge} (public, disposable; issued at {timestamp:.0f}).")
        return challenge

    def verify_zkp_proof(self, user_id, challenge, proof):
        if user_id not in self.user_devices or not self.user_devices[user_id]:
            raise ValueError(f"No devices registered for {user_id}!")
        if user_id not in self.challenge_timestamps:
            raise ValueError(f"No active challenge for {user_id}!")
        
        p = 2**256 - 189
        verified_with_device = None
        
        for device in self.user_devices[user_id]:
            public_key = device['public_ver_key']
            expected_proof = pow(challenge, public_key, p)
            if proof == expected_proof:
                verified_with_device = device['device_id']
                break
        
        if verified_with_device is None:
            print(f"ZKP verification failed for {user_id} – Proof invalid (no matching device)!")
            return False, None
        
        issue_time = self.challenge_timestamps[user_id]
        current_time = time.time()
        if current_time - issue_time > self.TTL:
            print(f"ZKP verification failed for {user_id} – Proof expired (TTL exceeded: {current_time - issue_time:.1f}s > {self.TTL}s)!")
            del self.challenge_timestamps[user_id]
            return False, None
        
        token_id = secrets.token_hex(16)
        token = {
            'user_id': user_id,
            'token_id': token_id,
            'issued_at': current_time,
            'expires_at': current_time + self.SESSION_EXPIRY,
            'device_used': verified_with_device
        }
        self.active_sessions[user_id] = token
        print(f"ZKP verification success for {user_id} via device {verified_with_device[:4]}... – Access granted (within TTL: {current_time - issue_time:.1f}s)! Session token issued: {token_id[:8]}...")
        del self.challenge_timestamps[user_id]
        self._save_to_db()
        return True, token

    def revoke_session(self, user_id):
        if user_id in self.active_sessions:
            revoked_token = self.active_sessions[user_id]['token_id'][:8]
            del self.active_sessions[user_id]
            print(f"Session revoked for {user_id} – Token {revoked_token}... invalidated (logout complete)!")
            self._save_to_db()
            return True
        else:
            print(f"No active session to revoke for {user_id}!")
            return False

    def validate_session(self, user_id, token):
        if user_id not in self.active_sessions:
            print(f"Session validation failed for {user_id} – No active session (possibly revoked or expired)!")
            return False
        stored_token = self.active_sessions[user_id]
        current_time = time.time()
        if stored_token['expires_at'] < current_time:
            print(f"Session validation failed for {user_id} – Token expired ({current_time - stored_token['issued_at']:.0f}s ago)!")
            del self.active_sessions[user_id]
            self._save_to_db()
            return False
        print(f"Session validation success for {user_id} – Token valid (expires in {stored_token['expires_at'] - current_time:.0f}s; from device {stored_token['device_used'][:4]}...)!")
        return True

if __name__ == "__main__":
    server = InstagramServer()
    mock_public = 56789
    server.register_device("user123", mock_public)
    challenge = server.generate_challenge("user123")
    mock_proof = pow(challenge, mock_public, 2**256 - 189)
    verified, token = server.verify_zkp_proof("user123", challenge, mock_proof)
    if verified:
        print(f"Mock token: {token}")
        server.validate_session("user123", token)
        server.revoke_session("user123")