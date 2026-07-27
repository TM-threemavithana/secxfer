import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

DB_PATH = "secxfer_server.db"
DB_LOCK = threading.Lock()

# In-memory challenge store: {key_id_hex: (nonce_hex, expires_at)}
_CHALLENGES: dict = {}
_CHALLENGE_LOCK = threading.Lock()
_CHALLENGE_TTL = 300  # 5 minutes


def _issue_challenge(key_id_hex: str) -> str:
    """Generate a fresh 32-byte random nonce for a given key_id."""
    nonce = secrets.token_bytes(32).hex()
    expiry = time.time() + _CHALLENGE_TTL
    with _CHALLENGE_LOCK:
        _CHALLENGES[key_id_hex] = (nonce, expiry)
    return nonce


def _consume_challenge(key_id_hex: str):
    """Return and delete the pending challenge, or None if expired/missing."""
    now = time.time()
    with _CHALLENGE_LOCK:
        entry = _CHALLENGES.pop(key_id_hex, None)
    if entry is None:
        return None
    nonce, expiry = entry
    return None if now > expiry else nonce


def _verify_pop(identity_pubkey_hex: str, nonce_hex: str, signature_hex: str) -> bool:
    """
    Verify proof-of-possession. The client must have signed the nonce
    bytes with their Ed25519 private key.
    """
    try:
        pubkey_bytes = bytes.fromhex(identity_pubkey_hex)
        if len(pubkey_bytes) != 64:
            return False
        ed25519_pubkey = pubkey_bytes[32:]   # second 32 bytes are Ed25519
        nonce_bytes = bytes.fromhex(nonce_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        VerifyKey(ed25519_pubkey).verify(nonce_bytes, sig_bytes)
        return True
    except Exception:
        return False


def init_db():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                identity_pubkey TEXT NOT NULL,
                registered_at REAL NOT NULL
            )"""
        )
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                prekey_id TEXT NOT NULL,
                prekey_pubkey TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )"""
        )
        conn.commit()
        conn.close()

class KDCRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress noisy default access log

    def _send_json(self, status_code, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status_code, message):
        self._send_json(status_code, {"error": message})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == '/challenge':
            params = urllib.parse.parse_qs(parsed.query)
            key_id = params.get('key_id', [None])[0]
            if not key_id:
                self._send_error(400, "key_id query parameter required")
                return
            nonce = _issue_challenge(key_id)
            self._send_json(200, {"nonce": nonce})

        elif parsed.path.startswith('/keys/'):
            key_id = urllib.parse.unquote(parsed.path[len('/keys/'):])
            if not key_id:
                self._send_error(400, "key_id required")
                return
            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        'SELECT id, identity_pubkey FROM users WHERE key_id = ?', (key_id,)
                    )
                    user_row = cursor.fetchone()
                    if not user_row:
                        self._send_error(404, "User not found")
                        return
                    user_id, identity_pubkey = user_row
                    cursor.execute(
                        'SELECT COUNT(*) FROM prekeys WHERE user_id = ? AND used = 0', (user_id,)
                    )
                    count = cursor.fetchone()[0]
                    if count == 0:
                        self._send_error(404, "Pre-keys exhausted. User must re-register.")
                        return

                    cursor.execute(
                        'SELECT id, prekey_id, prekey_pubkey FROM prekeys '
                        'WHERE user_id = ? AND used = 0 LIMIT 1', (user_id,)
                    )
                    pk_db_id, prekey_id, prekey_pubkey = cursor.fetchone()
                    
                    if count > 1:
                        cursor.execute('UPDATE prekeys SET used = 1 WHERE id = ?', (pk_db_id,))
                        conn.commit()

                    self._send_json(200, {
                        "identity_pubkey": identity_pubkey,
                        "prekey": {"id": prekey_id, "pubkey": prekey_pubkey}
                    })
                except sqlite3.Error as e:
                    conn.rollback()
                    self._send_error(500, f"Database error: {str(e)}")
                finally:
                    conn.close()
        else:
            self._send_error(404, "Not Found")

    def do_POST(self):
        if self.path != '/register':
            self._send_error(404, "Not Found")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self._send_error(400, "Empty body")
            return

        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
            key_id          = data['key_id']
            identity_pubkey = data['identity_pubkey']
            prekeys         = data['prekeys']
            challenge_nonce = data['challenge_nonce']
            signature       = data['signature']
        except (json.JSONDecodeError, KeyError) as exc:
            self._send_error(400, f"Invalid JSON payload: {exc}")
            return

        # C5: Verify proof-of-possession before touching the database
        pending_nonce = _consume_challenge(key_id)
        if pending_nonce is None:
            self._send_error(401, "No valid challenge. Call GET /challenge?key_id=... first.")
            return
        if pending_nonce != challenge_nonce:
            self._send_error(401, "Challenge nonce mismatch.")
            return
        if not _verify_pop(identity_pubkey, challenge_nonce, signature):
            self._send_error(401, "Proof-of-possession signature verification failed.")
            return

        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            try:
                cursor.execute('SELECT id FROM users WHERE key_id = ?', (key_id,))
                row = cursor.fetchone()
                if row:
                    user_id = row[0]
                    cursor.execute(
                        'UPDATE users SET identity_pubkey = ?, registered_at = ? WHERE id = ?',
                        (identity_pubkey, time.time(), user_id)
                    )
                else:
                    cursor.execute(
                        'INSERT INTO users (key_id, identity_pubkey, registered_at) VALUES (?, ?, ?)',
                        (key_id, identity_pubkey, time.time())
                    )
                    user_id = cursor.lastrowid
                for pk in prekeys:
                    cursor.execute(
                        'INSERT INTO prekeys (user_id, prekey_id, prekey_pubkey, used) VALUES (?, ?, ?, 0)',
                        (user_id, pk['id'], pk['pubkey'])
                    )
                conn.commit()
                self._send_json(200, {"status": "registered", "prekeys_added": len(prekeys)})
            except sqlite3.Error as e:
                conn.rollback()
                self._send_error(500, f"Database error: {str(e)}")
            finally:
                conn.close()


def serve(port=54321):
    init_db()
    httpd = HTTPServer(('', port), KDCRequestHandler)
    print(f"[*] Key Distribution Center (with PoP auth) running on port {port}...")
    httpd.serve_forever()


if __name__ == '__main__':
    serve()
