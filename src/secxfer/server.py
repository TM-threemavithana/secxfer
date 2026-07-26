import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import os

DB_PATH = "secxfer_server.db"
DB_LOCK = threading.Lock()

def init_db():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                identity_pubkey TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                prekey_id TEXT NOT NULL,
                prekey_pubkey TEXT NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
        conn.close()

class KDCRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _send_error(self, status_code, message):
        self._send_json(status_code, {"error": message})

    def do_POST(self):
        if self.path == '/register':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self._send_error(400, "Empty body")
                return

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                name = data['name']
                identity_pubkey = data['identity_pubkey']
                prekeys = data['prekeys']
            except (json.JSONDecodeError, KeyError):
                self._send_error(400, "Invalid JSON payload")
                return

            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                try:
                    # Upsert user
                    cursor.execute('SELECT id FROM users WHERE name = ?', (name,))
                    row = cursor.fetchone()
                    if row:
                        user_id = row[0]
                        cursor.execute('UPDATE users SET identity_pubkey = ? WHERE id = ?', (identity_pubkey, user_id))
                    else:
                        cursor.execute('INSERT INTO users (name, identity_pubkey) VALUES (?, ?)', (name, identity_pubkey))
                        user_id = cursor.lastrowid

                    # Insert prekeys
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
        else:
            self._send_error(404, "Not Found")

    def do_GET(self):
        if self.path.startswith('/keys/'):
            name = urllib.parse.unquote(self.path[len('/keys/'):])
            if not name:
                self._send_error(400, "Name required")
                return

            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                try:
                    cursor.execute('SELECT id, identity_pubkey FROM users WHERE name = ?', (name,))
                    user_row = cursor.fetchone()
                    if not user_row:
                        self._send_error(404, "User not found")
                        return

                    user_id, identity_pubkey = user_row

                    # Atomically fetch and mark one prekey as used
                    cursor.execute('''
                        SELECT id, prekey_id, prekey_pubkey FROM prekeys 
                        WHERE user_id = ? AND used = 0 LIMIT 1
                    ''', (user_id,))
                    pk_row = cursor.fetchone()

                    if not pk_row:
                        self._send_error(404, "Pre-keys exhausted. User must re-register.")
                        return

                    pk_db_id, prekey_id, prekey_pubkey = pk_row

                    cursor.execute('UPDATE prekeys SET used = 1 WHERE id = ?', (pk_db_id,))
                    conn.commit()

                    self._send_json(200, {
                        "identity_pubkey": identity_pubkey,
                        "prekey": {
                            "id": prekey_id,
                            "pubkey": prekey_pubkey
                        }
                    })
                except sqlite3.Error as e:
                    conn.rollback()
                    self._send_error(500, f"Database error: {str(e)}")
                finally:
                    conn.close()
        else:
            self._send_error(404, "Not Found")


def serve(port=54321):
    init_db()
    server_address = ('', port)
    httpd = HTTPServer(server_address, KDCRequestHandler)
    print(f"Key Distribution Center running on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    serve()
