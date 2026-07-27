import logging
import urllib.request
import json
from pathlib import Path
from typing import Optional
import sys
import asyncio

from secxfer.keystore import Keystore, load_identity, key_id_from_x25519_pubkey, UnknownSenderError, get_unused_prekeys
from secxfer.transfer import build_file_v2, decrypt_file_v2, NonceCache, ProtocolError

logger = logging.getLogger(__name__)

class SecXferClient:
    """
    SDK wrapper for the secxfer file transfer protocol.
    Maintains identity, keystore, and nonce cache state.
    """

    def __init__(self, identity_path: str | Path, keystore_dir: str | Path, password: str | None = None, use_tor: bool = False):
        self.identity_path = Path(identity_path)
        self.keystore_dir = Path(keystore_dir)
        self.identity = load_identity(self.identity_path, password)
        self.keystore = Keystore.from_directory(self.keystore_dir)
        self.nonce_cache = NonceCache(db_path=self.keystore_dir / "nonces.db")
        self.http_proxy = "socks5://127.0.0.1:9050" if use_tor else None
        
        self.identity_name = self.identity_path.stem
        
        if len(self.keystore) == 0:
            logger.warning(f"No .pub files found in {self.keystore_dir}. Transfers from any sender will be rejected.")

    def refresh_keystore(self):
        """Reload all .pub files from disk into the in-memory keystore."""
        self.keystore = Keystore.from_directory(self.keystore_dir)
        logger.info(f"Keystore refreshed: {len(self.keystore)} peer(s) loaded from {self.keystore_dir}")

    async def send(
        self,
        receiver_name: str,
        file_path: Path | str,
        server_url: str,
        ttl_seconds: int = 300,
        pqc_psk: Optional[str] = None,
    ) -> None:
        """
        Sends an encrypted file to the central server (Store-and-Forward).
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        pub_file = self.keystore_dir / f"{receiver_name}.pub"
        if not pub_file.exists():
            raise ProtocolError(f"Receiver {receiver_name} is not pinned! Run 'pin' first.")
            
        pinned_peer_bytes = pub_file.read_bytes()
        receiver_key_id = key_id_from_x25519_pubkey(pinned_peer_bytes[:32])

        logger.info(f"Fetching Pre-Keys from {server_url} for {receiver_name} ({receiver_key_id.hex()})")
        req = urllib.request.Request(server_url.rstrip("/") + "/keys/" + receiver_key_id.hex())

        def fetch_keys():
            with urllib.request.urlopen(req, timeout=10.0) as response:
                return json.loads(response.read().decode())

        try:
            data = await asyncio.to_thread(fetch_keys)
        except Exception as exc:
            raise ProtocolError(f"Failed to fetch keys for {receiver_name} from server: {exc}")

        server_ident_bytes = bytes.fromhex(data["identity_pubkey"])
        
        try:
            pinned_peer = self.keystore.get(receiver_key_id)
        except UnknownSenderError:
            raise ProtocolError(f"Receiver {receiver_name} is not loaded in Keystore!")
        
        if (pinned_peer.x25519 + pinned_peer.ed25519) != server_ident_bytes:
            raise ProtocolError(f"CRITICAL: Server returned a different identity key for {receiver_name} than your pinned version! MITM attack detected.")

        receiver_prekey_id = data["prekey"]["id"]
        receiver_prekey_pubkey = bytes.fromhex(data["prekey"]["pubkey"])

        payload = build_file_v2(
            self.identity,
            receiver_key_id,
            receiver_prekey_id,
            receiver_prekey_pubkey,
            file_path,
            ttl_seconds=ttl_seconds,
            pqc_psk=pqc_psk,
        )
        
        logger.info(f"Uploading {len(payload)} encrypted bytes to server...")
        upload_req = urllib.request.Request(server_url.rstrip("/") + "/upload", data=payload, method="POST")
        upload_req.add_header("X-Receiver-Key-Id", receiver_key_id.hex())
        upload_req.add_header("X-Sender-Key-Id", self.identity.key_id.hex())
        upload_req.add_header("Content-Type", "application/octet-stream")
        
        def do_upload():
            with urllib.request.urlopen(upload_req, timeout=30.0) as resp:
                return resp.read()
                
        await asyncio.to_thread(do_upload)
        logger.info("Upload complete!")

    async def check_inbox(self, server_url: str) -> list:
        """Polls the server for pending encrypted files."""
        req = urllib.request.Request(server_url.rstrip("/") + "/inbox/" + self.identity.key_id.hex())
        def fetch():
            with urllib.request.urlopen(req, timeout=10.0) as response:
                return json.loads(response.read().decode())['inbox']
        return await asyncio.to_thread(fetch)

    async def download(
        self,
        file_id: int,
        server_url: str,
        dest_path: Path | str,
        pqc_psk: Optional[str] = None
    ) -> None:
        """Downloads and decrypts a pending file."""
        logger.info(f"Downloading file {file_id} from {server_url}...")
        req = urllib.request.Request(server_url.rstrip("/") + f"/download/{file_id}")
        def fetch():
            with urllib.request.urlopen(req, timeout=30.0) as response:
                return response.read()
        
        ciphertext = await asyncio.to_thread(fetch)
        logger.info(f"Downloaded {len(ciphertext)} bytes. Decrypting...")
        
        decrypt_file_v2(
            self.identity,
            self.keystore,
            self.identity_path.parent,
            ciphertext,
            dest_path,
            self.nonce_cache,
            pqc_psk=pqc_psk
        )
        logger.info("Decryption complete!")

    def __del__(self):
        try:
            self.identity.wipe()
        except Exception:
            pass

    async def upload_keys(self, server_url: str) -> dict:
        """
        Upload the local identity and unused prekeys to the central key directory.
        """
        prekeys = get_unused_prekeys(self.identity_path.parent, self.identity_name)
        if not prekeys:
            logger.warning("No unused prekeys found to upload. Run keygen again to generate more.")
            return {"prekeys_added": 0}

        payload = {
            "key_id": self.identity.key_id.hex(),
            "identity_pubkey": (self.identity.x25519_pubkey + self.identity.ed25519_pubkey).hex(),
            "prekeys": prekeys
        }

        def fetch_challenge():
            req = urllib.request.Request(server_url.rstrip("/") + f"/challenge?key_id={self.identity.key_id.hex()}")
            with urllib.request.urlopen(req, timeout=10.0) as response:
                return json.loads(response.read().decode())

        try:
            challenge_data = await asyncio.to_thread(fetch_challenge)
            nonce_hex = challenge_data["nonce"]
        except Exception as exc:
            raise ProtocolError(f"Failed to fetch PoP challenge from server: {exc}")

        # Sign the nonce with Ed25519 seed (private key)
        from nacl.signing import SigningKey
        sk = SigningKey(self.identity.ed25519_seed)
        signature = sk.sign(bytes.fromhex(nonce_hex)).signature
        
        payload["challenge_nonce"] = nonce_hex
        payload["signature"] = signature.hex()

        req = urllib.request.Request(
            server_url.rstrip("/") + "/register",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )

        def do_upload():
            with urllib.request.urlopen(req, timeout=10.0) as response:
                return json.loads(response.read().decode())

        try:
            data = await asyncio.to_thread(do_upload)
            logger.info(f"Successfully registered keys to {server_url}. Added {data.get('prekeys_added')} prekeys.")
            return data
        except Exception as exc:
            raise ProtocolError(f"Failed to register keys to server: {exc}")
