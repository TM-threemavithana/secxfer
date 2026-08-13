import logging
import secrets
import time
import httpx
import aiofiles
from pathlib import Path

from secxfer.constants import DEFAULT_TTL
from secxfer.crypto import CHUNK_SIZE
from secxfer.keystore import Keystore, load_identity, key_id_from_x25519_pubkey, UnknownSenderError, get_unused_prekeys
from secxfer.transfer import build_file_v2, decrypt_file_v2, decrypt_file_v2_from_path, NonceCache, ProtocolError
from secxfer.wire import PREAMBLE_SIZE_V2

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
        # httpx 0.28+ uses ``proxy`` (singular).  Do not pass a proxy setting
        # at all for direct connections.
        http_options = {"proxy": "socks5://127.0.0.1:9050"} if use_tor else {}
        self._http = httpx.AsyncClient(**http_options)
        
        self.identity_name = self.identity_path.stem
        
        if len(self.keystore) == 0:
            logger.warning(f"No .pub files found in {self.keystore_dir}. Transfers from any sender will be rejected.")

    def refresh_keystore(self):
        """Reload all .pub files from disk into the in-memory keystore."""
        self.keystore = Keystore.from_directory(self.keystore_dir)
        logger.info(f"Keystore refreshed: {len(self.keystore)} peer(s) loaded from {self.keystore_dir}")

    def _auth_headers(self, method: str, path: str, context: str = "") -> dict[str, str]:
        """Create a one-time Ed25519 proof bound to request metadata."""
        from nacl.signing import SigningKey
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        message = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{context}".encode("utf-8")
        signature = SigningKey(self.identity.ed25519_seed).sign(message).signature.hex()
        return {
            "X-Auth-Key-Id": self.identity.key_id.hex(),
            "X-Auth-Timestamp": timestamp,
            "X-Auth-Nonce": nonce,
            "X-Auth-Signature": signature,
        }

    @staticmethod
    def _payload_size(file_path: Path) -> int:
        """Return the exact wire size emitted by build_file_v2's default chunks."""
        file_size = file_path.stat().st_size
        metadata_size = 38 + len(file_path.name.encode("utf-8"))
        metadata_frame = 4 + metadata_size + 17
        trailer_frame = 4 + 64 + 17
        if file_size == 0:
            return 1 + PREAMBLE_SIZE_V2 + metadata_frame + trailer_frame
        full_chunks, remainder = divmod(file_size, CHUNK_SIZE)
        data_frame_size = full_chunks * (4 + CHUNK_SIZE + 17)
        if remainder:
            data_frame_size += 4 + remainder + 17
        return 1 + PREAMBLE_SIZE_V2 + metadata_frame + data_frame_size + trailer_frame

    async def send(
        self,
        receiver_name: str,
        file_path: Path | str,
        server_url: str,
        ttl_seconds: int = DEFAULT_TTL,
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
        try:
            path = f"/keys/{receiver_key_id.hex()}"
            response = await self._http.get(f"{server_url.rstrip('/')}{path}", headers=self._auth_headers("GET", path), timeout=10.0)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            raise ProtocolError(f"Failed to fetch keys for {receiver_name} from server: {exc}")

        server_ident_bytes = bytes.fromhex(data["identity_pubkey"])
        
        try:
            pinned_peer = self.keystore.get(receiver_key_id)
        except UnknownSenderError:
            raise ProtocolError(f"Receiver {receiver_name} is not loaded in Keystore!")
        
        if (pinned_peer.x25519 + pinned_peer.ed25519 + pinned_peer.kyber) != server_ident_bytes:
            raise ProtocolError(f"CRITICAL: Server returned a different identity key for {receiver_name} than your pinned version! MITM attack detected.")

        receiver_prekey_id = data["prekey"]["id"]
        receiver_prekey_pubkey = bytes.fromhex(data["prekey"]["pubkey"])

        payload_gen = build_file_v2(
            self.identity,
            receiver_key_id,
            receiver_prekey_id,
            receiver_prekey_pubkey,
            pinned_peer.kyber,
            file_path,
            ttl_seconds=ttl_seconds,
        )
        
        logger.info("Uploading encrypted chunks to server...")
        headers = {
            "X-Receiver-Key-Id": receiver_key_id.hex(),
            "X-Sender-Key-Id": self.identity.key_id.hex(),
            "X-Prekey-Id": receiver_prekey_id,  # server uses this to finally burn the prekey on upload
            "Content-Type": "application/octet-stream",
            "Content-Length": str(self._payload_size(file_path)),
        }
        context = f"{self.identity.key_id.hex()}\n{receiver_key_id.hex()}\n{receiver_prekey_id}\n{headers['Content-Length']}"
        headers.update(self._auth_headers("POST", "/upload", context))
        upload_resp = await self._http.post(
            f"{server_url.rstrip('/')}/upload",
            content=payload_gen,
            headers=headers,
            timeout=30.0
        )
        upload_resp.raise_for_status()
        logger.info("Upload complete!")

    async def check_inbox(self, server_url: str) -> list:
        """Polls the server for pending encrypted files."""
        path = f"/inbox/{self.identity.key_id.hex()}"
        response = await self._http.get(f"{server_url.rstrip('/')}{path}", headers=self._auth_headers("GET", path), timeout=10.0)
        response.raise_for_status()
        return response.json()['inbox']

    async def get_audit_log(self, server_url: str, limit: int = 100, offset: int = 0) -> list:
        path = f"/audit/log?limit={limit}&offset={offset}"
        response = await self._http.get(f"{server_url.rstrip('/')}{path}", headers=self._auth_headers("GET", "/audit/log"), timeout=10.0)
        response.raise_for_status()
        return response.json()["log"]

    async def download(
        self,
        file_id: int,
        server_url: str,
        dest_path: Path | str
    ) -> None:
        """Downloads and decrypts a pending file. Streams to a temp file to avoid OOM on large files."""
        logger.info(f"Downloading file {file_id} from {server_url}...")
        tmp_dir = self.keystore_dir / "tmp"
        tmp_dir.mkdir(exist_ok=True)
        tmp_path = tmp_dir / f"download_{file_id}.bin"

        try:
            path = f"/download/{file_id}"
            async with self._http.stream("GET", f"{server_url.rstrip('/')}{path}", headers=self._auth_headers("GET", path), timeout=None) as response:
                response.raise_for_status()
                async with aiofiles.open(tmp_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        await f.write(chunk)
            logger.info(f"Download complete. Decrypting from {tmp_path}...")
            decrypt_file_v2_from_path(
                self.identity,
                self.keystore,
                self.identity_path.parent,
                tmp_path,
                dest_path,
                self.nonce_cache,
                self.identity_name,
            )
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
        logger.info("Decryption complete!")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def aclose(self):
        """Async close — awaits httpx client shutdown. Use from async contexts (e.g. FastAPI shutdown)."""
        try:
            await self._http.aclose()
        except Exception:
            pass
        self.close()

    def close(self):
        """Sync close — wipes identity memory only. Does not close the httpx client."""
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
            "identity_pubkey": (self.identity.x25519_pubkey + self.identity.ed25519_pubkey + self.identity.kyber_pubkey).hex(),
            "prekeys": prekeys
        }

        try:
            challenge_resp = await self._http.get(f"{server_url.rstrip('/')}/challenge?key_id={self.identity.key_id.hex()}", timeout=10.0)
            challenge_resp.raise_for_status()
            challenge_data = challenge_resp.json()
            nonce_hex = challenge_data["nonce"]
        except Exception as exc:
            raise ProtocolError(f"Failed to fetch PoP challenge from server: {exc}")

        # Sign the nonce with Ed25519 seed (private key)
        from nacl.signing import SigningKey
        sk = SigningKey(self.identity.ed25519_seed)
        signature = sk.sign(bytes.fromhex(nonce_hex)).signature
            
        payload["challenge_nonce"] = nonce_hex
        payload["signature"] = signature.hex()

        try:
            reg_resp = await self._http.post(
                f"{server_url.rstrip('/')}/register", json=payload, timeout=10.0
            )
            reg_resp.raise_for_status()
            data = reg_resp.json()
            logger.info(f"Successfully registered keys to {server_url}. Added {data.get('prekeys_added')} prekeys.")
            return data
        except Exception as exc:
            raise ProtocolError(f"Failed to register keys to server: {exc}")
