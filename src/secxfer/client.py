import logging
import httpx
import aiofiles
from pathlib import Path
from typing import Optional

from secxfer.keystore import Keystore, load_identity, key_id_from_x25519_pubkey, UnknownSenderError, get_unused_prekeys
from secxfer.transfer import build_file_v2, decrypt_file_v2, decrypt_file_v2_from_path, NonceCache, ProtocolError

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
        proxy = "socks5://127.0.0.1:9050" if use_tor else None
        # Shared client: enables TCP connection reuse (HTTP keep-alive) across all API calls
        self._http = httpx.AsyncClient(proxies=proxy)
        
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
            response = await self._http.get(f"{server_url.rstrip('/')}/keys/{receiver_key_id.hex()}", timeout=10.0)
            response.raise_for_status()
            data = response.json()
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
            "Content-Type": "application/octet-stream"
        }
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
        response = await self._http.get(f"{server_url.rstrip('/')}/inbox/{self.identity.key_id.hex()}", timeout=10.0)
        response.raise_for_status()
        return response.json()['inbox']

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
            async with self._http.stream("GET", f"{server_url.rstrip('/')}/download/{file_id}", timeout=None) as response:
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
                self.nonce_cache
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
            "identity_pubkey": (self.identity.x25519_pubkey + self.identity.ed25519_pubkey).hex(),
            "prekeys": prekeys
        }

        async with self._http as http:
            try:
                challenge_resp = await http.get(f"{server_url.rstrip('/')}/challenge?key_id={self.identity.key_id.hex()}", timeout=10.0)
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
                reg_resp = await http.post(
                    f"{server_url.rstrip('/')}/register",
                    json=payload,
                    timeout=10.0
                )
                reg_resp.raise_for_status()
                data = reg_resp.json()
                logger.info(f"Successfully registered keys to {server_url}. Added {data.get('prekeys_added')} prekeys.")
                return data
            except Exception as exc:
                raise ProtocolError(f"Failed to register keys to server: {exc}")
