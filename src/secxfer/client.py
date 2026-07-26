import logging
import urllib.request
import json
from pathlib import Path
from typing import Optional
import sys
import asyncio

from secxfer.keystore import Keystore, load_identity, key_id_from_x25519_pubkey, UnknownSenderError, get_unused_prekeys
from secxfer.transfer import send_file_v1, send_file_v2, receive_file, NonceCache, ProtocolError, AsyncReader, AsyncWriter

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
        
        # Identity name is usually the stem of the identity file
        self.identity_name = self.identity_path.stem
        
        if len(self.keystore) == 0:
            logger.warning(f"No .pub files found in {self.keystore_dir}. Transfers from any sender will be rejected.")

    async def send(
        self,
        receiver_name: str,
        file_path: Path | str,
        out_stream: AsyncWriter,
        server_url: Optional[str] = None,
        ttl_seconds: int = 300,
    ) -> None:
        """
        Sends a file. If server_url is provided, uses V2 Forward Secrecy.
        Otherwise, receiver_name must be a path to a public key (V1).
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if server_url:
            # V2 (Server-Assisted / X3DH mode)
            pub_file = self.keystore_dir / f"{receiver_name}.pub"
            if not pub_file.exists():
                raise ProtocolError(f"Receiver {receiver_name} is not pinned! Run 'pin' first.")
            pinned_peer_bytes = pub_file.read_bytes()
            receiver_key_id = key_id_from_x25519_pubkey(pinned_peer_bytes[:32])

            logger.info(f"Using server-assisted V2 transfer via {server_url} to {receiver_name} ({receiver_key_id.hex()})")
            req = urllib.request.Request(server_url.rstrip("/") + "/keys/" + receiver_key_id.hex())

            def fetch_keys():
                with urllib.request.urlopen(req) as response:
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

            await send_file_v2(
                self.identity,
                receiver_key_id,
                receiver_prekey_id,
                receiver_prekey_pubkey,
                file_path,
                out_stream,
                ttl_seconds=ttl_seconds,
            )
        else:
            # V1 (P2P mode)
            logger.info(f"Using P2P V1 transfer to {receiver_name}")
            pub_path = Path(receiver_name)
            if not pub_path.exists():
                raise FileNotFoundError(f"Public key file not found: {pub_path}")

            pubkey_bytes = pub_path.read_bytes()
            if len(pubkey_bytes) != 64:
                raise ValueError("Public key file must be exactly 64 bytes (X25519 + Ed25519).")
            receiver_pubkey_x25519 = pubkey_bytes[:32]

            await send_file_v1(
                self.identity,
                receiver_pubkey_x25519,
                file_path,
                out_stream,
                ttl_seconds=ttl_seconds,
            )

    async def receive(
        self,
        inp_stream: AsyncReader,
        dest_path: Path | str,
    ) -> None:
        """
        Decrypt and verify a file from a binary stream.
        """
        dest_path = Path(dest_path)
        logger.info(f"Receiving transfer to {dest_path}")
        await receive_file(
            self.identity, 
            self.keystore, 
            self.identity_path.parent, 
            self.identity_name, 
            inp_stream, 
            dest_path, 
            self.nonce_cache
        )


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

        req = urllib.request.Request(
            server_url.rstrip("/") + "/upload",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )

        def do_upload():
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode())

        try:
            data = await asyncio.to_thread(do_upload)
            logger.info(f"Successfully uploaded keys to {server_url}. Added {data.get('prekeys_added')} prekeys.")
            return data
        except Exception as exc:
            raise ProtocolError(f"Failed to upload keys to server: {exc}")
