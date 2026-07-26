import re

with open('src/secxfer/crypto.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add secure_wipe
wipe_code = '''
# ---------------------------------------------------------------------------
# Secure Memory Management
# ---------------------------------------------------------------------------
import ctypes
import sys

def secure_wipe(b: bytes) -> None:
    """
    Overwrites the memory of a bytes object with zeros.
    Uses ctypes to bypass Python's immutability guarantees.
    WARNING: Only use this on cryptographic keys that are no longer needed.
    """
    if not isinstance(b, bytes):
        return
    # CPython bytes object structure: 
    # PyObject_VAR_HEAD (24 bytes on 64-bit) + hash (8 bytes) = 32 bytes offset
    offset = 32 if sys.maxsize > 2**32 else 16
    buf_addr = id(b) + offset
    ctypes.memset(buf_addr, 0, len(b))
'''
content = content.replace('import hashlib', wipe_code + '\nimport hashlib')

# 2. Update derive_stream_key
derive_old = '''def derive_stream_key(
    local_privkey: bytes,
    remote_pubkey: bytes,
    stream_salt: bytes,
) -> bytes:'''
derive_new = '''def derive_stream_key(
    local_privkey: bytes,
    remote_pubkey: bytes,
    stream_salt: bytes,
    pqc_psk: str | None = None,
) -> bytes:'''
content = content.replace(derive_old, derive_new)

derive_logic_old = '''    shared_secret: bytes = _nb.crypto_scalarmult(local_privkey, remote_pubkey)
    return _hkdf_sha256(
        ikm=shared_secret,
        salt=stream_salt,
        info=b"secxfer-v1-stream",
        length=STREAM_KEY_SIZE,
    )'''
derive_logic_new = '''    shared_secret: bytes = _nb.crypto_scalarmult(local_privkey, remote_pubkey)
    if pqc_psk:
        # Mix the PQC-PSK into the shared secret to create a Hybrid KEM equivalent
        shared_secret = hashlib.sha256(shared_secret + pqc_psk.encode('utf-8')).digest()
        
    return _hkdf_sha256(
        ikm=shared_secret,
        salt=stream_salt,
        info=b"secxfer-v1-stream",
        length=STREAM_KEY_SIZE,
    )'''
content = content.replace(derive_logic_old, derive_logic_new)

with open('src/secxfer/crypto.py', 'w', encoding='utf-8') as f:
    f.write(content)


# 3. Update keystore.py
with open('src/secxfer/keystore.py', 'r', encoding='utf-8') as f:
    k_content = f.read()

wipe_method = '''    key_id: bytes           # 8 bytes — derived; included in wire preamble

    def wipe(self):
        """Securely zero out the private keys from RAM."""
        from secxfer.crypto import secure_wipe
        secure_wipe(self.x25519_privkey)
        secure_wipe(self.ed25519_seed)'''

k_content = k_content.replace('    key_id: bytes           # 8 bytes — derived; included in wire preamble', wipe_method)

with open('src/secxfer/keystore.py', 'w', encoding='utf-8') as f:
    f.write(k_content)
