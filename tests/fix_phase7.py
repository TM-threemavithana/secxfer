import re

# 1. Update client.py
with open('src/secxfer/client.py', 'r', encoding='utf-8') as f:
    client_content = f.read()

wipe_del = '''
    def __del__(self):
        try:
            self.identity.wipe()
        except Exception:
            pass

    async def upload_keys'''
client_content = client_content.replace('    async def upload_keys', wipe_del)

client_content = client_content.replace(
    'async def send_file(self, target_key_id: bytes, file_path: Path):',
    'async def send_file(self, target_key_id: bytes, file_path: Path, pqc_psk: str | None = None):'
)
client_content = client_content.replace(
    'await transfer.send(self.identity, target_pub, file_path, host, port)',
    'await transfer.send(self.identity, target_pub, file_path, host, port, pqc_psk=pqc_psk)'
)

client_content = client_content.replace(
    'async def receive_file(self, host: str, port: int, output_dir: Path):',
    'async def receive_file(self, host: str, port: int, output_dir: Path, pqc_psk: str | None = None):'
)
client_content = client_content.replace(
    'await transfer.receive(self.identity, self.keystore, host, port, output_dir)',
    'await transfer.receive(self.identity, self.keystore, host, port, output_dir, pqc_psk=pqc_psk)'
)

with open('src/secxfer/client.py', 'w', encoding='utf-8') as f:
    f.write(client_content)


# 2. Update transfer.py
with open('src/secxfer/transfer.py', 'r', encoding='utf-8') as f:
    t_content = f.read()

t_content = t_content.replace(
    'async def send(local_id, remote_pub: PeerPublicKey, file_path: Path, host: str, port: int) -> None:',
    'async def send(local_id, remote_pub: PeerPublicKey, file_path: Path, host: str, port: int, pqc_psk: str | None = None) -> None:'
)
t_content = t_content.replace(
    'stream_key = derive_stream_key(local_id.x25519_privkey, remote_pub.x25519, stream_salt)',
    'stream_key = derive_stream_key(local_id.x25519_privkey, remote_pub.x25519, stream_salt, pqc_psk=pqc_psk)'
)

t_content = t_content.replace(
    'async def receive(local_id, keystore, host: str, port: int, output_dir: Path) -> None:',
    'async def receive(local_id, keystore, host: str, port: int, output_dir: Path, pqc_psk: str | None = None) -> None:'
)
t_content = t_content.replace(
    'async def _process_payload(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:',
    'async def _process_payload(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, pqc_psk: str | None = None) -> None:'
)
t_content = t_content.replace(
    'await _process_payload(reader, writer)',
    'await _process_payload(reader, writer, pqc_psk)'
)
t_content = t_content.replace(
    'stream_key = derive_stream_key(local_id.x25519_privkey, sender_pub.x25519, stream_salt)',
    'stream_key = derive_stream_key(local_id.x25519_privkey, sender_pub.x25519, stream_salt, pqc_psk=pqc_psk)'
)

with open('src/secxfer/transfer.py', 'w', encoding='utf-8') as f:
    f.write(t_content)


# 3. Update cli.py
with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    c_content = f.read()

c_content = c_content.replace(
    'parser.add_argument("--tor", action="store_true", help="route server HTTP traffic through local Tor daemon (socks5://127.0.0.1:9050)")',
    'parser.add_argument("--tor", action="store_true", help="route server HTTP traffic through local Tor daemon (socks5://127.0.0.1:9050)")\n    parser.add_argument("--pqc-psk", help="Post-Quantum Pre-Shared Key (Hybrid KEM)")'
)

c_content = c_content.replace(
    'await client.send_file(target_key_id, Path(args.file))',
    'await client.send_file(target_key_id, Path(args.file), pqc_psk=args.pqc_psk)'
)
c_content = c_content.replace(
    'await client.receive_file(args.host, args.port, out_dir)',
    'await client.receive_file(args.host, args.port, out_dir, pqc_psk=args.pqc_psk)'
)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(c_content)
