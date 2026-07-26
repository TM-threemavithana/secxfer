import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add --tor to main parser
content = content.replace('parser.add_argument("--debug", action="store_true", help="enable debug logging")', 'parser.add_argument("--debug", action="store_true", help="enable debug logging")\n    parser.add_argument("--tor", action="store_true", help="route server HTTP traffic through local Tor daemon (socks5://127.0.0.1:9050)")')

# Update _get_client helper
helper_old = '''def _get_client(identity_path: str, keystore_dir: str) -> 'SecXferClient':'''
helper_new = '''def _get_client(identity_path: str, keystore_dir: str, use_tor: bool = False) -> 'SecXferClient':'''
content = content.replace(helper_old, helper_new)

proxy_patch = '''            try:
                return SecXferClient(identity_path, keystore_dir, password=pwd, use_tor=use_tor)'''
content = re.sub(r'            try:\n                return SecXferClient\(identity_path, keystore_dir, password=pwd\)', proxy_patch, content)

init_patch = '''    try:
        return SecXferClient(identity_path, keystore_dir, use_tor=use_tor)'''
content = re.sub(r'    try:\n        return SecXferClient\(identity_path, keystore_dir\)', init_patch, content)

# Update _get_client calls
content = content.replace('client = _get_client(args.identity, keystore_dir)', 'client = _get_client(args.identity, keystore_dir, use_tor=args.tor)')
content = content.replace('client = _get_client(args.identity, args.keystore)', 'client = _get_client(args.identity, args.keystore, use_tor=args.tor)')
content = content.replace('client = _get_client(args.identity, keystore)', 'client = _get_client(args.identity, keystore, use_tor=args.tor)')

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)


# Now update client.py to accept use_tor and apply it
with open('src/secxfer/client.py', 'r', encoding='utf-8') as f:
    client_content = f.read()

client_content = client_content.replace(
    'def __init__(self, identity_path: str | Path, keystore_dir: str | Path, password: str | None = None):',
    'def __init__(self, identity_path: str | Path, keystore_dir: str | Path, password: str | None = None, use_tor: bool = False):'
)

client_content = client_content.replace(
    '        self.nonce_cache = NonceCache(db_path=self.keystore_dir / "nonces.db")',
    '        self.nonce_cache = NonceCache(db_path=self.keystore_dir / "nonces.db")\n        self.http_proxy = "socks5://127.0.0.1:9050" if use_tor else None'
)

client_content = client_content.replace(
    '        async with httpx.AsyncClient() as http:',
    '        async with httpx.AsyncClient(proxy=self.http_proxy) as http:'
)

with open('src/secxfer/client.py', 'w', encoding='utf-8') as f:
    f.write(client_content)
