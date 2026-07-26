import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace _cmd_pin
new_pin = '''def _cmd_pin(args: argparse.Namespace) -> None:
    import urllib.request
    import json
    from pathlib import Path
    
    # We fetch by key_id
    req = urllib.request.Request(args.server.rstrip("/") + "/keys/" + args.key_id)
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
    except Exception as exc:
        logging.error(f"Failed to fetch key for {args.key_id}: {exc}")
        return

    identity_pubkey_hex = data["identity_pubkey"]
    prekey_data = data.get("prekey")
    
    keystore_dir = Path(args.keystore)
    keystore_dir.mkdir(parents=True, exist_ok=True)
    
    pub_path = keystore_dir / f"{args.name}.pub"
    pub_path.write_bytes(bytes.fromhex(identity_pubkey_hex))
    logging.info(f"Pinned identity to {pub_path}")
    
    if prekey_data:
        pk_dir = keystore_dir / f"{args.name}_prekeys"
        pk_dir.mkdir(parents=True, exist_ok=True)
        pk_id = prekey_data["id"]
        pk_pub = prekey_data["pubkey"]
        (pk_dir / f"{pk_id}.pub").write_bytes(bytes.fromhex(pk_pub))
        logging.info(f"Saved one-time pre-key {pk_id} for V2 transfers")
'''

content = re.sub(r'def _cmd_pin\(args: argparse\.Namespace\) -> None:.*?def _cmd_send', new_pin + '\n\ndef _cmd_send', content, flags=re.DOTALL)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
