import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add --force to p_pin
content = content.replace('p_pin.add_argument("--keystore"', 'p_pin.add_argument("--force", action="store_true", help="force overwrite if identity changed")\n    p_pin.add_argument("--keystore"')

# 2. Add TOFU check in _cmd_pin
tofu_patch = '''
    pub_path = keystore_dir / f"{args.name}.pub"
    if pub_path.exists():
        existing_pubkey_hex = pub_path.read_bytes().hex()
        if existing_pubkey_hex != identity_pubkey_hex:
            if not args.force:
                logging.error(f"WARNING: Identity for '{args.name}' has CHANGED! This could be a MITM attack or key rotation. Use --force to overwrite.")
                return
            else:
                logging.warning(f"Overwriting identity for '{args.name}' due to --force.")
                
    pub_path.write_bytes(bytes.fromhex(identity_pubkey_hex))'''

content = content.replace('    pub_path = keystore_dir / f"{args.name}.pub"\n    pub_path.write_bytes(bytes.fromhex(identity_pubkey_hex))', tofu_patch.strip())

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
