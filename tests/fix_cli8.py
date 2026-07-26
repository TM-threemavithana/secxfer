import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add _get_client helper
helper = '''
def _get_client(identity_path: str, keystore_dir: str) -> 'SecXferClient':
    from secxfer.client import SecXferClient
    from secxfer.crypto import WrongPasswordError
    import getpass
    import sys
    
    try:
        return SecXferClient(identity_path, keystore_dir)
    except WrongPasswordError:
        while True:
            pwd = getpass.getpass(f"Enter password to unlock {identity_path}: ")
            try:
                return SecXferClient(identity_path, keystore_dir, password=pwd)
            except WrongPasswordError:
                print("Incorrect password. Please try again.", file=sys.stderr)
'''

# Insert it before _cmd_keygen
content = content.replace('def _cmd_keygen', helper + '\n\ndef _cmd_keygen')

# 2. Update all client initializations in cli.py
content = content.replace('client = SecXferClient(args.identity, keystore_dir)', 'client = _get_client(args.identity, keystore_dir)')
content = content.replace('client = SecXferClient(args.identity, args.keystore)', 'client = _get_client(args.identity, args.keystore)')
content = content.replace('client = SecXferClient(args.identity, keystore)', 'client = _get_client(args.identity, keystore)')

# 3. Update keygen to ask for password
keygen_patch = '''
    import getpass
    pwd = getpass.getpass(f"Enter password to encrypt {args.name}.key (leave blank for no encryption): ")
    if not pwd:
        pwd = None
        
    identity = generate_keypair(out_dir, args.name, password=pwd)
'''
content = re.sub(r'identity = generate_keypair\(out_dir, args\.name\)', keygen_patch.strip(), content)

# 4. Update _cmd_qr_show
# qr_show also loads the identity directly. We should use a helper for load_identity too.
qr_patch = '''def _load_id(path):
    from secxfer.keystore import load_identity
    from secxfer.crypto import WrongPasswordError
    import getpass
    import sys
    try:
        return load_identity(path)
    except WrongPasswordError:
        while True:
            pwd = getpass.getpass(f"Enter password to unlock {path}: ")
            try:
                return load_identity(path, pwd)
            except WrongPasswordError:
                print("Incorrect password. Please try again.", file=sys.stderr)

def _cmd_qr_show(args: argparse.Namespace) -> None:
    import segno
    
    identity = _load_id(Path(args.identity))'''
content = re.sub(r'def _cmd_qr_show\(args: argparse\.Namespace\) -> None:\s*from secxfer\.keystore import load_identity\s*import segno\s*identity = load_identity\(Path\(args\.identity\)\)', qr_patch, content)


with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
