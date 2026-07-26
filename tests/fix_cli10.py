import re

# 1. Update keystore.py
with open('src/secxfer/keystore.py', 'r', encoding='utf-8') as f:
    k_content = f.read()

k_content = k_content.replace(
    'def generate_keypair(output_dir: Path | str, name: str = "identity", num_prekeys: int = 50, password: str | None = None) -> LocalIdentity:',
    'def generate_keypair(output_dir: Path | str, name: str = "identity", num_prekeys: int = 50, password: str | None = None, duress_password: str | None = None) -> LocalIdentity:'
)

patch = '''    priv_bytes = x25519_priv + ed25519_seed
    if password:
        from secxfer.crypto import encrypt_private_key
        fake_priv_bytes = None
        if duress_password:
            import os
            from nacl.signing import SigningKey
            import nacl.bindings as _nb
            fake_x25519_priv = os.urandom(32)
            fake_signing_key = SigningKey.generate()
            fake_ed25519_seed = bytes(fake_signing_key)
            fake_priv_bytes = fake_x25519_priv + fake_ed25519_seed
        key_path.write_bytes(encrypt_private_key(priv_bytes, password, duress_password, fake_priv_bytes))
    else:'''

k_content = re.sub(r'    priv_bytes = x25519_priv \+ ed25519_seed\n    if password:\n        from secxfer\.crypto import encrypt_private_key\n        key_path\.write_bytes\(encrypt_private_key\(priv_bytes, password\)\)\n    else:', patch, k_content)

with open('src/secxfer/keystore.py', 'w', encoding='utf-8') as f:
    f.write(k_content)


# 2. Update cli.py
with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    c_content = f.read()

c_patch = '''    import getpass
    pwd = getpass.getpass(f"Enter REAL password to encrypt {args.name}.key (leave blank for no encryption): ")
    dpwd = None
    if pwd:
        dpwd = getpass.getpass(f"Enter DURESS password for Plausible Deniability (leave blank to skip): ")
    if not pwd:
        pwd = None
    if not dpwd:
        dpwd = None
        
    identity = generate_keypair(out_dir, args.name, password=pwd, duress_password=dpwd)'''

c_content = re.sub(r'    import getpass\n    pwd = getpass\.getpass\(f"Enter password to encrypt \{args\.name\}\.key \(leave blank for no encryption\): "\)\n    if not pwd:\n        pwd = None\n        \n    identity = generate_keypair\(out_dir, args\.name, password=pwd\)', c_patch, c_content)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(c_content)
