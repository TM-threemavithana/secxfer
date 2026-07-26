import re

with open('src/secxfer/keystore.py', 'r', encoding='utf-8') as f:
    k_content = f.read()

k_content = k_content.replace(
    'def generate_keypair(output_dir: Path | str, name: str = "identity", num_prekeys: int = 50, password: str | None = None, duress_password: str | None = None) -> LocalIdentity:',
    'def generate_keypair(output_dir: Path | str, name: str = "identity", num_prekeys: int = 50, password: str | None = None, duress_password: str | None = None, user_entropy: bytes | None = None) -> LocalIdentity:'
)

patch = '''    # Curve25519 keypair
    if user_entropy:
        # Mix OS entropy with user entropy
        x25519_priv = hashlib.sha256(os.urandom(32) + user_entropy + b"x25519").digest()
        ed25519_seed_raw = hashlib.sha256(os.urandom(32) + user_entropy + b"ed25519").digest()
    else:
        x25519_priv = os.urandom(32)
        ed25519_seed_raw = None

    x25519_pub = _nb.crypto_scalarmult_base(x25519_priv)

    # Ed25519 keypair
    if ed25519_seed_raw:
        signing_key = SigningKey(ed25519_seed_raw)
    else:
        signing_key = SigningKey.generate()
        
    ed25519_seed = bytes(signing_key)'''

k_content = re.sub(r'    # Curve25519 keypair\n    x25519_priv = os\.urandom\(32\)\n    x25519_pub = _nb\.crypto_scalarmult_base\(x25519_priv\)\n\n    # Ed25519 keypair\n    signing_key = SigningKey\.generate\(\)\n    ed25519_seed = bytes\(signing_key\)', patch, k_content)


with open('src/secxfer/keystore.py', 'w', encoding='utf-8') as f:
    f.write(k_content)


# Update cli.py to prompt for entropy
with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    c_content = f.read()

c_patch = '''    import time
    print("\n[ENTROPY MIXING]")
    print("To defeat CPU hardware backdoors (RDRAND), please mash your keyboard randomly.")
    entropy_str = input("Type random characters and press ENTER: ")
    user_entropy = entropy_str.encode('utf-8') + str(time.time_ns()).encode('utf-8')
    
    identity = generate_keypair(out_dir, args.name, password=pwd, duress_password=dpwd, user_entropy=user_entropy)'''

c_content = c_content.replace('    identity = generate_keypair(out_dir, args.name, password=pwd, duress_password=dpwd)', c_patch)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(c_content)
