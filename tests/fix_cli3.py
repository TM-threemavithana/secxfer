import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add _cmd_qr show
new_qr = '''def _cmd_qr_show(args: argparse.Namespace) -> None:
    from secxfer.keystore import load_identity
    import segno
    
    identity = load_identity(Path(args.identity))
    # We embed the key_id and public key
    full_pubkey = (identity.x25519_pubkey + identity.ed25519_pubkey).hex()
    key_id = identity.key_id.hex()
    
    payload = f"secxfer://identity/{key_id}/{full_pubkey}"
    qr = segno.make_qr(payload)
    
    print(f"\\nQR Code for Identity: {args.identity}\\n")
    qr.terminal(compact=True)
    print(f"\\nKey ID: {key_id}\\n")
    print("Scan this to verify the identity out-of-band.\\n")
'''

content = new_qr + '\n\n' + content

# Fix _cmd_pin arguments (remove --name and add --key-id)
content = re.sub(r'p_pin\.add_argument\("--name", required=True, metavar="NAME"\)', 'p_pin.add_argument("--key-id", required=True, metavar="ID")\\n    p_pin.add_argument("--name", required=True, metavar="ALIAS", help="local alias to save as")', content)

# Add register --keystore
content = re.sub(r'p_reg\.add_argument\("--name", required=True, metavar="NAME"\)', 'p_reg.add_argument("--name", required=False, metavar="NAME")\\n    p_reg.add_argument("--keystore", required=False, metavar="DIR")', content)

# Add qr subcommand
parser_qr = '''
    # ── qr ──────────────────────────────────────────────────────────────────
    p_qr = sub.add_parser("qr", help="generate QR code for identity")
    p_qr_sub = p_qr.add_subparsers(title="qr commands")
    
    p_qr_show = p_qr_sub.add_parser("show", help="show QR code in terminal")
    p_qr_show.add_argument("--identity", required=True, metavar="KEY")
    p_qr_show.set_defaults(func=_cmd_qr_show)
'''
content = content.replace('    # ── send ────────────────────────────────────────────────────────────────', parser_qr + '\n    # ── send ────────────────────────────────────────────────────────────────')

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
