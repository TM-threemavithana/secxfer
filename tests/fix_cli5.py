with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix register
content = content.replace(
    'keystore = getattr(args, "keystore", Path(args.identity).parent / "keystore")',
    'keystore = Path(args.keystore) if getattr(args, "keystore", None) else Path(args.identity).parent / "keystore"'
)

# Fix qr show
content = content.replace(
    'qr.terminal(compact=True)',
    'import sys\\n    sys.stdout.reconfigure(encoding="utf-8")\\n    qr.terminal(compact=True, out=sys.stdout)'
)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
