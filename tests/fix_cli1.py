import ast
import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace _cmd_register
new_register = '''def _cmd_register(args: argparse.Namespace) -> None:
    from secxfer.client import SecXferClient
    import asyncio
    
    # We require a keystore to initialize the client, even if it's empty
    keystore = getattr(args, "keystore", Path(args.identity).parent / "keystore")
    keystore.mkdir(exist_ok=True)
    
    client = SecXferClient(args.identity, keystore)
    try:
        data = asyncio.run(client.upload_keys(args.server))
        print(f"Registered successfully! Added {data.get('prekeys_added')} prekeys.")
    except Exception as exc:
        logging.error(f"Registration failed: {exc}")
'''

content = re.sub(r'def _cmd_register\(args: argparse\.Namespace\) -> None:.*?def _cmd_pin', new_register + '\n\ndef _cmd_pin', content, flags=re.DOTALL)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
