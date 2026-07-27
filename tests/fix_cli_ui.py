import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add ui command to parser
ui_parser = '''
    p_receive.add_argument("--host", default="0.0.0.0", help="host to bind")
    p_receive.add_argument("--port", type=int, default=9090, help="port to bind")
    
    # UI Command
    p_ui = subparsers.add_parser("ui", help="start the SecXfer local web dashboard")
    p_ui.add_argument("--port", type=int, default=8080, help="port for the web UI")
'''
content = content.replace('    p_receive.add_argument("--host", default="0.0.0.0", help="host to bind")\n    p_receive.add_argument("--port", type=int, default=9090, help="port to bind")', ui_parser)

# Add ui command handler
ui_handler = '''
async def _cmd_ui(args):
    import uvicorn
    from secxfer.ui.app import app
    from pathlib import Path
    
    keystore = Path(args.keystore)
    keystore.mkdir(parents=True, exist_ok=True)
    
    app.state.identity_name = args.identity
    app.state.keystore_dir = keystore
    app.state.use_tor = args.tor
    app.state.pqc_psk = args.pqc_psk
    
    print(f"\\n[*] Starting SecXfer Web UI Dashboard on http://localhost:{args.port} ...")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="info")

async def main():'''

content = content.replace('async def main():', ui_handler)

dispatch = '''    elif args.command == "receive":
        await _cmd_receive(args)
    elif args.command == "ui":
        await _cmd_ui(args)'''
content = content.replace('    elif args.command == "receive":\n        await _cmd_receive(args)', dispatch)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
