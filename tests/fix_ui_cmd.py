import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

if 'p_ui = subparsers.add_parser("ui"' not in content:
    # Add ui parser properly
    ui_parser = '''
    # UI Command
    p_ui = subparsers.add_parser("ui", help="start the SecXfer local web dashboard")
    p_ui.add_argument("--port", type=int, default=8080, help="port for the web UI")

async def _cmd_keygen(args):'''
    content = content.replace('async def _cmd_keygen(args):', ui_parser)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
