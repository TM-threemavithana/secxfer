with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix receive call
content = content.replace('await client.receive(args.name, AsyncFileWrapper(inp_f), dest_path)', 'await client.receive(AsyncFileWrapper(inp_f), dest_path)')
content = content.replace('await client.receive(args.name, AsyncFileWrapper(inp_stream), dest_path)', 'await client.receive(AsyncFileWrapper(inp_stream), dest_path)')

# We can also remove --name from p_recv.add_argument("--name", ...) since the client derives it from the identity.
import re
content = re.sub(r'p_recv\.add_argument\([^)]*"--name"[^)]*\)\n', '', content)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
