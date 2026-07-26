import re

with open('src/secxfer/cli.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(r'\s*p_recv\.add_argument\([^)]*"--name"[^)]*\)\n', '\n', content)

with open('src/secxfer/cli.py', 'w', encoding='utf-8') as f:
    f.write(content)
