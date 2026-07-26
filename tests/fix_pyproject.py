import re

with open('pyproject.toml', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('"httpx>=0.24.0",  # for TestClient', '"httpx[socks]>=0.24.0",')

with open('pyproject.toml', 'w', encoding='utf-8') as f:
    f.write(content)
