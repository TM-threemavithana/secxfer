import re

with open('pyproject.toml', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('"httpx[socks]>=0.24.0",', '"httpx[socks]>=0.24.0",\n    "uvicorn>=0.30.0",\n    "python-multipart>=0.0.9",')

with open('pyproject.toml', 'w', encoding='utf-8') as f:
    f.write(content)
