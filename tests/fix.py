with open('tests/test_transfer_v1.py', 'r', encoding='utf-8') as f:
    code = f.read()

code = code.replace('io.BytesIO(', 'AsyncBytesIO(')

with open('tests/test_transfer_v1.py', 'w', encoding='utf-8') as f:
    f.write(code)
