import re

with open('tests/test_x3dh_failures.py', 'r', encoding='utf-8') as f:
    code = f.read()

# Add import AsyncBytesIO
if 'from tests.async_mock import AsyncBytesIO' not in code:
    code = code.replace('import pytest', 'import pytest\nfrom tests.async_mock import AsyncBytesIO')

code = code.replace('io.BytesIO()', 'AsyncBytesIO()')
code = re.sub(r'(?<!await )send_file\(', 'await send_file(', code)
code = re.sub(r'(?<!await )receive_file\(', 'await receive_file(', code)

code = re.sub(r'def test_([a-zA-Z_]+)\(', r'@pytest.mark.asyncio\nasync def test_\1(', code)

with open('tests/test_x3dh_failures.py', 'w', encoding='utf-8') as f:
    f.write(code)

print("test_x3dh_failures refactored")
