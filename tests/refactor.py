import re

with open('tests/test_transfer_v1.py', 'r', encoding='utf-8') as f:
    code = f.read()

# Add import AsyncBytesIO
if 'from tests.async_mock import AsyncBytesIO' not in code:
    code = code.replace('import pytest', 'import pytest\nfrom tests.async_mock import AsyncBytesIO')

# Change io.BytesIO() to AsyncBytesIO() in transfer helper
code = code.replace('buf = io.BytesIO()', 'buf = AsyncBytesIO()')

# Change def _transfer to async def _transfer
code = code.replace('def _transfer(', 'async def _transfer(')

# add await to send_file and receive_file
code = re.sub(r'(?<!await )send_file\(', 'await send_file(', code)
code = re.sub(r'(?<!await )receive_file\(', 'await receive_file(', code)
code = re.sub(r'(?<!await )_transfer\(', 'await _transfer(', code)

# change test methods to async def in Roundtrip and Negative
code = re.sub(r'    def test_([a-zA-Z_]+)\(', r'    @pytest.mark.asyncio\n    async def test_\1(', code)

# fix _send_to_buffer
code = code.replace('def _send_to_buffer(', 'async def _send_to_buffer(')
code = re.sub(r'(?<!await )self._send_to_buffer\(', 'await self._send_to_buffer(', code)

with open('tests/test_transfer_v1.py', 'w', encoding='utf-8') as f:
    f.write(code)

print("test_transfer_v1 refactored")
