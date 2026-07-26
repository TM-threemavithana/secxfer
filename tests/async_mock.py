import io

class AsyncBytesIO:
    def __init__(self, initial_bytes=b""):
        self._buf = io.BytesIO(initial_bytes)
        
    async def read(self, n=-1):
        return self._buf.read(n)
        
    async def write(self, b):
        return self._buf.write(b)
        
    def seek(self, offset, whence=0):
        return self._buf.seek(offset, whence)

    def getvalue(self):
        return self._buf.getvalue()
