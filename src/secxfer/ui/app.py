from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
import os
import shutil
import asyncio

from secxfer.client import SecXferClient
from secxfer.keystore import generate_keypair

app = FastAPI(title="SecXfer UI")

# These will be set dynamically by cli.py
app.state.identity_name = "identity"
app.state.keystore_dir = Path("./keys")
app.state.use_tor = False
app.state.pqc_psk = None
app.state.client = None

def get_client() -> SecXferClient:
    if app.state.client:
        return app.state.client
    raise HTTPException(status_code=401, detail="Client not initialized. Call /api/unlock.")

@app.post("/api/unlock")
async def unlock(password: str = Form(None)):
    identity_path = app.state.keystore_dir / f"{app.state.identity_name}.key"
    if not identity_path.exists():
        return {"error": "Identity not found"}
    try:
        app.state.client = SecXferClient(
            identity_path, 
            app.state.keystore_dir, 
            password=password, 
            use_tor=app.state.use_tor
        )
        return {"status": "ok", "key_id": app.state.client.identity.key_id.hex()}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/keygen")
async def keygen(password: str = Form(None), duress_password: str = Form(None), entropy: str = Form(None)):
    try:
        user_entropy = entropy.encode('utf-8') if entropy else None
        generate_keypair(
            app.state.keystore_dir, 
            app.state.identity_name, 
            password=password, 
            duress_password=duress_password, 
            user_entropy=user_entropy
        )
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/status")
async def status():
    identity_path = app.state.keystore_dir / f"{app.state.identity_name}.key"
    exists = identity_path.exists()
    unlocked = app.state.client is not None
    key_id = app.state.client.identity.key_id.hex() if unlocked else None
    return {"exists": exists, "unlocked": unlocked, "key_id": key_id}

@app.post("/api/register")
async def register(server_url: str = Form("http://127.0.0.1:54321")):
    client = get_client()
    try:
        await client.upload_keys(server_url)
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}

class TCPWriterWrapper:
    def __init__(self, writer):
        self.writer = writer
    async def write(self, data):
        self.writer.write(data)
        await self.writer.drain()
    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()

class TCPReaderWrapper:
    def __init__(self, reader):
        self.reader = reader
    async def read(self, n=-1):
        return await self.reader.read(n)

@app.post("/api/send")
async def send_file(
    target_key_id: str = Form(...),
    file: UploadFile = File(...),
    pqc_psk: str = Form(None),
    target_host: str = Form("127.0.0.1"),
    target_port: int = Form(9090),
):
    client = get_client()
    temp_dir = app.state.keystore_dir / "tmp"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / file.filename
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    try:
        reader, writer = await asyncio.open_connection(target_host, target_port)
        out_stream = TCPWriterWrapper(writer)
        
        # In P2P mode, the target is the path to the pubkey
        receiver_name = target_key_id
        
        await client.send(receiver_name, file_path, out_stream, pqc_psk=pqc_psk or app.state.pqc_psk)
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        if file_path.exists():
            file_path.unlink()

@app.post("/api/receive")
async def receive_file(port: int = Form(9090), pqc_psk: str = Form(None)):
    client = get_client()
    out_dir = app.state.keystore_dir / "downloads"
    out_dir.mkdir(exist_ok=True)
    
    # A7: limit concurrent receivers to prevent resource exhaustion
    _receive_semaphore = asyncio.Semaphore(4)
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    
    async def handle_client(reader, writer):
        async with _receive_semaphore:
            if not future.done():
                # Always reload .pub files from disk so newly-added peers are recognised
                client.refresh_keystore()
                inp_stream = TCPReaderWrapper(reader)
                try:
                    await client.receive(inp_stream, out_dir, pqc_psk=pqc_psk or app.state.pqc_psk)
                    future.set_result(True)
                except Exception as e:
                    future.set_exception(e)
                finally:
                    writer.close()
                    await writer.wait_closed()
    
    # A7: bind to loopback only — not all interfaces
    server = await asyncio.start_server(handle_client, "127.0.0.1", port)
    try:
        await asyncio.wait_for(future, timeout=60.0)
        return {"status": "ok"}
    except asyncio.TimeoutError:
        return {"error": "Timeout waiting for connection"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        server.close()
        await server.wait_closed()

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
