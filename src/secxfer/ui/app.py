from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import os
import shutil
import asyncio

from secxfer.client import SecXferClient
from secxfer.keystore import generate_keypair

app = FastAPI(title="SecXfer UI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# These will be set dynamically by cli.py
app.state.identity_name = "identity"
app.state.keystore_dir = Path("./keys")
app.state.use_tor = False
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

@app.post("/api/send")
async def send_file(
    target_key_id: str = Form(...),
    file: UploadFile = File(...),
    server_url: str = Form("http://127.0.0.1:54321")
):
    client = get_client()
    temp_dir = app.state.keystore_dir / "tmp"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / file.filename
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    try:
        await client.send(target_key_id, file_path, server_url)
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        if file_path.exists():
            file_path.unlink()

@app.get("/api/inbox")
async def check_inbox(server_url: str = "http://127.0.0.1:54321"):
    client = get_client()
    try:
        inbox = await client.check_inbox(server_url)
        return {"status": "ok", "inbox": inbox}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/download")
async def download_file(
    file_id: int = Form(...),
    server_url: str = Form("http://127.0.0.1:54321")
):
    client = get_client()
    out_dir = app.state.keystore_dir / "downloads"
    out_dir.mkdir(exist_ok=True)
    try:
        await client.download(file_id, server_url, out_dir)
        return {"status": "ok"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/audit")
async def fetch_audit_log(server_url: str = "http://127.0.0.1:54321"):
    import urllib.request
    import json
    req = urllib.request.Request(server_url.rstrip("/") + "/audit/log")
    def fetch():
        with urllib.request.urlopen(req, timeout=10.0) as response:
            return json.loads(response.read().decode())['log']
    try:
        log_data = await asyncio.to_thread(fetch)
        return {"status": "ok", "log": log_data}
    except Exception as e:
        return {"error": str(e)}

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
