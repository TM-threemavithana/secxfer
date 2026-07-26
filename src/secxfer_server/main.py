from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel

from .database import get_db, init_db, User, PreKey

init_db()

app = FastAPI(title="SecXfer Key Directory")

class PreKeyModel(BaseModel):
    id: str
    pubkey: str

class UploadBundle(BaseModel):
    key_id: str
    identity_pubkey: str
    prekeys: List[PreKeyModel]

@app.post("/upload")
def upload_bundle(bundle: UploadBundle, db: Session = Depends(get_db)):
    # Upsert User
    user = db.query(User).filter(User.key_id == bundle.key_id).first()
    if not user:
        user = User(key_id=bundle.key_id, identity_pubkey=bundle.identity_pubkey)
        db.add(user)
    else:
        if user.identity_pubkey != bundle.identity_pubkey:
            raise HTTPException(status_code=400, detail="Identity key mismatch for existing user.")

    # Insert PreKeys (ignore duplicates)
    for pk in bundle.prekeys:
        existing = db.query(PreKey).filter(PreKey.id == pk.id).first()
        if not existing:
            new_pk = PreKey(id=pk.id, pubkey=pk.pubkey, user_id=user.key_id)
            db.add(new_pk)

    db.commit()
    return {"message": "Keys uploaded successfully", "prekeys_added": len(bundle.prekeys)}

@app.get("/keys/{key_id}")
def get_keys(key_id: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.key_id == key_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    prekey = db.query(PreKey).filter(PreKey.user_id == key_id).first()
    if not prekey:
        raise HTTPException(status_code=404, detail="No pre-keys available for this user")

    response_data = {
        "identity_pubkey": user.identity_pubkey,
        "prekey": {
            "id": prekey.id,
            "pubkey": prekey.pubkey
        }
    }
    
    db.delete(prekey)
    db.commit()
    
    return response_data
