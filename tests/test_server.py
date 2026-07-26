from fastapi.testclient import TestClient
from secxfer_server.main import app

client = TestClient(app)

def test_upload_and_get_keys():
    # 1. Upload keys
    payload = {
        "key_id": "alice123",
        "identity_pubkey": "a" * 128,  # 64 bytes hex
        "prekeys": [
            {"id": "pk1", "pubkey": "b" * 64},
            {"id": "pk2", "pubkey": "c" * 64},
        ]
    }
    
    response = client.post("/upload", json=payload)
    assert response.status_code == 200
    assert response.json()["prekeys_added"] == 2
    
    # 2. Get keys (pops pk1)
    response = client.get("/keys/alice123")
    assert response.status_code == 200
    data = response.json()
    assert data["identity_pubkey"] == "a" * 128
    assert data["prekey"]["id"] == "pk1"
    
    # 3. Get keys again (pops pk2)
    response = client.get("/keys/alice123")
    assert response.status_code == 200
    data = response.json()
    assert data["prekey"]["id"] == "pk2"
    
    # 4. Get keys (empty)
    response = client.get("/keys/alice123")
    assert response.status_code == 404
    assert response.json()["detail"] == "No pre-keys available for this user"
