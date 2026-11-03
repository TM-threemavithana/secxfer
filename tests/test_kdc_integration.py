import sys
from pathlib import Path
WORKSPACE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE / "src"))

import pytest
import os
import time
import json
import subprocess
import shutil

from secxfer.keystore import generate_keypair
from secxfer.client import SecXferClient
from secxfer.cli import main

DJANGO_DIR = WORKSPACE / "secxfer_django"

@pytest.fixture(scope="module")
def django_kdc():
    port = 8031
    env = os.environ.copy()
    env["PYTHONPATH"] = str(WORKSPACE / "src")
    env["DJANGO_SECRET_KEY"] = "integration-test-secret-key-high-entropy-kdc-12345"
    env["DJANGO_DEBUG"] = "true"

    # Migrate & createcachetable
    subprocess.run([sys.executable, "manage.py", "migrate"], cwd=DJANGO_DIR, env=env, capture_output=True, check=True)
    subprocess.run([sys.executable, "manage.py", "createcachetable"], cwd=DJANGO_DIR, env=env, capture_output=True)

    proc = subprocess.Popen(
        [sys.executable, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"],
        cwd=DJANGO_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except:
        proc.kill()

@pytest.fixture
def tmp_env(tmp_path):
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    alice_dir.mkdir()
    bob_dir.mkdir()
    return {"alice": alice_dir, "bob": bob_dir}

# 1. Identity generation
def test_01_identity_generation(tmp_env):
    alice_ident = generate_keypair(tmp_env["alice"], name="alice")
    assert (tmp_env["alice"] / "alice.key").exists()
    assert (tmp_env["alice"] / "alice.pub").exists()
    assert len(alice_ident.key_id) == 16
    assert len(alice_ident.x25519_pubkey) == 32
    assert len(alice_ident.ed25519_pubkey) == 32

# 2. Authentication challenge
def test_02_authentication_challenge(django_kdc, tmp_env):
    import urllib.request
    alice_ident = generate_keypair(tmp_env["alice"], name="alice")
    url = f"{django_kdc}/challenge?key_id={alice_ident.key_id.hex()}"
    with urllib.request.urlopen(url) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "nonce" in data
        assert len(bytes.fromhex(data["nonce"])) == 32

# 3. Successful registration
def test_03_successful_registration(django_kdc, tmp_env):
    alice_ident = generate_keypair(tmp_env["alice"], name="alice")
    exit_code = main(["register", "--identity", str(tmp_env["alice"] / "alice.key"), "--server", django_kdc, "--keystore", str(tmp_env["alice"])])
    assert exit_code == 0

# 4. Authenticated peer-key retrieval
def test_04_authenticated_peer_key_retrieval(django_kdc, tmp_env):
    import urllib.request
    alice_ident = generate_keypair(tmp_env["alice"], name="alice")
    bob_ident = generate_keypair(tmp_env["bob"], name="bob")
    
    assert main(["register", "--identity", str(tmp_env["alice"] / "alice.key"), "--server", django_kdc, "--keystore", str(tmp_env["alice"])]) == 0
    assert main(["register", "--identity", str(tmp_env["bob"] / "bob.key"), "--server", django_kdc, "--keystore", str(tmp_env["bob"])]) == 0

    client = SecXferClient(tmp_env["alice"] / "alice.key", tmp_env["alice"])
    path = f"/keys/{bob_ident.key_id.hex()}"
    headers = client._auth_headers("GET", path)

    req = urllib.request.Request(f"{django_kdc}{path}", headers=headers)
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())
        assert "identity_pubkey" in data
        assert "prekey" in data
        assert "id" in data["prekey"]
        assert "pubkey" in data["prekey"]

# 5. Identity pinning
def test_05_identity_pinning(django_kdc, tmp_env):
    alice_ident = generate_keypair(tmp_env["alice"], name="alice")
    bob_ident = generate_keypair(tmp_env["bob"], name="bob")

    assert main(["register", "--identity", str(tmp_env["alice"] / "alice.key"), "--server", django_kdc, "--keystore", str(tmp_env["alice"])]) == 0
    assert main(["register", "--identity", str(tmp_env["bob"] / "bob.key"), "--server", django_kdc, "--keystore", str(tmp_env["bob"])]) == 0

    exit_code = main([
        "pin",
        "--identity", str(tmp_env["alice"] / "alice.key"),
        "--key-id", bob_ident.key_id.hex(),
        "--name", "bob",
        "--server", django_kdc,
        "--keystore", str(tmp_env["alice"])
    ])
    assert exit_code == 0
    assert (tmp_env["alice"] / "bob.pub").exists()

# 6. Invalid authentication
def test_06_invalid_authentication(django_kdc, tmp_env):
    import urllib.request
    import urllib.error
    bob_ident = generate_keypair(tmp_env["bob"], name="bob")
    assert main(["register", "--identity", str(tmp_env["bob"] / "bob.key"), "--server", django_kdc, "--keystore", str(tmp_env["bob"])]) == 0

    path = f"/keys/{bob_ident.key_id.hex()}"
    # Unauthenticated request -> 401
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"{django_kdc}{path}")
    assert exc_info.value.code == 401

    # Bad signature -> 401
    bad_headers = {
        "X-Auth-Key-Id": "0" * 32,
        "X-Auth-Timestamp": str(int(time.time())),
        "X-Auth-Nonce": "f" * 32,
        "X-Auth-Signature": "0" * 128
    }
    req = urllib.request.Request(f"{django_kdc}{path}", headers=bad_headers)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 401

# 7. Missing or exhausted prekeys
def test_07_missing_or_exhausted_prekeys(django_kdc, tmp_env):
    alice_ident = generate_keypair(tmp_env["alice"], name="alice")
    assert main(["register", "--identity", str(tmp_env["alice"] / "alice.key"), "--server", django_kdc, "--keystore", str(tmp_env["alice"])]) == 0

    exit_code = main([
        "pin",
        "--identity", str(tmp_env["alice"] / "alice.key"),
        "--key-id", "deadbeef00000000deadbeef00000000",
        "--name", "ghost",
        "--server", django_kdc,
        "--keystore", str(tmp_env["alice"])
    ])
    assert exit_code == 1

# 8. Failed command exit codes
def test_08_failed_command_exit_codes(django_kdc, tmp_env):
    # Empty args
    assert main([]) == 1
    # Invalid identity file
    assert main(["show-id", "--identity", "non_existent.key"]) == 1
    # Register to offline server
    alice_ident = generate_keypair(tmp_env["alice"], name="alice")
    assert main(["register", "--identity", str(tmp_env["alice"] / "alice.key"), "--server", "http://127.0.0.1:59999", "--keystore", str(tmp_env["alice"])]) == 1
    # Unauthenticated pin against Django KDC returns 1
    bob_ident = generate_keypair(tmp_env["bob"], name="bob")
    assert main(["pin", "--key-id", bob_ident.key_id.hex(), "--name", "bob", "--server", django_kdc, "--keystore", str(tmp_env["alice"])]) == 1

# 9. Python version compatibility
def test_09_python_version_compatibility():
    assert sys.version_info >= (3, 11)
    if sys.version_info >= (3, 12):
        import django
        assert django.VERSION[0] >= 6
