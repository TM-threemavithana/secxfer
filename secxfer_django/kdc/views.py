import json
import os
import secrets
import time
import hashlib
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from nacl.signing import VerifyKey
from .models import UserIdentity, PreKey, EncryptedFile, AuditLog

_CHALLENGES = {}
_CHALLENGE_TTL = 300

def _issue_challenge(key_id_hex: str) -> str:
    nonce = secrets.token_bytes(32).hex()
    _CHALLENGES[key_id_hex] = (nonce, time.time() + _CHALLENGE_TTL)
    return nonce

def _consume_challenge(key_id_hex: str):
    entry = _CHALLENGES.pop(key_id_hex, None)
    if entry is None:
        return None
    nonce, expiry = entry
    return None if time.time() > expiry else nonce

def _verify_pop(identity_pubkey_hex: str, nonce_hex: str, signature_hex: str) -> bool:
    try:
        pubkey_bytes = bytes.fromhex(identity_pubkey_hex)
        ed25519_pubkey = pubkey_bytes[32:]
        nonce_bytes = bytes.fromhex(nonce_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        VerifyKey(ed25519_pubkey).verify(nonce_bytes, sig_bytes)
        return True
    except Exception:
        return False

def append_audit_log(event_type: str, details: dict):
    last_log = AuditLog.objects.order_by('-id').first()
    previous_hash = last_log.current_hash if last_log else "GENESIS_HASH"
    timestamp_val = time.time()
    details_json = json.dumps(details, sort_keys=True)
    hash_input = f"{event_type}|{details_json}|{timestamp_val}|{previous_hash}".encode('utf-8')
    current_hash = hashlib.sha256(hash_input).hexdigest()
    AuditLog.objects.create(
        event_type=event_type,
        details=details_json,
        previous_hash=previous_hash,
        current_hash=current_hash,
        timestamp=timestamp_val
    )

def challenge_view(request):
    key_id = request.GET.get('key_id')
    if not key_id:
        return JsonResponse({"error": "key_id query parameter required"}, status=400)
    return JsonResponse({"nonce": _issue_challenge(key_id)})

@csrf_exempt
def register_view(request):
    if request.method != 'POST':
        return JsonResponse({"error": "POST required"}, status=405)
    try:
        data = json.loads(request.body)
        key_id = data['key_id']
        identity_pubkey = data['identity_pubkey']
        prekeys = data['prekeys']
        challenge_nonce = data['challenge_nonce']
        signature = data['signature']
    except Exception as exc:
        return JsonResponse({"error": f"Invalid payload: {exc}"}, status=400)

    pending_nonce = _consume_challenge(key_id)
    if not pending_nonce or pending_nonce != challenge_nonce or not _verify_pop(identity_pubkey, challenge_nonce, signature):
        return JsonResponse({"error": "Auth failed"}, status=401)

    user, created = UserIdentity.objects.update_or_create(
        key_id=key_id,
        defaults={"identity_pubkey": identity_pubkey, "registered_at": time.time()}
    )
    for pk in prekeys:
        PreKey.objects.create(user=user, prekey_id=pk['id'], prekey_pubkey=pk['pubkey'])
        
    append_audit_log("REGISTER", {"key_id": key_id, "prekeys_added": len(prekeys)})
    return JsonResponse({"status": "registered", "prekeys_added": len(prekeys)})

def keys_view(request, key_id):
    try:
        user = UserIdentity.objects.get(key_id=key_id)
        prekey = user.prekeys.filter(used=False).first()
        if not prekey:
            return JsonResponse({"error": "Pre-keys exhausted"}, status=404)
        
        prekey.used = True
        prekey.save()
        return JsonResponse({
            "identity_pubkey": user.identity_pubkey,
            "prekey": {"id": prekey.prekey_id, "pubkey": prekey.prekey_pubkey}
        })
    except UserIdentity.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

@csrf_exempt
def upload_view(request):
    if request.method != 'POST':
        return JsonResponse({"error": "POST required"}, status=405)
    
    receiver_key_id = request.headers.get('X-Receiver-Key-Id')
    sender_key_id = request.headers.get('X-Sender-Key-Id')
    if not receiver_key_id or not sender_key_id:
        return JsonResponse({"error": "Missing headers"}, status=400)
    
    os.makedirs('server_vault', exist_ok=True)
    file_id = secrets.token_hex(16)
    file_path = os.path.join('server_vault', file_id + ".bin")
    
    with open(file_path, 'wb') as f:
        f.write(request.body)
        
    size = len(request.body)
    EncryptedFile.objects.create(
        sender_key_id=sender_key_id,
        receiver_key_id=receiver_key_id,
        file_path=file_path,
        timestamp=time.time(),
        size=size
    )
    
    append_audit_log("UPLOAD", {"sender": sender_key_id, "receiver": receiver_key_id, "file_id": file_id, "size": size})
    return JsonResponse({"status": "uploaded"})

def inbox_view(request, key_id):
    files = EncryptedFile.objects.filter(receiver_key_id=key_id)
    out = [{"file_id": f.id, "sender_key_id": f.sender_key_id, "timestamp": f.timestamp, "size": f.size} for f in files]
    return JsonResponse({"inbox": out})

@csrf_exempt
def download_view(request, file_id):
    try:
        fobj = EncryptedFile.objects.get(id=file_id)
        if not os.path.exists(fobj.file_path):
            return JsonResponse({"error": "File not found"}, status=404)
        
        append_audit_log("DOWNLOAD", {"file_id": str(file_id)})
        
        with open(fobj.file_path, 'rb') as f:
            return HttpResponse(f.read(), content_type='application/octet-stream')
    except EncryptedFile.DoesNotExist:
        return JsonResponse({"error": "File not found"}, status=404)

def audit_log_view(request):
    logs = AuditLog.objects.order_by('id')
    out = [{"id": r.id, "event_type": r.event_type, "details_raw": r.details, "previous_hash": r.previous_hash, "current_hash": r.current_hash, "timestamp": r.timestamp} for r in logs]
    return JsonResponse({"log": out})
