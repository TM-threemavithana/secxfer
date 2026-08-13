import json
import os
import secrets
import time
import hashlib
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.db import transaction
from nacl.signing import VerifyKey
from .models import UserIdentity, PreKey, EncryptedFile, AuditLog, AuditChainHead
from kdc.constants import CHALLENGE_TTL

def _issue_challenge(key_id_hex: str) -> str:
    nonce = secrets.token_bytes(32).hex()
    cache.set(f"challenge:{key_id_hex}", nonce, timeout=CHALLENGE_TTL)
    return nonce

def _consume_challenge(key_id_hex: str):
    nonce = cache.get(f"challenge:{key_id_hex}")
    if nonce:
        cache.delete(f"challenge:{key_id_hex}")
    return nonce

def _verify_pop(identity_pubkey_hex: str, nonce_hex: str, signature_hex: str) -> bool:
    try:
        pubkey_bytes = bytes.fromhex(identity_pubkey_hex)
        if len(pubkey_bytes) != 1248:
            return False
        ed25519_pubkey = pubkey_bytes[32:64]
        nonce_bytes = bytes.fromhex(nonce_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        VerifyKey(ed25519_pubkey).verify(nonce_bytes, sig_bytes)
        return True
    except Exception:
        return False

def append_audit_log(event_type: str, details: dict):
    with transaction.atomic():
        head, _ = AuditChainHead.objects.get_or_create(pk=1)
        head = AuditChainHead.objects.select_for_update().get(pk=head.pk)
        timestamp_val = time.time()
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
        hash_input = f"{event_type}|{details_json}|{timestamp_val}|{head.current_hash}".encode("utf-8")
        current_hash = hashlib.sha256(hash_input).hexdigest()
        AuditLog.objects.create(event_type=event_type, details=details_json, previous_hash=head.current_hash, current_hash=current_hash, timestamp=timestamp_val)
        head.current_hash = current_hash
        head.save(update_fields=["current_hash"])

def _authenticate_request(request):
    """Validate a short-lived request signature from an already registered identity."""
    key_id = request.headers.get("X-Auth-Key-Id")
    timestamp = request.headers.get("X-Auth-Timestamp")
    nonce = request.headers.get("X-Auth-Nonce")
    signature = request.headers.get("X-Auth-Signature")
    if not key_id or not timestamp or not nonce or not signature:
        return None
    try:
        if abs(time.time() - int(timestamp)) > 60 or len(nonce) != 32:
            return None
        # ``add`` is atomic for the configured Django cache backend.  It makes
        # a signed request single-use during its validity window.
        if not cache.add(f"request-nonce:{key_id}:{nonce}", True, timeout=60):
            return None
        identity = UserIdentity.objects.get(key_id=key_id)
        context = ""
        if request.path == "/upload":
            context = "\n".join([
                request.headers.get("X-Sender-Key-Id", ""),
                request.headers.get("X-Receiver-Key-Id", ""),
                request.headers.get("X-Prekey-Id", ""),
                request.headers.get("Content-Length", ""),
            ])
        message = f"{request.method}\n{request.path}\n{timestamp}\n{nonce}\n{context}".encode("utf-8")
        VerifyKey(bytes.fromhex(identity.identity_pubkey)[32:64]).verify(message, bytes.fromhex(signature))
        return identity
    except Exception:
        return None

def _prekey_request_allowed(identity: UserIdentity) -> bool:
    """Limit one authenticated caller from reserving a user's key pool."""
    bucket = f"prekey-rate:{identity.key_id}:{int(time.time() // 60)}"
    if cache.add(bucket, 1, timeout=61):
        return True
    try:
        return cache.incr(bucket) <= 10
    except ValueError:
        return False

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

    try:
        identity_bytes = bytes.fromhex(identity_pubkey)
        if hashlib.sha256(identity_bytes[:32]).digest()[:16].hex() != key_id:
            return JsonResponse({"error": "key_id does not match identity key"}, status=400)
        if len({pk["id"] for pk in prekeys}) != len(prekeys):
            return JsonResponse({"error": "Duplicate prekey IDs"}, status=400)
        for pk in prekeys:
            if len(pk["id"]) > 64 or len(bytes.fromhex(pk["pubkey"])) != 32:
                return JsonResponse({"error": "Invalid prekey bundle"}, status=400)
    except (KeyError, TypeError, ValueError):
        return JsonResponse({"error": "Invalid key bundle"}, status=400)

    with transaction.atomic():
        user, created = UserIdentity.objects.get_or_create(
            key_id=key_id, defaults={"identity_pubkey": identity_pubkey, "registered_at": time.time()}
        )
        if not created and user.identity_pubkey != identity_pubkey:
            return JsonResponse({"error": "Identity key rotation requires an explicit recovery flow"}, status=409)
        added = 0
        for pk in prekeys:
            existing, was_created = PreKey.objects.get_or_create(
                user=user, prekey_id=pk["id"], defaults={"prekey_pubkey": pk["pubkey"]}
            )
            if not was_created and existing.prekey_pubkey != pk["pubkey"]:
                return JsonResponse({"error": "Prekey ID conflicts with existing key material"}, status=409)
            added += was_created
        
    append_audit_log("REGISTER", {"key_id": key_id, "prekeys_added": added})
    return JsonResponse({"status": "registered", "prekeys_added": added})

def keys_view(request, key_id):
    try:
        requester = _authenticate_request(request)
        if not requester:
            return JsonResponse({"error": "Authentication required"}, status=401)
        if not _prekey_request_allowed(requester):
            return JsonResponse({"error": "Prekey request rate limit exceeded"}, status=429)
        user = UserIdentity.objects.get(key_id=key_id)
        # Atomically reserve the prekey using SELECT FOR UPDATE to prevent
        # concurrent senders from fetching the same one-time prekey.
        with transaction.atomic():
            # Reclaim a reservation only after a short timeout.
            PreKey.objects.filter(user=user, reserved=True, used=False, reserved_at__lt=time.time() - 300).update(reserved=False, reserved_at=None, reserved_by_key_id=None)
            prekey = user.prekeys.select_for_update().filter(used=False, reserved=False).first()
            if not prekey:
                return JsonResponse({"error": "Pre-keys exhausted"}, status=404)
            prekey.reserved = True
            prekey.reserved_at = time.time()
            prekey.reserved_by_key_id = requester.key_id
            prekey.save(update_fields=["reserved", "reserved_at", "reserved_by_key_id"])
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
    sender = _authenticate_request(request)
    if not sender or sender.key_id != sender_key_id:
        return JsonResponse({"error": "Authentication required"}, status=401)
    prekey_id = request.headers.get("X-Prekey-Id")
    if not prekey_id:
        return JsonResponse({"error": "Missing prekey header"}, status=400)
    try:
        content_length = int(request.META.get("CONTENT_LENGTH", "0"))
    except ValueError:
        return JsonResponse({"error": "Invalid content length"}, status=400)
    if content_length <= 0 or content_length > 1024 * 1024 * 1024:
        return JsonResponse({"error": "Invalid upload size"}, status=413)
    
    os.makedirs('server_vault', exist_ok=True)
    file_id = secrets.token_hex(16)
    file_path = os.path.join('server_vault', file_id + ".bin")
    part_path = file_path + ".part"

    try:
        with open(part_path, 'wb') as f:
            size = 0
            for chunk in request:
                f.write(chunk)
                size += len(chunk)
        # Atomic rename: only committed if full write succeeded
        os.replace(part_path, file_path)
    except Exception as e:
        if os.path.exists(part_path):
            os.remove(part_path)
        return JsonResponse({"error": f"Upload failed: {e}"}, status=500)

    try:
        with transaction.atomic():
            prekey = PreKey.objects.select_for_update().get(user__key_id=receiver_key_id, prekey_id=prekey_id, reserved=True, reserved_by_key_id=sender_key_id, used=False)
            prekey.used = True
            prekey.reserved = False
            prekey.reserved_at = None
            prekey.reserved_by_key_id = None
            prekey.save(update_fields=["used", "reserved", "reserved_at", "reserved_by_key_id"])
            EncryptedFile.objects.create(sender_key_id=sender_key_id, receiver_key_id=receiver_key_id, file_path=file_path, timestamp=time.time(), size=size)
    except PreKey.DoesNotExist:
        if os.path.exists(file_path):
            os.remove(file_path)
        return JsonResponse({"error": "Prekey is not reserved for this upload"}, status=409)
    
    append_audit_log("UPLOAD", {"sender": sender_key_id, "receiver": receiver_key_id, "file_id": file_id, "size": size})
    return JsonResponse({"status": "uploaded"})

def inbox_view(request, key_id):
    identity = _authenticate_request(request)
    if not identity or identity.key_id != key_id:
        return JsonResponse({"error": "Authentication required"}, status=401)
    files = EncryptedFile.objects.filter(receiver_key_id=key_id)
    out = [{"file_id": f.id, "sender_key_id": f.sender_key_id, "timestamp": f.timestamp, "size": f.size} for f in files]
    return JsonResponse({"inbox": out})

@csrf_exempt
def download_view(request, file_id):
    try:
        fobj = EncryptedFile.objects.get(id=file_id)
        identity = _authenticate_request(request)
        if not identity or identity.key_id != fobj.receiver_key_id:
            return JsonResponse({"error": "Authentication required"}, status=401)
        if not os.path.exists(fobj.file_path):
            return JsonResponse({"error": "File not found on disk"}, status=404)
        
        append_audit_log("DOWNLOAD", {"file_id": str(file_id)})
        # FileResponse streams the file in chunks — avoids loading entire file into RAM
        return FileResponse(open(fobj.file_path, 'rb'), content_type='application/octet-stream')
    except EncryptedFile.DoesNotExist:
        return JsonResponse({"error": "File not found"}, status=404)

def audit_log_view(request):
    if not _authenticate_request(request):
        return JsonResponse({"error": "Authentication required"}, status=401)
    try:
        limit = int(request.GET.get('limit', 100))
        offset = int(request.GET.get('offset', 0))
    except ValueError:
        return JsonResponse({"error": "Invalid pagination parameters"}, status=400)
        
    limit = min(max(limit, 1), 500)
    offset = max(offset, 0)
    logs = AuditLog.objects.order_by('id')[offset:offset+limit]
    out = [{"id": r.id, "event_type": r.event_type, "details_raw": r.details, "previous_hash": r.previous_hash, "current_hash": r.current_hash, "timestamp": r.timestamp} for r in logs]
    return JsonResponse({"log": out})
