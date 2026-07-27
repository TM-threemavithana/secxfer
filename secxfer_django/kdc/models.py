import time
from django.db import models

class UserIdentity(models.Model):
    key_id = models.CharField(max_length=64, unique=True)
    identity_pubkey = models.CharField(max_length=128)
    registered_at = models.FloatField(default=time.time)

class PreKey(models.Model):
    user = models.ForeignKey(UserIdentity, on_delete=models.CASCADE, related_name='prekeys')
    prekey_id = models.CharField(max_length=64)
    prekey_pubkey = models.CharField(max_length=128)
    used = models.BooleanField(default=False)

class EncryptedFile(models.Model):
    sender_key_id = models.CharField(max_length=64)
    receiver_key_id = models.CharField(max_length=64)
    file_path = models.CharField(max_length=512)
    timestamp = models.FloatField(default=time.time)
    size = models.IntegerField()

class AuditLog(models.Model):
    event_type = models.CharField(max_length=32)
    details = models.TextField()
    previous_hash = models.CharField(max_length=64)
    current_hash = models.CharField(max_length=64)
    timestamp = models.FloatField(default=time.time)
