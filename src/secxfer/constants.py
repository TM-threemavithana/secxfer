"""
Constants for SecXfer core library.
"""

DEFAULT_TTL = 300           # seconds; default transfer time-to-live
ED25519_SIG_LEN = 64        # bytes; length of an Ed25519 signature
CLOCK_SKEW_TOLERANCE = 300  # seconds; reject packets timestamped more than this far in the past
RESERVATION_TTL = 3600      # seconds; a reserved-but-unused prekey expires after this long
