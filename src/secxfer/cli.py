"""
secxfer.cli — command-line interface.

Thin wrapper over send_file / receive_file / generate_keypair.
No business logic lives here; this module only handles argument parsing,
I/O plumbing, and user-facing error messages.

Commands
--------
  secxfer keygen   --dir DIR [--name NAME]
  secxfer send     FILE --identity KEY --to PUBKEY [--ttl SECS] [--out FILE]
  secxfer receive  DEST --identity KEY --keystore DIR [--in FILE]
  secxfer show-id  --identity KEY

Transport model
---------------
send writes to stdout (or --out FILE); receive reads from stdin (or --in FILE).
This makes the tool composable with standard Unix plumbing::

    secxfer send secret.txt --identity alice.key --to bob.pub | \\
        secxfer receive out.txt --identity bob.key --keystore ./keys

Or via a file::

    secxfer send secret.txt --identity alice.key --to bob.pub --out transfer.bin
    secxfer receive out.txt --identity bob.key --keystore ./keys --in transfer.bin

Nonce cache lifetime
--------------------
The NonceCache is created fresh per invocation.  For a single-shot CLI this
is correct; replay protection works within a single session.  For a
long-running service, persist the cache across invocations or use an
external store (see threat model §5).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secxfer.crypto import AuthenticationError, SignatureError
from secxfer.keystore import (
    UnknownSenderError,
    generate_keypair,
    load_identity,
)
from secxfer.transfer import (
    NonceCache,
    ProtocolError,
    ReplayError,
    TTLError,
    TruncationError,
    VersionError,
    receive_file,
    send_file,
)
from secxfer.keystore import Keystore


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Parse arguments and dispatch to the appropriate subcommand.

    Returns exit code (0 = success, 1 = error).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        args.func(args)
        return 0
    except (
        AuthenticationError,
        SignatureError,
        ProtocolError,
        ReplayError,
        TTLError,
        TruncationError,
        VersionError,
        UnknownSenderError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: file not found — {exc}", file=sys.stderr)
        return 1
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def _cmd_keygen(args: argparse.Namespace) -> None:
    """Generate a Curve25519 + Ed25519 keypair and write to disk."""
    identity = generate_keypair(Path(args.dir), name=args.name)
    key_dir = Path(args.dir)
    print(f"Generated keypair in {key_dir.resolve()}/")
    print(f"  Private key : {key_dir / args.name}.key  (keep secret)")
    print(f"  Public key  : {key_dir / args.name}.pub  (share with peers)")
    print(f"  Key ID      : {identity.key_id.hex()}")
    print()
    print("Share the .pub file with anyone who should be able to receive")
    print("files from you, or whose files you want to send to.")


def _cmd_show_id(args: argparse.Namespace) -> None:
    """Print the key ID (first 8 bytes of SHA-256(x25519_pubkey)) for an identity."""
    identity = load_identity(Path(args.identity))
    print(f"Key ID  : {identity.key_id.hex()}")
    print(f"X25519  : {identity.x25519_pubkey.hex()}")
    print(f"Ed25519 : {identity.ed25519_pubkey.hex()}")


def _cmd_send(args: argparse.Namespace) -> None:
    """Encrypt and send a file to stdout (or --out FILE)."""
    identity = load_identity(Path(args.identity))

    # Load receiver's public key from their .pub file
    raw = Path(args.to).read_bytes()
    if len(raw) != 64:
        raise ProtocolError(
            f"{args.to} is not a valid .pub file (expected 64 bytes, got {len(raw)})"
        )
    receiver_x25519_pubkey = raw[:32]  # first 32 bytes are the X25519 key

    file_path = Path(args.file)
    if not file_path.exists():
        raise FileNotFoundError(file_path)

    if args.out:
        out_path = Path(args.out)
        with out_path.open("wb") as out_f:
            send_file(
                identity,
                receiver_x25519_pubkey,
                file_path,
                out_f,
                ttl_seconds=args.ttl,
            )
        print(f"Sent: {file_path} → {out_path}", file=sys.stderr)
    else:
        # Write to stdout in binary mode
        out_stream = sys.stdout.buffer
        send_file(
            identity,
            receiver_x25519_pubkey,
            file_path,
            out_stream,
            ttl_seconds=args.ttl,
        )


def _cmd_receive(args: argparse.Namespace) -> None:
    """Decrypt and verify a file from stdin (or --in FILE) to DEST."""
    identity = load_identity(Path(args.identity))
    keystore = Keystore.from_directory(Path(args.keystore))

    if len(keystore) == 0:
        print(
            f"warning: no .pub files found in {args.keystore} — "
            "transfers from any sender will be rejected",
            file=sys.stderr,
        )

    dest_path = Path(args.dest)
    nonce_cache = NonceCache()

    if args.input:
        inp_path = Path(args.input)
        with inp_path.open("rb") as inp_f:
            receive_file(identity, keystore, inp_f, dest_path, nonce_cache)
    else:
        inp_stream = sys.stdin.buffer
        receive_file(identity, keystore, inp_stream, dest_path, nonce_cache)

    print(f"Received: → {dest_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secxfer",
        description=(
            "Cryptographically secure file transfer using pre-shared keys.\n"
            "Primitives: X25519 + HKDF-SHA256, XChaCha20-Poly1305 (secretstream), Ed25519."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(title="commands")

    # ── keygen ──────────────────────────────────────────────────────────────
    p_keygen = sub.add_parser(
        "keygen",
        help="generate a keypair and write it to disk",
        description=(
            "Generates a Curve25519 keypair (for key exchange) and an Ed25519\n"
            "keypair (for signing).  Writes <name>.key (private) and <name>.pub\n"
            "(public) to DIR.  Share only the .pub file."
        ),
    )
    p_keygen.add_argument(
        "--dir", required=True, metavar="DIR",
        help="directory in which to write the key files"
    )
    p_keygen.add_argument(
        "--name", default="identity", metavar="NAME",
        help="base filename for the key files (default: identity)"
    )
    p_keygen.set_defaults(func=_cmd_keygen)

    # ── show-id ─────────────────────────────────────────────────────────────
    p_showid = sub.add_parser(
        "show-id",
        help="print the key ID and public key bytes for an identity",
    )
    p_showid.add_argument(
        "--identity", required=True, metavar="KEY",
        help="path to the .key file"
    )
    p_showid.set_defaults(func=_cmd_show_id)

    # ── send ────────────────────────────────────────────────────────────────
    p_send = sub.add_parser(
        "send",
        help="encrypt and send a file (writes to stdout or --out FILE)",
        description=(
            "Encrypts FILE using the receiver's public key and the sender's\n"
            "identity.  Output goes to stdout by default (pipe to receiver)\n"
            "or to --out FILE."
        ),
    )
    p_send.add_argument("file", metavar="FILE", help="plaintext file to send")
    p_send.add_argument(
        "--identity", required=True, metavar="KEY",
        help="sender's .key file"
    )
    p_send.add_argument(
        "--to", required=True, metavar="PUBKEY",
        help="receiver's .pub file"
    )
    p_send.add_argument(
        "--ttl", type=int, default=300, metavar="SECS",
        help="transfer time-to-live in seconds (default: 300)"
    )
    p_send.add_argument(
        "--out", metavar="FILE", default=None,
        help="write encrypted output to FILE instead of stdout"
    )
    p_send.set_defaults(func=_cmd_send)

    # ── receive ─────────────────────────────────────────────────────────────
    p_recv = sub.add_parser(
        "receive",
        help="decrypt and verify a file (reads from stdin or --in FILE)",
        description=(
            "Decrypts and verifies a transfer from stdin (or --in FILE),\n"
            "writing the plaintext to DEST only after all authentication\n"
            "checks pass.  DEST is never created in a partial state."
        ),
    )
    p_recv.add_argument("dest", metavar="DEST", help="destination file path")
    p_recv.add_argument(
        "--identity", required=True, metavar="KEY",
        help="receiver's .key file"
    )
    p_recv.add_argument(
        "--keystore", required=True, metavar="DIR",
        help="directory containing trusted sender .pub files"
    )
    p_recv.add_argument(
        "--in", dest="input", metavar="FILE", default=None,
        help="read encrypted input from FILE instead of stdin"
    )
    p_recv.set_defaults(func=_cmd_receive)

    return parser


if __name__ == "__main__":
    raise SystemExit(main())
