"""
secxfer.cli — command-line interface.

Thin wrapper over send_file / receive_file / generate_keypair.
No business logic lives here; this module only handles argument parsing,
I/O plumbing, and user-facing error messages.

Commands
--------
  secxfer keygen   --dir DIR [--name NAME]
  secxfer register --identity KEY --name NAME --server URL
  secxfer pin      --name NAME --server URL --keystore DIR
  secxfer send     FILE --identity KEY --to DEST [--server URL] [--keystore DIR] [--ttl SECS] [--out FILE]
  secxfer receive  DEST --identity KEY --name NAME --keystore DIR [--in FILE]
  secxfer show-id  --identity KEY

Transport model
---------------
send writes to stdout (or --out FILE); receive reads from stdin (or --in FILE).
This makes the tool composable with standard Unix plumbing::

    secxfer send secret.txt --identity alice.key --to bob.pub | \
        secxfer receive out.txt --identity bob.key --name bob --keystore ./keys
"""
from __future__ import annotations

import argparse
import sys
import logging
from pathlib import Path

from secxfer.crypto import AuthenticationError, SignatureError
from secxfer.keystore import (
    UnknownSenderError,
    generate_keypair,
    load_identity,
    Keystore,
)
from secxfer.transfer import (
    NonceCache,
    ProtocolError,
    ReplayError,
    TTLError,
    TruncationError,
    VersionError,
    PreKeyConsumedError,
    receive_file,
    send_file_v1,
    send_file_v2,
)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Parse arguments and dispatch to the appropriate subcommand.

    Returns exit code (0 = success, 1 = error).
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s',
        stream=sys.stderr
    )

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
        PreKeyConsumedError,
    ) as exc:
        logging.error(str(exc))
        return 1
    except FileNotFoundError as exc:
        logging.error(f"file not found — {exc}")
        return 1
    except FileExistsError as exc:
        logging.error(str(exc))
        return 1
    except KeyboardInterrupt:
        logging.info("Interrupted.")
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
    print("Share the .pub file with anyone who should be able to receive files from you, or whose files you want to send to.")


def _cmd_show_id(args: argparse.Namespace) -> None:
    """Print the key ID (first 8 bytes of SHA-256(x25519_pubkey)) for an identity."""
    identity = load_identity(Path(args.identity))
    print(f"Key ID  : {identity.key_id.hex()}")
    print(f"X25519  : {identity.x25519_pubkey.hex()}")
    print(f"Ed25519 : {identity.ed25519_pubkey.hex()}")


def _cmd_register(args: argparse.Namespace) -> None:
    import urllib.request
    import json
    from secxfer.keystore import get_unused_prekeys
    
    identity = load_identity(Path(args.identity))
    prekeys = get_unused_prekeys(Path(args.identity).parent, args.name)
    if not prekeys:
        logging.error("No unused pre-keys found. Generate with keygen.")
        return
    
    full_pubkey = identity.x25519_pubkey + identity.ed25519_pubkey
    payload = {
        "name": args.name,
        "identity_pubkey": full_pubkey.hex(),
        "prekeys": prekeys
    }
    req = urllib.request.Request(
        args.server + "/register", 
        data=json.dumps(payload).encode(), 
        headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req) as response:
            logging.info(f"Registered successfully: {response.read().decode()}")
    except Exception as exc:
        logging.error(f"Registration failed: {exc}")


def _cmd_pin(args: argparse.Namespace) -> None:
    import urllib.request
    import json
    req = urllib.request.Request(args.server + "/keys/" + args.name)
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
    except Exception as exc:
        logging.error(f"Failed to fetch key for {args.name}: {exc}")
        return

    ident_hex = data["identity_pubkey"]
    logging.info(f"Server provided identity key for {args.name}: {ident_hex}")
    ans = input("Trust this fingerprint? [y/N]: ")
    if ans.strip().lower() == 'y':
        keystore_dir = Path(args.keystore)
        keystore_dir.mkdir(parents=True, exist_ok=True)
        pub_path = keystore_dir / f"{args.name}.pub"
        pub_path.write_bytes(bytes.fromhex(ident_hex))
        logging.info(f"Pinned {args.name} in {pub_path}")
    else:
        logging.info("Pinning aborted.")


def _cmd_send(args: argparse.Namespace) -> None:
    """Encrypt and send a file to stdout (or --out FILE)."""
    from secxfer.client import SecXferClient
    
    file_path = Path(args.file)
    # Determine out stream
    out_f = None
    if args.out:
        out_path = Path(args.out)
        out_f = out_path.open("wb")
    else:
        out_f = sys.stdout.buffer

    try:
        # Default to identity's parent dir for keystore if not specified (for P2P mode)
        keystore_dir = Path(args.keystore) if args.keystore else Path(args.identity).parent
        client = SecXferClient(args.identity, keystore_dir)
        
        client.send(
            receiver_name=args.to,
            file_path=file_path,
            out_stream=out_f,
            server_url=args.server,
            ttl_seconds=args.ttl
        )
            
        if args.out:
            logging.info(f"Sent: {file_path} → {out_path}")
            
    finally:
        if args.out and out_f:
            out_f.close()


def _cmd_receive(args: argparse.Namespace) -> None:
    """Decrypt and verify a file from stdin (or --in FILE) to DEST."""
    from secxfer.client import SecXferClient
    client = SecXferClient(args.identity, args.keystore)

    dest_path = Path(args.dest)

    if args.input:
        inp_path = Path(args.input)
        with inp_path.open("rb") as inp_f:
            client.receive(args.name, inp_f, dest_path)
    else:
        inp_stream = sys.stdin.buffer
        client.receive(args.name, inp_stream, dest_path)

    logging.info(f"Received: → {dest_path}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secxfer",
        description=(
            "Cryptographically secure file transfer using pre-shared keys.\n"
            "Primitives: X25519 + HKDF-SHA256, XChaCha20-Poly1305 (secretstream), Ed25519.\n"
            "Supports V1 (P2P) and V2 (Forward Secrecy / Server-Assisted) modes."
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

    # ── register ────────────────────────────────────────────────────────────
    p_reg = sub.add_parser(
        "register",
        help="upload identity and pre-keys to the key server",
    )
    p_reg.add_argument("--identity", required=True, metavar="KEY")
    p_reg.add_argument("--name", required=True, metavar="NAME")
    p_reg.add_argument("--server", required=True, metavar="URL")
    p_reg.set_defaults(func=_cmd_register)

    # ── pin ─────────────────────────────────────────────────────────────────
    p_pin = sub.add_parser(
        "pin",
        help="fetch a peer's identity key from the server and interactively pin it",
    )
    p_pin.add_argument("--name", required=True, metavar="NAME")
    p_pin.add_argument("--server", required=True, metavar="URL")
    p_pin.add_argument("--keystore", required=True, metavar="DIR")
    p_pin.set_defaults(func=_cmd_pin)

    # ── send ────────────────────────────────────────────────────────────────
    p_send = sub.add_parser(
        "send",
        help="encrypt and send a file (writes to stdout or --out FILE)",
        description=(
            "Encrypts FILE using the receiver's pre-key from the server.\n"
            "Output goes to stdout by default (pipe to receiver) or to --out FILE."
        ),
    )
    p_send.add_argument("file", metavar="FILE", help="plaintext file to send")
    p_send.add_argument("--identity", required=True, metavar="KEY", help="sender's .key file")
    p_send.add_argument("--to", required=True, metavar="NAME", help="receiver's name (V2) or path to .pub file (V1)")
    p_send.add_argument("--server", default=None, metavar="URL", help="key server URL (triggers V2 Forward Secrecy mode)")
    p_send.add_argument("--keystore", default=None, metavar="DIR", help="pinned keystore directory (required for V2)")
    p_send.add_argument("--ttl", type=int, default=300, metavar="SECS")
    p_send.add_argument("--out", metavar="FILE", default=None)
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
        "--name", required=True, metavar="NAME",
        help="receiver's name (used for pre-key consumption)"
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
