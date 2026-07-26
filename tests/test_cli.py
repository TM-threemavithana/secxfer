"""
tests/test_cli.py

CLI smoke tests via main() — exercises the argument parsing and the
full send→receive pipeline through the CLI layer.

These are integration tests, not unit tests: they call main() with
synthetic argv and check exit codes and output files.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from secxfer.cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def key_dirs(tmp_path):
    alice_dir = tmp_path / "alice"
    bob_dir = tmp_path / "bob"
    alice_dir.mkdir()
    bob_dir.mkdir()
    return alice_dir, bob_dir


@pytest.fixture()
def alice_bob(key_dirs, tmp_path):
    alice_dir, bob_dir = key_dirs
    main(["keygen", "--dir", str(alice_dir), "--name", "identity"])
    main(["keygen", "--dir", str(bob_dir), "--name", "identity"])
    # Cross-load public keys
    (bob_dir / "alice.pub").write_bytes((alice_dir / "identity.pub").read_bytes())
    (alice_dir / "bob.pub").write_bytes((bob_dir / "identity.pub").read_bytes())
    return alice_dir, bob_dir


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

class TestKeygen:
    def test_creates_key_and_pub_files(self, tmp_path):
        main(["keygen", "--dir", str(tmp_path), "--name", "test"])
        assert (tmp_path / "test.key").exists()
        assert (tmp_path / "test.pub").exists()

    def test_key_file_is_64_bytes(self, tmp_path):
        main(["keygen", "--dir", str(tmp_path)])
        assert len((tmp_path / "identity.key").read_bytes()) == 64

    def test_pub_file_is_64_bytes(self, tmp_path):
        main(["keygen", "--dir", str(tmp_path)])
        assert len((tmp_path / "identity.pub").read_bytes()) == 64

    def test_duplicate_keygen_fails(self, tmp_path):
        main(["keygen", "--dir", str(tmp_path)])
        rc = main(["keygen", "--dir", str(tmp_path)])
        assert rc == 1  # FileExistsError


# ---------------------------------------------------------------------------
# show-id
# ---------------------------------------------------------------------------

class TestShowId:
    def test_exits_zero(self, tmp_path, capsys):
        main(["keygen", "--dir", str(tmp_path)])
        rc = main(["show-id", "--identity", str(tmp_path / "identity.key")])
        assert rc == 0

    def test_prints_key_id(self, tmp_path, capsys):
        main(["keygen", "--dir", str(tmp_path)])
        main(["show-id", "--identity", str(tmp_path / "identity.key")])
        out = capsys.readouterr().out
        assert "Key ID" in out


# ---------------------------------------------------------------------------
# send / receive via files
# ---------------------------------------------------------------------------

class TestSendReceive:
    def _do_transfer(self, alice_dir, bob_dir, src: Path, dest: Path, tmp_path: Path):
        enc = tmp_path / "transfer.bin"
        rc = main([
            "send", str(src),
            "--identity", str(alice_dir / "identity.key"),
            "--to", str(alice_dir / "bob.pub"),
            "--out", str(enc),
        ])
        assert rc == 0, f"send failed with rc={rc}"

        rc = main([
            "receive", str(dest),
            "--identity", str(bob_dir / "identity.key"),
            "--keystore", str(bob_dir),
            "--in", str(enc),
        ])
        assert rc == 0, f"receive failed with rc={rc}"

    def test_small_file_roundtrip(self, alice_bob, tmp_path):
        alice_dir, bob_dir = alice_bob
        src = tmp_path / "hello.txt"
        src.write_bytes(b"hello, secure world")
        dest = tmp_path / "received.txt"
        self._do_transfer(alice_dir, bob_dir, src, dest, tmp_path)
        assert dest.read_bytes() == b"hello, secure world"

    def test_binary_file_roundtrip(self, alice_bob, tmp_path):
        import os
        alice_dir, bob_dir = alice_bob
        data = os.urandom(150_000)
        src = tmp_path / "binary.bin"
        src.write_bytes(data)
        dest = tmp_path / "binary_out.bin"
        self._do_transfer(alice_dir, bob_dir, src, dest, tmp_path)
        assert dest.read_bytes() == data

    def test_missing_file_exits_nonzero(self, alice_bob, tmp_path):
        alice_dir, bob_dir = alice_bob
        rc = main([
            "send", str(tmp_path / "nonexistent.txt"),
            "--identity", str(alice_dir / "identity.key"),
            "--to", str(alice_dir / "bob.pub"),
            "--out", str(tmp_path / "out.bin"),
        ])
        assert rc == 1

    def test_wrong_identity_exits_nonzero(self, alice_bob, tmp_path):
        """Receiving with wrong identity key → AuthenticationError → rc=1."""
        alice_dir, bob_dir = alice_bob
        src = tmp_path / "secret.txt"
        src.write_bytes(b"secret")
        enc = tmp_path / "enc.bin"
        dest = tmp_path / "out.txt"

        main([
            "send", str(src),
            "--identity", str(alice_dir / "identity.key"),
            "--to", str(alice_dir / "bob.pub"),
            "--out", str(enc),
        ])

        # Generate a wrong identity for the receiver
        wrong_dir = tmp_path / "wrong"
        main(["keygen", "--dir", str(wrong_dir)])
        (wrong_dir / "alice.pub").write_bytes(
            (alice_dir / "identity.pub").read_bytes()
        )

        rc = main([
            "receive", str(dest),
            "--identity", str(wrong_dir / "identity.key"),
            "--keystore", str(wrong_dir),
            "--in", str(enc),
        ])
        assert rc == 1
        assert not dest.exists()
