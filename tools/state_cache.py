#!/usr/bin/env python3
"""Encrypt the complete runtime state before uploading it to a public Actions cache."""
import argparse
import io
import os
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HEADER = b"SECNEWS-STATE-CACHE\x00\x01"
MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 1024


class StateCacheError(RuntimeError):
    pass


def cache_key(token):
    if not token or not token.strip():
        raise StateCacheError("state cache encryption key is missing")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"secnews Actions state cache v1").derive(token.strip().encode())


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name
            or any(part in (".", "..") for part in path.parts) or "\\" in name or ":" in name):
        raise StateCacheError("unsafe state cache entry")
    return path


def seal(folder, archive, token):
    key = cache_key(token)
    if not folder.is_dir() or folder.is_symlink():
        raise StateCacheError("runtime state directory is missing or unsafe")
    buffer, size, count = io.BytesIO(), 0, 0
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as packed:
        for path in sorted(folder.rglob("*")):
            if path.is_symlink():
                raise StateCacheError("runtime state must not contain symlinks")
            if path.is_dir():
                continue
            if not path.is_file():
                raise StateCacheError("runtime state contains a special file")
            name = path.relative_to(folder).as_posix()
            safe_name(name)
            size += path.stat().st_size
            count += 1
            if size > MAX_BYTES or count > MAX_FILES:
                raise StateCacheError("runtime state exceeds the cache size limit")
            packed.write(path, arcname=name)
    nonce = os.urandom(12)
    encrypted = HEADER + nonce + AESGCM(key).encrypt(nonce, buffer.getvalue(), HEADER)
    archive.parent.mkdir(parents=True, exist_ok=True)
    temp = archive.with_suffix(".tmp")
    temp.write_bytes(encrypted)
    temp.replace(archive)
    return count


def restore(archive, folder, token):
    key = cache_key(token)
    if archive.stat().st_size > MAX_BYTES * 2:
        raise StateCacheError("encrypted state cache exceeds the size limit")
    raw = archive.read_bytes()
    if not raw.startswith(HEADER) or len(raw) < len(HEADER) + 12 + 16:
        raise StateCacheError("invalid encrypted state cache format")
    nonce = raw[len(HEADER):len(HEADER) + 12]
    try:
        plain = AESGCM(key).decrypt(nonce, raw[len(HEADER) + 12:], HEADER)
    except InvalidTag:
        raise StateCacheError("state cache authentication failed; refusing to reset runtime state") from None
    # Validate and unpack completely before touching the destination. Never turn a bad cache
    # into an empty seen list, and never write archive paths outside the state directory.
    contents, size = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(plain)) as packed:
            entries = packed.infolist()
            if len(entries) > MAX_FILES:
                raise StateCacheError("too many state cache entries")
            for entry in entries:
                name = entry.filename
                safe_name(name)
                kind = stat.S_IFMT(entry.external_attr >> 16)
                if name in contents or entry.is_dir() or kind not in (0, stat.S_IFREG):
                    raise StateCacheError("unsafe or duplicate state cache entry")
                size += entry.file_size
                if size > MAX_BYTES:
                    raise StateCacheError("unpacked state exceeds the cache size limit")
                contents[name] = packed.read(entry)
    except (zipfile.BadZipFile, RuntimeError, ValueError) as error:
        if isinstance(error, StateCacheError):
            raise
        raise StateCacheError("invalid state cache archive") from None
    if folder.is_symlink() or (folder.exists() and (not folder.is_dir() or any(folder.iterdir()))):
        raise StateCacheError("refusing to overwrite existing runtime state")
    folder.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".state-restore-", dir=folder.parent) as temp:
        stage = Path(temp) / "state"
        stage.mkdir(mode=0o700)
        for name, data in contents.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o600)
        if folder.exists():
            folder.rmdir()  # only an empty directory can reach this point
        stage.replace(folder)
    return len(contents)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("seal", "open"))
    parser.add_argument("--state", type=Path, default=Path(".state"))
    parser.add_argument("--archive", type=Path, default=Path(".state-cache/state.enc"))
    args = parser.parse_args()
    try:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        count = (seal(args.state, args.archive, token) if args.operation == "seal" else
                 restore(args.archive, args.state, token))
    except (StateCacheError, OSError):
        # Do not include filenames, payloads, keys or provider URLs in public logs.
        print("error: encrypted state cache operation failed; runtime state was not reset", file=sys.stderr)
        return 1
    print(f"state cache: {args.operation} succeeded ({count} files, encrypted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
