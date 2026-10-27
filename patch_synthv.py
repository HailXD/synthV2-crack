import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


APP_DIR = Path(r"C:\Program Files\Synthesizer V Studio 2 Pro")
TARGET = APP_DIR / "synthv-studio.exe"
BACKUP = APP_DIR / "synthv-studio.exe.original"
MANIFEST = APP_DIR / "synthv-patches.json"
ORIGINAL_SHA256 = "7d81044df4827d21a1f232d2eb42d37d5ac87648abfb406a34f027e4e74ca35b"
ACTIONS = ("inspect", "patch", "unpatch")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_manifest():
    require(
        MANIFEST.is_file(),
        "No verified patch manifest exists. Trial removal is not implemented. "
        "No files changed.",
    )
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(isinstance(manifest, dict), "Manifest must be an object")
    require(
        manifest.get("original_sha256") == ORIGINAL_SHA256,
        "Manifest does not target the inspected executable",
    )
    patched_hash = manifest.get("patched_sha256", "")
    require(
        isinstance(patched_hash, str)
        and len(patched_hash) == 64
        and all(c in "0123456789abcdef" for c in patched_hash)
        and patched_hash != ORIGINAL_SHA256,
        "Manifest requires a distinct, verified patched SHA-256",
    )
    patches = manifest.get("patches")
    require(isinstance(patches, list) and patches, "Manifest has no verified patches")
    return manifest


def patched_image(original, manifest):
    require(digest(original) == ORIGINAL_SHA256, "Original SHA-256 mismatch")
    changes = []
    for patch in manifest["patches"]:
        require(isinstance(patch, dict), "Each patch must be an object")
        offset = patch.get("offset")
        require(type(offset) is int and offset >= 0, "Invalid file offset")
        before_hex = patch.get("before")
        after_hex = patch.get("after")
        require(
            isinstance(before_hex, str) and isinstance(after_hex, str),
            "Patch bytes must be hexadecimal strings",
        )
        before = bytes.fromhex(before_hex)
        after = bytes.fromhex(after_hex)
        require(before and len(before) == len(after), "Patches must preserve length")
        require(before != after, "Patch does not change any bytes")
        end = offset + len(before)
        require(end <= len(original), "Patch exceeds executable size")
        require(original[offset:end] == before, "Expected original bytes mismatch")
        changes.append((offset, end, after))
    changes.sort()
    result = bytearray(original)
    previous_end = 0
    for offset, end, after in changes:
        require(offset >= previous_end, "Overlapping patches")
        result[offset:end] = after
        previous_end = end
    require(digest(result) == manifest["patched_sha256"], "Patched SHA-256 mismatch")
    return bytes(result)


def save_backup(original):
    if BACKUP.exists():
        require(BACKUP.read_bytes() == original, "Existing backup differs; not overwriting")
        return
    with BACKUP.open("xb") as stream:
        stream.write(original)
        stream.flush()
        os.fsync(stream.fileno())
    require(BACKUP.read_bytes() == original, "Backup verification failed")


def replace_target(expected, replacement):
    require(TARGET.read_bytes() == expected, "Executable changed during operation")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=APP_DIR, prefix=".synthv-", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        shutil.copystat(TARGET, temporary)
        require(temporary.read_bytes() == replacement, "Temporary file verification failed")
        require(TARGET.read_bytes() == expected, "Executable changed during operation")
        os.replace(temporary, TARGET)
        require(TARGET.read_bytes() == replacement, "Replacement verification failed")
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def inspect():
    image = TARGET.read_bytes()
    fingerprint = digest(image)
    print(f"Executable: {TARGET}")
    print(f"Bytes: {len(image)}")
    print(f"SHA-256: {fingerprint}")
    print(f"Matches inspected original: {fingerprint == ORIGINAL_SHA256}")
    print(f"Backup exists: {BACKUP.exists()}")
    print(f"Manifest exists: {MANIFEST.exists()}")
    print("Trial removal is not implemented; verified patch locations are unavailable.")


def patch():
    manifest = load_manifest()
    current = TARGET.read_bytes()
    if digest(current) == manifest["patched_sha256"]:
        require(BACKUP.is_file(), "Already patched, but the original backup is missing")
        require(
            patched_image(BACKUP.read_bytes(), manifest) == current,
            "Backup does not reproduce the patched executable",
        )
        print("Already patched; no changes.")
        return
    replacement = patched_image(current, manifest)
    save_backup(current)
    replace_target(current, replacement)
    print(f"Patched: {TARGET}\nOriginal retained: {BACKUP}")


def unpatch():
    current = TARGET.read_bytes()
    if digest(current) == ORIGINAL_SHA256:
        print("Already original; no changes.")
        return
    manifest = load_manifest()
    original = BACKUP.read_bytes()
    require(
        current == patched_image(original, manifest),
        "Executable is not the expected patched image; refusing to overwrite",
    )
    replace_target(current, original)
    print(f"Restored original bytes: {TARGET}\nBackup retained: {BACKUP}")


def main():
    args = sys.argv[1:]
    require(len(args) <= 1, "Usage: python patch_synthv.py [inspect|patch|unpatch]")
    action = args[0] if args else "inspect"
    require(action in ACTIONS, "Usage: python patch_synthv.py [inspect|patch|unpatch]")
    {"inspect": inspect, "patch": patch, "unpatch": unpatch}[action]()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
