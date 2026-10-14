"""Encryption for firewall passwords (used by firewalls.py). Works on Linux and Windows.

Passwords are encrypted with Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography`
package). The key comes from:

  1. the FIREWALL_KEY environment variable (recommended for servers / Docker), or
  2. the file <DATA_DIR>/.firewall.key, created automatically on first use.

Anyone with the key can decrypt the passwords, so keep it secret and back it up:
without it, every firewall password must be re-entered.
Generate a key with:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Older versions encrypted with Windows DPAPI. On Windows those values can still be read,
and `python migrate_credentials.py` converts them to Fernet so the inventory can be moved
to a Linux server.

Also reads the old single "remembered" firewall file, which is migrated into the inventory.
"""
import json
import os
import sys
import threading

from cryptography.fernet import Fernet, InvalidToken

import config

CREDS_FILE = config.data_path("firewall_credentials.json")
KEY_FILE = config.data_path(".firewall.key")
_lock = threading.Lock()
_fernet = None


def _load_key():
    key = os.environ.get("FIREWALL_KEY", "").strip()
    if key:
        return key.encode()
    with _lock:
        if not os.path.exists(KEY_FILE):
            new_key = Fernet.generate_key()
            # Create the file readable by the owner only.
            fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(new_key)
            print(f"[credential_store] Created new encryption key: {KEY_FILE} - back it up!", file=sys.stderr)
        with open(KEY_FILE, "rb") as f:
            return f.read().strip()


def _cipher():
    global _fernet
    if _fernet is None:
        try:
            _fernet = Fernet(_load_key())
        except ValueError as e:
            raise RuntimeError("FIREWALL_KEY / .firewall.key is not a valid Fernet key (32 url-safe base64 bytes).") from e
    return _fernet


def is_fernet(token):
    return isinstance(token, str) and token.startswith("gAAAAA")


def encrypt(text):
    return _cipher().encrypt(text.encode("utf-8")).decode()


def decrypt(token):
    """Decrypt a stored password. Raises OSError if it cannot be decrypted with this key."""
    if is_fernet(token):
        try:
            return _cipher().decrypt(token.encode()).decode("utf-8")
        except InvalidToken:
            raise OSError("Password was encrypted with a different key (check FIREWALL_KEY).")
    if sys.platform == "win32":
        return _dpapi_decrypt(token)  # legacy value from older versions
    raise OSError("Password was encrypted with Windows DPAPI and cannot be read on this system.")


# ---- Legacy Windows DPAPI (read-only, Windows only)
def _dpapi_decrypt(token):
    import base64
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    data = base64.b64decode(token)
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData).decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ---- Old single-firewall file (migrated into firewalls.json by firewalls.migrate_legacy)
def exists():
    return os.path.exists(CREDS_FILE)


def save(firewall_url, username, password):
    with open(CREDS_FILE, "w", encoding="utf-8") as f:
        json.dump({"firewall_url": firewall_url, "username": username, "password": encrypt(password)}, f, indent=2)


def load():
    """Return (firewall_url, username, password) or None if nothing saved / unreadable."""
    if not exists():
        return None
    try:
        with open(CREDS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data["firewall_url"], data["username"], decrypt(data["password"])
    except (OSError, ValueError, KeyError):
        return None  # corrupt, other key, or DPAPI value on Linux


def forget():
    if exists():
        os.remove(CREDS_FILE)
