"""Windows DPAPI encryption for firewall passwords (used by firewalls.py).

Also reads the old single "remembered" firewall file, which is migrated into the inventory.

The password can only be decrypted by the same Windows user on the same computer.
"""
import base64
import ctypes
import ctypes.wintypes as wt
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDS_FILE = os.path.join(BASE_DIR, "firewall_credentials.json")
CRYPTPROTECT_UI_FORBIDDEN = 0x1


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _crypt(func, data):
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not func(ctypes.byref(blob_in), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def encrypt(text):
    return base64.b64encode(_crypt(ctypes.windll.crypt32.CryptProtectData, text.encode("utf-8"))).decode()


def decrypt(token):
    return _crypt(ctypes.windll.crypt32.CryptUnprotectData, base64.b64decode(token)).decode("utf-8")


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
        return None  # corrupt, or saved by another Windows user


def forget():
    if exists():
        os.remove(CREDS_FILE)
