"""Shared paths and settings, read from environment variables.

DATA_DIR   Folder for runtime data (users.json, firewalls.json, audit.log, keys).
           Default: the project folder (same behaviour as before).
           In Docker this is /data, mounted as a volume so data survives rebuilds.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.environ.get("DATA_DIR") or BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)


def data_path(name):
    """Absolute path of a runtime data file inside DATA_DIR."""
    return os.path.join(DATA_DIR, name)


def env_bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def write_json(path, data):
    """Save JSON safely: write a temp file, then swap it in.

    If the file is bind-mounted on its own in Docker (e.g. ./users.json:/app/users.json),
    it cannot be swapped (OSError 16 "Device or resource busy"), so write it in place instead.
    """
    import errno
    import json

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.replace(tmp, path)
    except OSError as e:
        if e.errno not in (errno.EBUSY, errno.EXDEV, errno.EPERM, errno.EACCES):
            raise
        os.remove(tmp)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
