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
