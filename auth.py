"""App users for the GUI login page. Passwords are stored hashed in users.json.

users.json format: {"alice": {"hash": "<werkzeug hash>", "role": "admin" | "user"}}
Old entries of the form {"alice": "<hash>"} are read as admins.
"""
import json
import os
import re
import time

from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

ROLES = ("admin", "user")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
MIN_PASSWORD_LENGTH = 8

MAX_FAILURES = 5
LOCKOUT_SECONDS = 5 * 60
_failures = {}  # username -> list of failure timestamps
_DUMMY_HASH = generate_password_hash("dummy-password")


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, encoding="utf-8") as f:
        raw = json.load(f)
    return {name: {"hash": v, "role": "admin"} if isinstance(v, str) else v for name, v in raw.items()}


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def get_user(username):
    return load_users().get(username)


def list_users():
    return [{"username": name, "role": u["role"]} for name, u in sorted(load_users().items(), key=lambda x: x[0].lower())]


def _check_password(password):
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")


def _check_role(role):
    if role not in ROLES:
        raise ValueError(f"Role must be one of: {', '.join(ROLES)}.")


def _admin_count(users):
    return sum(1 for u in users.values() if u["role"] == "admin")


def create_user(username, password, role="user"):
    if not USERNAME_RE.match(username or ""):
        raise ValueError("Username must be 3-32 characters: letters, numbers, dot, dash or underscore.")
    _check_password(password)
    _check_role(role)
    users = load_users()
    if any(name.lower() == username.lower() for name in users):
        raise ValueError(f"User '{username}' already exists.")
    users[username] = {"hash": generate_password_hash(password), "role": role}
    save_users(users)


def set_password(username, password):
    _check_password(password)
    users = load_users()
    if username not in users:
        raise ValueError(f"User '{username}' not found.")
    users[username]["hash"] = generate_password_hash(password)
    save_users(users)


def set_role(username, role):
    _check_role(role)
    users = load_users()
    if username not in users:
        raise ValueError(f"User '{username}' not found.")
    if users[username]["role"] == "admin" and role != "admin" and _admin_count(users) == 1:
        raise ValueError("Cannot remove the last admin.")
    users[username]["role"] = role
    save_users(users)


def delete_user(username):
    users = load_users()
    if username not in users:
        raise ValueError(f"User '{username}' not found.")
    if users[username]["role"] == "admin" and _admin_count(users) == 1:
        raise ValueError("Cannot delete the last admin.")
    del users[username]
    save_users(users)


def set_last_firewall(username, fw_id):
    """Remember the firewall a user last connected to (auto-reconnect on next login)."""
    users = load_users()
    if username in users:
        users[username]["last_firewall"] = fw_id
        save_users(users)


def set_user(username, password, role="admin"):
    """Create or reset a user (used by manage_users.py)."""
    if get_user(username):
        set_password(username, password)
        set_role(username, role)
    else:
        create_user(username, password, role)


def password_stamp(username):
    """Short fingerprint of the password hash; changes whenever the password changes.
    Stored in the session so a password reset logs out existing sessions."""
    user = get_user(username)
    return user["hash"][-16:] if user else None


def is_locked(username):
    now = time.time()
    recent = [t for t in _failures.get(username.lower(), []) if now - t < LOCKOUT_SECONDS]
    _failures[username.lower()] = recent
    return len(recent) >= MAX_FAILURES


def verify(username, password):
    """Check credentials. Returns True/False and records failures for lockout."""
    user = get_user(username)
    # Always run a hash check so unknown users take as long as wrong passwords.
    ok = check_password_hash(user["hash"] if user else _DUMMY_HASH, password) and user is not None
    if ok:
        _failures.pop(username.lower(), None)
    else:
        _failures.setdefault(username.lower(), []).append(time.time())
    return ok
