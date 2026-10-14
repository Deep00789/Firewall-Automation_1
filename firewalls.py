"""Firewall inventory: the list of Sophos firewalls this portal can connect to.

Stored in <DATA_DIR>/firewalls.json. Passwords are encrypted with Fernet (credential_store).
"""
import csv
import io
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import config
import credential_store
import Sophos_Login_And_Sendrequest as sophoslogin

FIREWALLS_FILE = config.data_path("firewalls.json")
CSV_COLUMNS = ["Name", "URL", "Username", "Password", "Site", "Notes"]
CHECK_TIMEOUT = 8  # seconds per firewall for status checks
_lock = threading.Lock()
_status = {}  # id -> {"ok", "message", "time"}  (in memory; refreshed by tests)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load():
    if not os.path.exists(FIREWALLS_FILE):
        return []
    with open(FIREWALLS_FILE, encoding="utf-8") as f:
        return json.load(f)


def _save(items):
    config.write_json(FIREWALLS_FILE, items)


def _public(fw):
    return {k: fw.get(k, "") for k in ("id", "name", "url", "username", "site", "notes", "created_by", "created_at")} | {
        "status": _status.get(fw["id"])}


def _normalize_url(url):
    url = (url or "").strip().rstrip("/")
    if url and "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ValueError(f"Invalid firewall URL: '{url}'. Example: https://192.168.1.1:4444")
    return url


def _validate(items, name, url, username, skip_id=None):
    name = (name or "").strip()
    if not name:
        raise ValueError("Firewall name is required.")
    if len(name) > 64:
        raise ValueError("Firewall name must be 64 characters or less.")
    if not (username or "").strip():
        raise ValueError("Firewall username is required.")
    if any(f["name"].lower() == name.lower() and f["id"] != skip_id for f in items):
        raise ValueError(f"A firewall named '{name}' already exists.")
    return name, _normalize_url(url), username.strip()


def migrate_legacy():
    """Import the old single remembered firewall as the first inventory entry."""
    with _lock:
        if os.path.exists(FIREWALLS_FILE):
            return
        saved = credential_store.load()
        items = []
        if saved:
            url, username, password = saved
            items.append({"id": uuid.uuid4().hex[:12], "name": "Default firewall", "url": url, "username": username,
                          "password": credential_store.encrypt(password), "site": "", "notes": "Migrated from single-firewall setup",
                          "created_by": "system", "created_at": _now()})
        _save(items)


def list_firewalls():
    return sorted((_public(f) for f in _load()), key=lambda f: (f["site"].lower(), f["name"].lower()))


def get(fw_id, with_password=False):
    for f in _load():
        if f["id"] == fw_id:
            if not with_password:
                return _public(f)
            try:
                password = credential_store.decrypt(f["password"])
            except OSError as e:
                raise ValueError(f"Cannot decrypt the password of '{f['name']}': {e} Edit the firewall and re-enter the password.")
            return _public(f) | {"password": password}
    raise ValueError("Firewall not found. It may have been deleted.")


def add(name, url, username, password, site="", notes="", created_by=""):
    with _lock:
        items = _load()
        name, url, username = _validate(items, name, url, username)
        if not password:
            raise ValueError("Firewall password is required.")
        fw = {"id": uuid.uuid4().hex[:12], "name": name, "url": url, "username": username,
              "password": credential_store.encrypt(password), "site": (site or "").strip(), "notes": (notes or "").strip(),
              "created_by": created_by, "created_at": _now()}
        items.append(fw)
        _save(items)
        return _public(fw)


def update(fw_id, name, url, username, password="", site="", notes=""):
    """Update a firewall. An empty password keeps the current one."""
    with _lock:
        items = _load()
        fw = next((f for f in items if f["id"] == fw_id), None)
        if fw is None:
            raise ValueError("Firewall not found.")
        name, url, username = _validate(items, name, url, username, skip_id=fw_id)
        changed = [k for k, v in (("name", name), ("url", url), ("username", username),
                                  ("site", (site or "").strip()), ("notes", (notes or "").strip())) if fw.get(k, "") != v]
        fw.update(name=name, url=url, username=username, site=(site or "").strip(), notes=(notes or "").strip())
        if password:
            fw["password"] = credential_store.encrypt(password)
            changed.append("password")
        _save(items)
        _status.pop(fw_id, None)
        return _public(fw), changed


def delete(fw_id):
    with _lock:
        items = _load()
        fw = next((f for f in items if f["id"] == fw_id), None)
        if fw is None:
            raise ValueError("Firewall not found.")
        _save([f for f in items if f["id"] != fw_id])
        _status.pop(fw_id, None)
        return fw["name"]


def import_csv(text, created_by=""):
    """Add firewalls from CSV (Name,URL,Username,Password,Site,Notes). Returns per-row results."""
    reader = csv.DictReader(io.StringIO(text))
    headers = {(h or "").strip().lower(): h for h in reader.fieldnames or []}
    missing = [c for c in ("Name", "URL", "Username", "Password") if c.lower() not in headers]
    if missing:
        raise ValueError(f"CSV is missing column(s): {', '.join(missing)}. Expected: {','.join(CSV_COLUMNS)}")
    col = lambda row, c: (row.get(headers.get(c.lower(), ""), "") or "").strip()
    results = []
    for line, row in enumerate(reader, start=2):
        if not any((v or "").strip() for v in row.values()):
            continue
        name = col(row, "Name")
        try:
            add(name, col(row, "URL"), col(row, "Username"), col(row, "Password"), col(row, "Site"), col(row, "Notes"), created_by)
            results.append({"line": line, "name": name, "ok": True, "reason": ""})
        except ValueError as e:
            results.append({"line": line, "name": name, "ok": False, "reason": str(e)})
    return results


def template_csv():
    return ",".join(CSV_COLUMNS) + "\nHQ-Firewall,https://192.168.1.1:4444,admin,ChangeMe,Head Office,Main building\n"


def test(fw_id, timeout=CHECK_TIMEOUT):
    """Try to log in to one firewall. Records and returns its status."""
    try:
        fw = get(fw_id, with_password=True)
        with sophoslogin.using(fw["url"], fw["username"], fw["password"], timeout=timeout):
            sophoslogin.login()
        result = {"ok": True, "message": "Reachable, login successful"}
    except (sophoslogin.SophosError, ValueError) as e:
        result = {"ok": False, "message": str(e)}
    result["time"] = _now()
    _status[fw_id] = result
    return result


def test_all(workers=16):
    """Check every firewall in parallel. Returns {id: status}."""
    ids = [f["id"] for f in _load()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(ids, pool.map(test, ids)))
