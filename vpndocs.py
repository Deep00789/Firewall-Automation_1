"""VPN documentation: a manual record of site-to-site VPN tunnels.

Stored in <DATA_DIR>/vpndocs.json. This is documentation only; nothing is read from or pushed to a firewall.
"""
import csv
import io
import ipaddress
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone

import config

FILE = config.data_path("vpndocs.json")
CSV_COLUMNS = ["VPN Name", "Local GW", "Remote GW", "Local Subnet", "Remote Subnet", "Description"]
KEYS = ["name", "local_gw", "remote_gw", "local_subnet", "remote_subnet", "description"]
_ALIASES = {"description": ("description", "descriptions")}
_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load():
    if not os.path.exists(FILE):
        return []
    with open(FILE, encoding="utf-8") as f:
        return json.load(f)


def _save(items):
    config.write_json(FILE, items)


def _gateway(value, label):
    """An IPv4 address or a DNS name (a remote gateway is often a hostname)."""
    if not value:
        raise ValueError(f"{label} is required.")
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", value) or not _HOST_RE.match(value):
        raise ValueError(f"{label} '{value}' is not a valid IPv4 address or host name.")
    return value


def _subnets(value, label):
    """One or more IPv4 networks / addresses separated by commas, semicolons, spaces or new lines."""
    tokens = [t for t in re.split(r"[,;\s]+", value or "") if t]
    if not tokens:
        raise ValueError(f"{label} is required.")
    for t in tokens:
        try:
            ipaddress.IPv4Network(t, strict=False)
        except ValueError:
            raise ValueError(f"{label} '{t}' is not a valid IPv4 address or network (e.g. 10.0.0.0/24).")
    return ", ".join(tokens)


def _clean(d):
    g = lambda k: str(d.get(k) or "").strip()
    rec = {"name": g("name"), "local_gw": _gateway(g("local_gw"), "Local GW"), "remote_gw": _gateway(g("remote_gw"), "Remote GW"),
           "local_subnet": _subnets(g("local_subnet"), "Local Subnet"), "remote_subnet": _subnets(g("remote_subnet"), "Remote Subnet"),
           "description": g("description")}
    if not rec["name"]:
        raise ValueError("VPN name is required.")
    for k, limit in (("name", 128), ("description", 1000)):
        if len(rec[k]) > limit:
            raise ValueError(f"{k.capitalize()} must be {limit} characters or less.")
    return rec


def _check_dup(items, rec, skip_id=None):
    if any(r["id"] != skip_id and r["name"].lower() == rec["name"].lower() for r in items):
        raise ValueError(f"A VPN named '{rec['name']}' is already documented.")


def list_all():
    return sorted(_load(), key=lambda r: r["name"].lower())


def add(data, user=""):
    rec = _clean(data)
    with _lock:
        items = _load()
        _check_dup(items, rec)
        rec |= {"id": uuid.uuid4().hex[:12], "created_by": user, "created_at": _now(), "updated_by": user, "updated_at": _now()}
        items.append(rec)
        _save(items)
        return rec


def update(rec_id, data, user=""):
    """Returns (record, names of changed fields)."""
    rec = _clean(data)
    with _lock:
        items = _load()
        cur = next((r for r in items if r["id"] == rec_id), None)
        if cur is None:
            raise ValueError("VPN record not found. It may have been deleted.")
        _check_dup(items, rec, skip_id=rec_id)
        changed = [k for k in KEYS if cur.get(k, "") != rec[k]]
        cur.update(rec, updated_by=user, updated_at=_now())
        _save(items)
        return cur, changed


def delete_many(ids):
    """Delete records. Returns the deleted records."""
    ids = set(ids)
    with _lock:
        items = _load()
        gone = [r for r in items if r["id"] in ids]
        if not gone:
            raise ValueError("None of the selected records exist any more.")
        _save([r for r in items if r["id"] not in ids])
        return gone


def _norm(header):
    return re.sub(r"[^a-z]", "", (header or "").lower())


def import_csv(text, user=""):
    """Add records from CSV. Headers are matched ignoring case, spaces and underscores. Returns per-row results."""
    reader = csv.DictReader(io.StringIO(text))
    by_norm = {_norm(h): h for h in reader.fieldnames or []}
    names = {k: _ALIASES.get(k, (_norm(c),)) for k, c in zip(KEYS, CSV_COLUMNS)}
    column = {k: next((by_norm[n] for n in ns if n in by_norm), None) for k, ns in names.items()}
    missing = [c for k, c in zip(KEYS, CSV_COLUMNS) if k != "description" and column[k] is None]
    if missing:
        raise ValueError(f"CSV is missing column(s): {', '.join(missing)}. Expected: {','.join(CSV_COLUMNS)}")
    results = []
    for line, row in enumerate(reader, start=2):
        if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
            continue
        data = {k: (row.get(c) if c else "") for k, c in column.items()}
        label = (data["name"] or "").strip() or "(no name)"
        try:
            add(data, user)
            results.append({"line": line, "name": label, "ok": True, "reason": ""})
        except ValueError as e:
            results.append({"line": line, "name": label, "ok": False, "reason": str(e)})
    return results


def _safe(v):
    """Neutralise spreadsheet formulas in exported text."""
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def to_csv(items):
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for r in items:
        w.writerow([_safe(str(r.get(k, ""))) for k in KEYS])
    return "﻿" + out.getvalue()


def template_csv():
    return (",".join(CSV_COLUMNS) + "\n"
            'Pune-to-Mumbai,203.0.113.10,198.51.100.20,"192.168.1.0/24, 192.168.2.0/24",10.20.0.0/16,Site-to-site IPsec\n')
