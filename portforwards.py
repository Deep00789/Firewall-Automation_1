"""Port-forwarding documentation: a manual record of NAT / port-forward rules.

Stored in <DATA_DIR>/portforwards.json. This is documentation only; nothing is pushed to a firewall.
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

FILE = config.data_path("portforwards.json")
CSV_COLUMNS = ["Rule_No", "Port", "Public IP", "Private IP", "External Port", "Internal Port", "Requestor", "Sites", "Description"]
KEYS = ["rule_no", "port", "public_ip", "private_ip", "external_port", "internal_port", "requestor", "sites", "description"]
_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?([,/]\d{1,5}(-\d{1,5})?)*$")
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


def _ip(value, label):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise ValueError(f"{label} '{value}' is not a valid IPv4 address.")


def _ports(value, label):
    value = re.sub(r"\s+", "", value or "")
    if not value:
        raise ValueError(f"{label} is required.")
    if not _PORT_RE.match(value):
        raise ValueError(f"{label} '{value}' is invalid. Use a number, a range (8000-8010) or a list (80,443 or 80/443).")
    for part in re.split(r"[,/]", value):
        lo, _, hi = part.partition("-")
        if not 1 <= int(lo) <= 65535 or (hi and not int(lo) <= int(hi) <= 65535):
            raise ValueError(f"{label} '{value}' is out of range (1-65535).")
    return value


def _clean(d):
    """Validate one record's fields and return them normalised."""
    g = lambda k: str(d.get(k) or "").strip()
    rec = {
        "rule_no": g("rule_no"), "port": g("port"),
        "public_ip": _ip(g("public_ip"), "Public IP"), "private_ip": _ip(g("private_ip"), "Private IP"),
        "external_port": _ports(g("external_port"), "External Port"), "internal_port": _ports(g("internal_port"), "Internal Port"),
        "requestor": g("requestor"), "sites": g("sites"), "description": g("description"),
    }
    if not rec["sites"]:
        raise ValueError("Sites is required.")
    for k, limit in (("rule_no", 64), ("port", 64), ("requestor", 128), ("sites", 128), ("description", 1000)):
        if len(rec[k]) > limit:
            raise ValueError(f"{k.replace('_', ' ').capitalize()} must be {limit} characters or less.")
    return rec


def _dup_key(r):
    return (r["public_ip"], r["external_port"], r["port"].lower())


def _check_dup(items, rec, skip_id=None):
    for r in items:
        if r["id"] != skip_id and _dup_key(r) == _dup_key(rec):
            raise ValueError(f"Public IP {rec['public_ip']} external port {rec['external_port']}"
                             f"{' (' + rec['port'] + ')' if rec['port'] else ''} is already documented"
                             f"{' (rule ' + r['rule_no'] + ')' if r['rule_no'] else ''}.")


def list_all():
    return sorted(_load(), key=lambda r: (r["sites"].lower(), r["public_ip"], r["external_port"]))


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
            raise ValueError("Port-forward record not found. It may have been deleted.")
        _check_dup(items, rec, skip_id=rec_id)
        changed = [k for k in KEYS if cur.get(k, "") != rec[k]]
        cur.update(rec, updated_by=user, updated_at=_now())
        _save(items)
        return cur, changed


def delete(rec_id):
    with _lock:
        items = _load()
        cur = next((r for r in items if r["id"] == rec_id), None)
        if cur is None:
            raise ValueError("Port-forward record not found.")
        _save([r for r in items if r["id"] != rec_id])
        return cur


def delete_many(ids):
    """Delete several records at once. Returns the deleted records."""
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
    wanted = {k: _norm(c) for k, c in zip(KEYS, CSV_COLUMNS)}
    missing = [c for k, c in zip(KEYS, CSV_COLUMNS) if k in ("public_ip", "private_ip", "external_port", "internal_port", "sites") and wanted[k] not in by_norm]
    if missing:
        raise ValueError(f"CSV is missing column(s): {', '.join(missing)}. Expected: {','.join(CSV_COLUMNS)}")
    results = []
    for line, row in enumerate(reader, start=2):
        if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
            continue
        data = {k: row.get(by_norm.get(n, ""), "") for k, n in wanted.items()}
        label = f"{(data['public_ip'] or '').strip()}:{(data['external_port'] or '').strip()}"
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
            "1,TCP,203.0.113.10,192.168.1.20,8443,443,John (IT),Pune,Intranet web server\n")
