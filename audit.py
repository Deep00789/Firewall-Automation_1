"""Audit log: who did what in the portal, and when.

Entries are appended as one JSON object per line to audit.log (never edited or deleted by the app).
"""
import csv
import io
import json
import os
import threading
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "audit.log")
CATEGORIES = ("auth", "firewall", "iphost", "machost", "dhcp", "users", "audit")
_lock = threading.Lock()


def log(user, category, action, target="", details="", ok=True, ip="", firewall=""):
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": (user or "-")[:64],
        "category": category,
        "action": action,
        "target": str(target)[:200],
        "details": str(details)[:2000],
        "ok": bool(ok),
        "ip": ip or "",
        "firewall": (firewall or "")[:64],
    }
    with _lock, open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _parse_time(value):
    """ISO date or datetime (e.g. from the browser's toISOString) -> aware UTC datetime, or None."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"Invalid date: {value}")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def read(user="", category="", q="", date_from="", date_to="", result="", firewall="", limit=500):
    """Return matching entries, newest first. date_from/date_to are ISO datetimes (inclusive)."""
    if not os.path.exists(LOG_FILE):
        return []
    q = q.lower().strip()
    start, end = _parse_time(date_from), _parse_time(date_to)
    matches = []
    with _lock, open(LOG_FILE, encoding="utf-8") as f:
        lines = f.readlines()
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if user and e["user"] != user:
            continue
        if category and e["category"] != category:
            continue
        if firewall and e.get("firewall", "") != firewall:
            continue
        if result == "ok" and not e["ok"] or result == "failed" and e["ok"]:
            continue
        if start or end:
            t = _parse_time(e["time"])
            if start and t < start or end and t > end:
                continue
        if q and q not in " ".join(str(e.get(k, "")) for k in ("user", "firewall", "action", "target", "details")).lower():
            continue
        matches.append(e)
        if limit and len(matches) >= limit:
            break
    return matches


def users_in_log():
    return sorted({e["user"] for e in read(limit=0)}, key=str.lower)


def firewalls_in_log():
    return sorted({e.get("firewall", "") for e in read(limit=0)} - {""}, key=str.lower)


def to_csv(entries):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["Time (UTC)", "User", "Firewall", "Category", "Action", "Target", "Details", "Result", "IP"])
    for e in entries:
        writer.writerow([e["time"], e["user"], e.get("firewall", ""), e["category"], e["action"], e["target"], e["details"],
                         "Success" if e["ok"] else "Failed", e["ip"]])
    return out.getvalue()
