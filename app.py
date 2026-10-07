"""Web GUI for the Sophos firewall automation scripts.

Run:  firewallautomation\\Scripts\\python.exe app.py   then open http://127.0.0.1:5000
"""
import os
import secrets
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps

from flask import Flask, Response, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for

import audit
import auth
import firewalls
import IPHost
import MACHost
import Sophos_Dhcp
import Sophos_Login_And_Sendrequest as sophoslogin

app = Flask(__name__)
firewalls.migrate_legacy()

# Routes that talk to the firewall the user is connected to (session["fw_id"]).
FIREWALL_ROUTES = ("/api/iphosts", "/api/machosts", "/api/dhcp")


def record(category, action, target="", details="", ok=True, user=None, firewall=None):
    """Write an audit log entry for the current request."""
    audit.log(user or g.get("user") or session.get("user"), category, action, target, details, ok,
              request.remote_addr, firewall if firewall is not None else g.get("fw_name", ""))


def admin_only(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.role != "admin":
            return jsonify({"ok": False, "message": "Only admins can do this."}), 403
        return view(*args, **kwargs)
    return wrapper


@contextmanager
def audited(category, action, target=""):
    """Log a failed entry if the wrapped block raises; the block logs its own success."""
    try:
        yield
    except Exception as e:
        record(category, action, target, f"Error: {e}", ok=False)
        raise


def _secret_key():
    """Use FLASK_SECRET_KEY, else a random key kept in .secret_key so sessions survive restarts."""
    if os.environ.get("FLASK_SECRET_KEY"):
        return os.environ["FLASK_SECRET_KEY"]
    path = os.path.join(auth.BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # idle timeout
)


@app.before_request
def require_login():
    if request.endpoint in ("login", "static", "favicon"):
        return None
    user = auth.get_user(session.get("user", ""))
    # Log out sessions whose user was deleted or whose password was changed/reset elsewhere.
    if not user or session.get("pw") != auth.password_stamp(session["user"]):
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "message": "Session expired. Please log in again."}), 401
        return redirect(url_for("login"))
    g.user, g.role = session["user"], user["role"]
    if request.path.startswith(("/api/users", "/api/audit")) and g.role != "admin":
        return jsonify({"ok": False, "message": "Only admins can do this."}), 403
    if request.path.startswith(FIREWALL_ROUTES):
        if not session.get("fw_id"):
            return jsonify({"ok": False, "message": "No firewall connected. Connect to one on the Firewalls tab."}), 400
        try:
            fw = firewalls.get(session["fw_id"], with_password=True)
        except ValueError as e:
            session.pop("fw_id", None)
            return jsonify({"ok": False, "message": str(e)}), 400
        g.fw_name = fw["name"]
        # Every Sophos call in this request goes to this user's firewall.
        sophoslogin.activate(fw["url"], fw["username"], fw["password"])
    return None


@app.teardown_request
def clear_firewall(_exc):
    sophoslogin.deactivate()


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("index"))
    if not auth.load_users():
        return render_template("login.html", no_users=True)

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if auth.is_locked(username):
            error = "Too many failed attempts. Try again in a few minutes."
            record("auth", "Login blocked", username, "Account temporarily locked after repeated failures", ok=False, user=username)
        elif auth.verify(username, password):
            session.clear()
            session.permanent = True
            session["user"] = username
            session["pw"] = auth.password_stamp(username)
            record("auth", "Login", username, user=username)
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password."
            record("auth", "Login failed", username, "Wrong username or password", ok=False, user=username or "-")
    return render_template("login.html", error=error, username=request.form.get("username", ""))


@app.post("/logout")
def logout():
    if session.get("user"):
        record("auth", "Logout", session["user"])
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(sophoslogin.SophosError)
@app.errorhandler(ValueError)
def handle_error(e):
    return jsonify({"ok": False, "message": str(e)}), 400


@app.get("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/vnd.microsoft.icon")


@app.get("/")
def index():
    return render_template("index.html", user=g.user, role=g.role)


# ---- Account & user management
@app.post("/api/account/password")
def change_own_password():
    data = request.get_json(force=True)
    with audited("users", "Change own password", g.user):
        if not auth.verify(g.user, data.get("current", "")):
            raise ValueError("Current password is incorrect.")
        auth.set_password(g.user, data.get("new", ""))
        record("users", "Change own password", g.user)
    session["pw"] = auth.password_stamp(g.user)  # keep this session logged in
    return jsonify({"ok": True, "message": "Your password has been changed."})


@app.get("/api/users")
def users_list():
    return jsonify({"ok": True, "users": auth.list_users(), "me": g.user})


@app.post("/api/users")
def users_create():
    data = request.get_json(force=True)
    username, role = data.get("username", "").strip(), data.get("role", "user")
    with audited("users", "Create user", username):
        auth.create_user(username, data.get("password", ""), role)
        record("users", "Create user", username, f"Role: {role}")
    return jsonify({"ok": True, "message": f"User '{username}' created."})


@app.delete("/api/users/<username>")
def users_delete(username):
    with audited("users", "Delete user", username):
        if username == g.user:
            raise ValueError("You cannot delete your own account.")
        auth.delete_user(username)
        record("users", "Delete user", username)
    return jsonify({"ok": True, "message": f"User '{username}' deleted."})


@app.post("/api/users/<username>/password")
def users_reset_password(username):
    with audited("users", "Reset password", username):
        auth.set_password(username, request.get_json(force=True).get("password", ""))
        record("users", "Reset password", username, "Password reset by admin; open sessions signed out")
    if username == g.user:
        session["pw"] = auth.password_stamp(g.user)
    return jsonify({"ok": True, "message": f"Password for '{username}' has been reset. Their open sessions are signed out."})


@app.post("/api/users/<username>/role")
def users_set_role(username):
    role = request.get_json(force=True).get("role", "")
    with audited("users", "Change role", username):
        if username == g.user and role != "admin":
            raise ValueError("You cannot remove your own admin role.")
        old_role = (auth.get_user(username) or {}).get("role", "?")
        auth.set_role(username, role)
        record("users", "Change role", username, f"{old_role} → {role}")
    return jsonify({"ok": True, "message": f"'{username}' is now {role}."})


# ---- Activity log (admins only)
def _audit_filters():
    a = request.args
    return dict(user=a.get("user", ""), category=a.get("category", ""), q=a.get("q", ""),
                date_from=a.get("from", ""), date_to=a.get("to", ""), result=a.get("result", ""),
                firewall=a.get("firewall", ""))


@app.get("/api/audit")
def audit_list():
    limit = min(int(request.args.get("limit", 500)), 5000)
    return jsonify({"ok": True, "entries": audit.read(**_audit_filters(), limit=limit),
                    "users": audit.users_in_log(), "firewalls": audit.firewalls_in_log()})


@app.get("/api/audit/export")
def audit_export():
    entries = audit.read(**_audit_filters(), limit=0)
    record("audit", "Export activity log", details=f"{len(entries)} entries", firewall="")
    return Response(audit.to_csv(entries), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="activity_log.csv"'})


# ---- Firewall inventory & connection
def _fw_form():
    d = request.get_json(force=True)
    return dict(name=d.get("name", ""), url=d.get("url", ""), username=d.get("username", ""),
                password=d.get("password", ""), site=d.get("site", ""), notes=d.get("notes", ""))


@app.get("/api/firewalls")
def firewalls_list():
    current = None
    if session.get("fw_id"):
        try:
            current = firewalls.get(session["fw_id"])
        except ValueError:
            session.pop("fw_id", None)
    user = auth.get_user(g.user) or {}
    return jsonify({"ok": True, "firewalls": firewalls.list_firewalls(), "current": current,
                    "last_used": user.get("last_firewall"), "can_manage": g.role == "admin"})


@app.post("/api/firewalls")
@admin_only
def firewalls_add():
    f = _fw_form()
    with audited("firewall", "Add firewall", f["name"]):
        fw = firewalls.add(**f, created_by=g.user)
        record("firewall", "Add firewall", fw["name"], f"URL: {fw['url']}; user: {fw['username']}; site: {fw['site'] or '-'}", firewall=fw["name"])
    return jsonify({"ok": True, "message": f"Firewall '{fw['name']}' added.", "firewall": fw})


@app.put("/api/firewalls/<fw_id>")
@admin_only
def firewalls_update(fw_id):
    f = _fw_form()
    with audited("firewall", "Edit firewall", f["name"]):
        fw, changed = firewalls.update(fw_id, **f)
        record("firewall", "Edit firewall", fw["name"], f"Changed: {', '.join(changed) or 'nothing'}", firewall=fw["name"])
    return jsonify({"ok": True, "message": f"Firewall '{fw['name']}' updated.", "firewall": fw})


@app.delete("/api/firewalls/<fw_id>")
@admin_only
def firewalls_delete(fw_id):
    with audited("firewall", "Delete firewall", fw_id):
        name = firewalls.delete(fw_id)
        record("firewall", "Delete firewall", name, firewall=name)
    if session.get("fw_id") == fw_id:
        session.pop("fw_id", None)
    return jsonify({"ok": True, "message": f"Firewall '{name}' deleted."})


@app.post("/api/firewalls/import")
@admin_only
def firewalls_import():
    file = request.files["file"]
    with audited("firewall", "Import firewalls", file.filename):
        results = firewalls.import_csv(file.read().decode("utf-8-sig"), created_by=g.user)
        added = [r["name"] for r in results if r["ok"]]
        record("firewall", "Import firewalls", file.filename,
               f"{len(added)} added, {len(results) - len(added)} skipped. Added: {', '.join(added) or 'none'}")
    return jsonify({"ok": True, "results": results})


@app.get("/api/firewalls/template")
def firewalls_template():
    return Response(firewalls.template_csv(), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="firewalls_template.csv"'})


@app.post("/api/firewalls/<fw_id>/test")
def firewalls_test(fw_id):
    return jsonify({"ok": True, "status": firewalls.test(fw_id)})


@app.post("/api/firewalls/check-all")
def firewalls_check_all():
    statuses = firewalls.test_all()
    up = sum(s["ok"] for s in statuses.values())
    record("firewall", "Check all firewalls", details=f"{up} of {len(statuses)} reachable", firewall="")
    return jsonify({"ok": True, "statuses": statuses})


@app.post("/api/firewalls/<fw_id>/connect")
def firewalls_connect(fw_id):
    fw = firewalls.get(fw_id)
    with audited("firewall", "Connect", fw["url"]):
        g.fw_name = fw["name"]
        status = firewalls.test(fw_id, timeout=sophoslogin.CONFIG["timeout"])
        if not status["ok"]:
            raise sophoslogin.SophosError(status["message"])
    session["fw_id"] = fw_id
    auth.set_last_firewall(g.user, fw_id)
    record("firewall", "Connect", fw["url"], f"Firewall user: {fw['username']}")
    return jsonify({"ok": True, "message": f"Connected to {fw['name']}.", "firewall": fw})


@app.post("/api/firewalls/disconnect")
def firewalls_disconnect():
    if session.get("fw_id"):
        try:
            fw = firewalls.get(session["fw_id"])
            record("firewall", "Disconnect", fw["url"], firewall=fw["name"])
        except ValueError:
            pass
    session.pop("fw_id", None)
    auth.set_last_firewall(g.user, None)  # an explicit disconnect must not auto-reconnect on refresh/login
    return jsonify({"ok": True, "message": "Disconnected."})


# ---- IP hosts
@app.get("/api/iphosts")
def list_iphosts():
    return jsonify({"ok": True, "hosts": IPHost.get_IPHosts(request.args.get("name") or "ALL")})


@app.post("/api/iphosts/add-ips")
def add_ips():
    data = request.get_json(force=True)
    name = data.get("name", "")
    ips = [ip for ip in data.get("ips", "").replace("\n", ",").split(",") if ip.strip()]
    with audited("iphost", "Add IPs to IP host", name):
        result = IPHost.edit_IPHost(name, ips)
    details = f"Added: {', '.join(result.get('added', [])) or 'none'}"
    if result.get("skipped"):
        details += f"; Skipped: {'; '.join(result['skipped'])}"
    record("iphost", "Add IPs to IP host", name, f"{details}; {result['message']}", ok=result["ok"])
    return jsonify(result)


# ---- MAC hosts
@app.get("/api/machosts")
def list_machosts():
    return jsonify({"ok": True, "hosts": MACHost.get_MACHosts("ALL")})


@app.post("/api/machosts/add-macs")
def add_macs():
    data = request.get_json(force=True)
    name = data.get("name", "")
    macs = [m for m in data.get("macs", "").replace("\n", ",").split(",") if m.strip()]
    with audited("machost", "Add MACs to MAC host", name):
        result = MACHost.edit_MACHost(name, macs)
    details = f"Added: {', '.join(result.get('added', [])) or 'none'}"
    if result.get("skipped"):
        details += f"; Skipped: {'; '.join(result['skipped'])}"
    record("machost", "Add MACs to MAC host", name, f"{details}; {result['message']}", ok=result["ok"])
    return jsonify(result)


# ---- DHCP
@app.get("/api/dhcp")
def list_dhcp():
    return jsonify({"ok": True, "servers": Sophos_Dhcp.get_dhcp_servers()})


@app.get("/api/dhcp/<name>")
def get_dhcp(name):
    return jsonify({"ok": True, "server": Sophos_Dhcp.get_existing_leases(name)})


@app.post("/api/dhcp/<name>/preview")
def preview_leases(name):
    file = request.files["file"]
    with audited("dhcp", "Import preview", name):
        rows = Sophos_Dhcp.read_lease_csv(file)
        results = Sophos_Dhcp.validate_new_leases(Sophos_Dhcp.get_existing_leases(name), rows)
    valid = sum(r["ok"] for r in results)
    record("dhcp", "Import preview", name, f"File: {file.filename}; {valid} valid, {len(results) - valid} skipped")
    return jsonify({"ok": True, "results": results})


@app.post("/api/dhcp/<name>/add")
def add_single_lease(name):
    """Add one static lease typed in the portal (same checks as the CSV import)."""
    d = request.get_json(force=True)
    row = {"HName": d.get("hostname", "").strip(), "MAC_Add": d.get("mac", "").strip(), "IpAdd": d.get("ip", "").strip()}
    target = f"{name}: {row['HName']} {row['MAC_Add']} {row['IpAdd']}"
    with audited("dhcp", "Add static lease", target):
        result = Sophos_Dhcp.add_static_leases(name, [row])
    r = result["results"][0]
    if not r["ok"]:
        record("dhcp", "Add static lease", target, r["reason"], ok=False)
        return jsonify({"ok": False, "message": f"Not added: {r['reason']}."}), 400
    record("dhcp", "Add static lease", target, result["message"])
    return jsonify({"ok": True, "message": f"Static lease {r['HName']} ({r['MAC_Add']} → {r['IpAdd']}) added.", "lease": r})


@app.post("/api/dhcp/<name>/apply")
def apply_leases(name):
    rows = request.get_json(force=True)["rows"]
    with audited("dhcp", "Import static leases", name):
        result = Sophos_Dhcp.add_static_leases(name, rows)
    added = [f"{r['HName']} {r['MAC_Add']} {r['IpAdd']}" for r in result["results"] if r["ok"]]
    details = f"Added {result.get('added', 0)}: {'; '.join(added) or 'none'}; {result['message']}"
    record("dhcp", "Import static leases", name, details, ok=result["ok"])
    return jsonify(result)


@app.get("/api/dhcp/<name>/export")
def export_leases(name):
    with audited("dhcp", "Export static leases", name):
        leases = Sophos_Dhcp.get_existing_leases(name)["leases"]
    record("dhcp", "Export static leases", name, f"{len(leases)} leases exported to CSV")
    return Response(Sophos_Dhcp.leases_to_csv(leases), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}_leases.csv"'})


if __name__ == "__main__":
    # Bound to localhost only: this app holds firewall admin credentials.
    app.run(host="172.16.69.157", port=5555, debug=False)
