# Sophos Firewall Automation Portal

A small Flask web portal for managing **Sophos XG / SFOS firewalls** through the Sophos XML API. Instead of clicking through each firewall's web console, operators sign in to one portal and can:

- keep an **inventory of firewalls** (passwords encrypted with Windows DPAPI) and connect to any of them,
- **add IPs to IP List hosts** and **MAC addresses to MAC List hosts**,
- **view, add, bulk-import and export DHCP static leases** with validation,
- look up whether a MAC/IP is **already bound** on any DHCP server,
- manage portal **users and roles** (admin / user),
- review a full **audit log** of who did what, on which firewall, and when.

---

## Table of contents

1. [Requirements](#requirements)
2. [Project structure](#project-structure)
3. [Installation](#installation)
4. [First-time setup](#first-time-setup)
5. [Running the portal](#running-the-portal)
6. [Using the portal](#using-the-portal)
7. [CSV formats](#csv-formats)
8. [Command-line usage](#command-line-usage)
9. [Configuration](#configuration)
10. [Security notes](#security-notes)
11. [API reference](#api-reference)
12. [Troubleshooting](#troubleshooting)

---

## Requirements

| Item | Notes |
|---|---|
| **OS** | **Windows**. Firewall passwords are encrypted with Windows DPAPI (`credential_store.py`), which only works on Windows and only for the same Windows user on the same machine. |
| **Python** | 3.10+ (the bundled venv uses Python 3.13). |
| **Python packages** | `flask`, `requests` (brings `urllib3`), `werkzeug` (installed with Flask). |
| **Sophos firewall** | API access enabled: *Backup & firmware → API → API configuration* → enable, and add the portal machine's IP to the **Allowed IP addresses**. An admin account with rights to edit hosts and DHCP. |
| **Network** | The portal host must reach each firewall's web admin port (usually `https://<ip>:4444`). |

---

## Project structure

```
FirewallAutomation/
├── app.py                          # Flask web app: routes, login, sessions, audit hooks
├── auth.py                         # Portal users (hashed passwords in users.json), roles, lockout
├── manage_users.py                 # CLI to add / remove / list portal users
├── audit.py                        # Append-only audit log (audit.log, JSON lines) + CSV export
├── firewalls.py                    # Firewall inventory (firewalls.json), CSV import, health checks
├── credential_store.py             # Windows DPAPI encrypt/decrypt for firewall passwords
├── Sophos_Login_And_Sendrequest.py # Low-level Sophos XML API client (login + send request)
├── IPHost.py                       # List IP hosts; append IPs to an IP List host
├── MACHost.py                      # List MAC hosts; append MACs to a MAC List host
├── Sophos_Dhcp.py                  # DHCP servers, static lease validation/import/export
├── sophos_firewall_api.py          # Stand-alone REST (v2) client example (not used by the portal)
├── templates/
│   ├── index.html                  # Main single-page UI
│   └── login.html                  # Login page
├── static/                         # CSS, logos, favicons
├── datasheet.csv                   # Sample input for CLI static-lease import
├── leasesheet.csv                  # Output of CLI static-lease export
├── _original_backup/               # Earlier versions of the scripts (reference only)
└── firewallautomation/             # Local Python virtual environment (not committed)
```

### Files created at runtime (do **not** commit)

| File | Contents |
|---|---|
| `users.json` | Portal users, password hashes, roles, last-used firewall |
| `firewalls.json` | Firewall inventory; passwords DPAPI-encrypted |
| `firewall_credentials.json` | Legacy single-firewall credentials (auto-migrated into `firewalls.json`) |
| `.secret_key` | Flask session signing key (auto-generated if `FLASK_SECRET_KEY` is not set) |
| `audit.log` | Audit trail, one JSON object per line |

> These files contain credentials or sensitive history. The current `.gitignore` does not list them yet, so add them before committing the project to Git.

---

## Installation

Open PowerShell in the project folder.

```powershell
# 1. Create a virtual environment (skip if firewallautomation\ already exists)
python -m venv firewallautomation

# 2. Activate it
.\firewallautomation\Scripts\Activate.ps1

# 3. Install dependencies
pip install flask requests
```

Optionally freeze them for later installs:

```powershell
pip freeze > requirements.txt
```

---

## First-time setup

The portal will not let anyone log in until at least one user exists. Create the first **admin** from the command line:

```powershell
python manage_users.py add admin admin
```

You will be prompted for a password. Password rules (enforced in `auth.py`):

- at least 8 characters
- at least one uppercase letter, one digit and one special character

Usernames must be 3–32 characters: letters, digits, `.`, `-`, `_`.

After the first admin exists, further users can be managed from the **User Management** tab in the portal.

---

## Running the portal

```powershell
.\firewallautomation\Scripts\python.exe app.py
```

Then open **http://127.0.0.1:5555** in a browser.

> `app.py` currently starts the server with `host="0.0.0.0", port=5555`, which means it listens on **all network interfaces**. If the portal should only be reachable from this machine, change it to `host="127.0.0.1"`. (Older notes in the code mention port 5000; the actual port is set at the bottom of `app.py`.)

---

## Using the portal

### 1. Firewalls tab
- **Admins** can add, edit, delete firewalls, or **import** many at once from CSV (a template can be downloaded from the tab).
- Anyone can **Test** a firewall or **Check all** (parallel login test, 8 s timeout each).
- Click **Connect** to choose the firewall you will work on. All IP host, MAC host and DHCP actions go to the connected firewall only. Your last-used firewall is remembered; an explicit **Disconnect** clears that.

### 2. IP Hosts
- Lists all IP hosts on the connected firewall.
- **Add IPs** to an existing *IP List* host — enter IPs separated by commas or new lines. Invalid or duplicate IPs are skipped and reported.

### 3. MAC Hosts
- Lists all MAC hosts.
- **Add MACs** to an existing *MAC List* host. Formats like `aa-bb-cc-dd-ee-ff` are normalized to `AA:BB:CC:DD:EE:FF`.

### 4. DHCP
- Lists DHCP servers and, per server, its settings, dynamic ranges and static leases.
- **Add a single static lease** (hostname, MAC, IP).
- **Bulk import**: upload a CSV → **Preview** shows which rows are valid and why others would be skipped → **Apply** adds the valid rows. Existing settings and leases are preserved.
- **Export** a server's static leases to CSV (re-importable).
- **Binding lookup**: search a full/partial MAC or an IP across all DHCP servers.

Each new lease is checked before it is sent to the firewall:

| Check | Skip reason |
|---|---|
| Hostname present | `Hostname is empty` |
| Valid MAC | `Invalid MAC address` |
| Valid IPv4 | `Invalid IP address` |
| Inside the DHCP subnet | `IP is outside DHCP subnet …` |
| Not in a dynamic range | `IP is in dynamic range` |
| No duplicate hostname / MAC / IP (on the server **or** within the file) | `… already exists` |

### 5. User Management (admins only)
Create users, delete users, reset passwords, change roles. Safeguards: you cannot delete yourself, remove your own admin role, or remove the last admin. Resetting a password signs out that user's open sessions.

### 6. Activity Log (admins only)
Filter by user, firewall, category (`auth`, `firewall`, `iphost`, `machost`, `dhcp`, `users`, `audit`), result, date range or free text, and export to CSV. Times are stored in UTC.

### Roles at a glance

| Action | admin | user |
|---|:---:|:---:|
| Connect / test firewalls | ✅ | ✅ |
| IP hosts, MAC hosts, DHCP changes | ✅ | ✅ |
| Add / edit / delete / import firewalls | ✅ | ❌ |
| User management | ✅ | ❌ |
| Activity log | ✅ | ❌ |
| Change own password | ✅ | ✅ |

---

## CSV formats

**Firewall import** (`Name`, `URL`, `Username`, `Password` required):

```csv
Name,URL,Username,Password,Site,Notes
HQ-Firewall,https://192.168.1.1:4444,admin,ChangeMe,Head Office,Main building
```

A URL without a scheme gets `https://` added automatically.

**DHCP static leases** (header required, column names are case-insensitive):

```csv
HostName,MAC_Address,IP_Address
DEVICE08,C8:32:AF:DE:44:18,192.168.29.154
```

---

## Command-line usage

The modules can also be run directly against a single firewall configured by environment variables (see [Configuration](#configuration)).

```powershell
$env:SOPHOS_URL      = "https://192.168.1.1:4444"
$env:SOPHOS_USER     = "admin"
$env:SOPHOS_PASSWORD = "********"

# Portal users
python manage_users.py list
python manage_users.py add <username> [admin|user]   # also resets an existing user's password
python manage_users.py remove <username>

# Print raw MAC host XML (diagnostic)
python MACHost.py [host-name]

# DHCP: by default exports static leases of server "vlan29" to leasesheet.csv.
# Edit the __main__ block to call Add_Static_Binding() to import datasheet.csv instead.
python Sophos_Dhcp.py

# IPHost.py's __main__ block is a hard-coded example; edit before running.
python IPHost.py
```

---

## Configuration

| Variable | Used by | Default | Purpose |
|---|---|---|---|
| `FLASK_SECRET_KEY` | `app.py` | random key saved to `.secret_key` | Signs session cookies. Set it if you run more than one instance. |
| `SOPHOS_URL` | CLI scripts | `https://192.168.159.133:4444` | Firewall URL when not using the portal |
| `SOPHOS_USER` | CLI scripts | `admin` | Firewall API user |
| `SOPHOS_PASSWORD` | CLI scripts | *(empty)* | Firewall API password |
| `SOPHOS_VERIFY_SSL` | all | `false` | Set to `true` to verify the firewall's TLS certificate |

Other settings in code:

| Setting | Location | Value |
|---|---|---|
| Session idle timeout | `app.py` | 30 minutes |
| Login lockout | `auth.py` | 5 failed attempts → locked for 5 minutes |
| Firewall request timeout | `Sophos_Login_And_Sendrequest.py` | 30 s |
| Health-check timeout | `firewalls.py` | 8 s per firewall, 16 in parallel |

---

## Security notes

- **Firewall passwords** are encrypted with Windows DPAPI. They can only be decrypted by the **same Windows account on the same computer**. If you move the project or run it as a different user, edit each firewall and re-enter its password.
- **Portal passwords** are stored as Werkzeug hashes, never in plain text.
- Sessions use `HttpOnly` + `SameSite=Strict` cookies, a 30-minute idle timeout, and are invalidated when the password changes.
- Login timing is equalized for unknown users, and repeated failures trigger a temporary lockout.
- Every login, change and failure is written to `audit.log`; the app never edits or deletes entries.
- **TLS verification is off by default** because most firewalls use self-signed certificates. Turn on `SOPHOS_VERIFY_SSL=true` if your firewalls have trusted certificates.
- The app is served by Flask's built-in server over **plain HTTP**. Keep it on localhost or a trusted management network, or put it behind an HTTPS reverse proxy before exposing it more widely.
- Never commit `users.json`, `firewalls.json`, `firewall_credentials.json`, `.secret_key` or `audit.log`.

---

## API reference

All endpoints require a logged-in session and return JSON (`{"ok": true|false, ...}`) unless noted.
Endpoints marked 🔌 need a connected firewall; 🔒 are admin-only.

**Auth & account**

| Method | Path | Description |
|---|---|---|
| GET/POST | `/login` | Login page / submit credentials |
| POST | `/logout` | Log out (also disconnects firewall) |
| POST | `/api/account/password` | Change own password |

**Users** 🔒

| Method | Path | Description |
|---|---|---|
| GET | `/api/users` | List users |
| POST | `/api/users` | Create user |
| DELETE | `/api/users/<username>` | Delete user |
| POST | `/api/users/<username>/password` | Reset password |
| POST | `/api/users/<username>/role` | Change role |

**Audit** 🔒

| Method | Path | Description |
|---|---|---|
| GET | `/api/audit` | Query log (`user`, `category`, `firewall`, `result`, `from`, `to`, `q`, `limit`) |
| GET | `/api/audit/export` | Same filters, CSV download |

**Firewalls**

| Method | Path | Description |
|---|---|---|
| GET | `/api/firewalls` | Inventory, current connection, last used |
| POST | `/api/firewalls` 🔒 | Add firewall |
| PUT | `/api/firewalls/<id>` 🔒 | Edit firewall (empty password keeps the old one) |
| DELETE | `/api/firewalls/<id>` 🔒 | Delete firewall |
| POST | `/api/firewalls/import` 🔒 | Import CSV (multipart `file`) |
| GET | `/api/firewalls/template` | Download CSV template |
| POST | `/api/firewalls/<id>/test` | Test login |
| POST | `/api/firewalls/check-all` | Test all firewalls |
| POST | `/api/firewalls/<id>/connect` | Connect this session to a firewall |
| POST | `/api/firewalls/disconnect` | Disconnect |

**IP / MAC hosts** 🔌

| Method | Path | Description |
|---|---|---|
| GET | `/api/iphosts?name=` | List IP hosts (all, or one by name) |
| POST | `/api/iphosts/add-ips` | `{"name", "ips"}` – append IPs |
| GET | `/api/machosts` | List MAC hosts |
| POST | `/api/machosts/add-macs` | `{"name", "macs"}` – append MACs |

**DHCP** 🔌

| Method | Path | Description |
|---|---|---|
| GET | `/api/dhcp` | List DHCP servers |
| GET | `/api/dhcp-lookup?q=` | Find a MAC/IP in static leases of all servers |
| GET | `/api/dhcp/<name>` | Server settings, ranges, leases |
| POST | `/api/dhcp/<name>/preview` | Validate an uploaded lease CSV |
| POST | `/api/dhcp/<name>/apply` | `{"rows": [...]}` – add validated leases |
| POST | `/api/dhcp/<name>/add` | `{"hostname", "mac", "ip"}` – add one lease |
| GET | `/api/dhcp/<name>/export` | Static leases as CSV |

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Login page says there are no users | Run `python manage_users.py add <name> admin`. |
| `Cannot reach firewall at …` | Wrong URL/port, firewall offline, or network/ACL blocking port 4444. |
| `Login failed: …` | Wrong firewall credentials, **API not enabled**, or the portal machine's IP is not in the firewall's API allowed list. |
| `Cannot decrypt the password of '…'` | The inventory was created by another Windows user or on another PC. Edit the firewall and re-enter its password. |
| `No firewall connected` | Connect to a firewall on the **Firewalls** tab first. |
| `Session expired` | 30 minutes idle, or your password was changed/reset. Log in again. |
| `Too many failed attempts` | Wait 5 minutes (lockout resets on app restart). |
| Lease rows skipped on import | Check the reason column in the preview (subnet, dynamic range, duplicates). |
| Adding IPs/MACs fails | The target must already exist on the firewall as an **IP List** / **MAC List** host. |
