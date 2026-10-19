# Sophos Firewall Automation Portal

A small Flask web portal for managing **Sophos XG / SFOS firewalls** through the Sophos XML API. Instead of clicking through each firewall's web console, operators sign in to one portal and can:

- keep an **inventory of firewalls** (passwords encrypted) and connect to any of them,
- **add IPs to IP List hosts** and **MAC addresses to MAC List hosts**,
- **view, add, bulk-import and export DHCP static leases** with validation,
- look up whether a MAC/IP is **already bound** on any DHCP server,
- manage portal **users and roles** (admin / user),
- review a full **audit log** of who did what, on which firewall, and when,
- find **where an IP or network is used** across all firewalls (hosts, interfaces, rules, NAT, VPN), propose **free subnets**, and run a **live host check** (nmap).

It runs on **Linux** (bare-metal, VM or **Docker**) and on **Windows**.

---

## Table of contents

1. [Requirements](#requirements)
2. [Project structure](#project-structure)
3. [Installation](#installation)
4. [First-time setup](#first-time-setup)
5. [Running the portal](#running-the-portal)
   - [Docker on a Linux server (recommended)](#option-a--docker-on-a-linux-server-recommended)
   - [Linux without Docker](#option-b--linux-without-docker)
   - [Windows](#option-c--windows)
   - [Moving from Windows to Linux](#moving-an-existing-windows-setup-to-linux)
6. [Using the portal](#using-the-portal)
7. [CSV formats](#csv-formats)
8. [Command-line usage](#command-line-usage)
9. [Configuration](#configuration)
10. [Security notes](#security-notes)
11. [API reference](#api-reference)
12. [Changelog](#changelog)
13. [Troubleshooting](#troubleshooting)

---

## Requirements

| Item | Notes |
|---|---|
| **OS** | Linux (e.g. Ubuntu 22.04 / 24.04, or any distro that runs Docker) or Windows. |
| **Docker** (optional) | Docker Engine 24+ with the Compose plugin (`docker compose`). |
| **Python** | 3.10+ when running without Docker. |
| **Python packages** | Listed in `requirements.txt`: Flask, requests, cryptography, python-nmap, gunicorn (Linux only). The Docker image uses Python 3.13 and also installs the `nmap` program. |
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
├── config.py                       # DATA_DIR and other shared settings from environment variables
├── credential_store.py             # Fernet encryption of firewall passwords (key: FIREWALL_KEY)
├── migrate_credentials.py          # One-time: convert old Windows DPAPI passwords to Fernet
├── Sophos_Login_And_Sendrequest.py # Low-level Sophos XML API client (login + send request)
├── IPHost.py                       # List IP hosts; append IPs to an IP List host
├── MACHost.py                      # List MAC hosts; append MACs to a MAC List host
├── Sophos_Dhcp.py                  # DHCP servers, static lease validation/import/export
├── portforwards.py                 # Port-forward documentation records (portforwards.json), CSV import / export
├── vpndocs.py                      # VPN detail documentation records (vpndocs.json), CSV import / export
├── subnet_tools.py                 # IP / subnet search, free subnets, live host scan (nmap)
├── sophos_firewall_api.py          # Stand-alone REST (v2) client example (not used by the portal)
├── requirements.txt                # Python dependencies
├── Dockerfile                      # Builds the container image
├── docker-compose.yml              # Starts the container, keeps data in ./data
├── gunicorn.conf.py                # Optional production web server settings
├── .env.example                    # Optional: list of settings (for Linux without Docker)
├── templates/
│   ├── index.html                  # Main single-page UI
│   └── login.html                  # Login page
├── static/                         # CSS, logos, favicons
├── datasheet.csv                   # Sample input for CLI static-lease import
├── leasesheet.csv                  # Output of CLI static-lease export
├── attendance.json                 # Sample data (not used by the portal)
├── .claude/launch.json             # Editor launch configuration
├── _original_backup/               # Earlier versions of the scripts (reference only)
├── _backup_before_linux/           # Windows-only versions before the Linux/Docker port (reference only)
├── IP_Subnet_Checkers/             # Old stand-alone subnet tool, merged into subnet_tools.py (git- and docker-ignored)
└── firewallautomation/             # Local Python virtual environment (not committed)
```

### Files created at runtime (do **not** commit)

They are written to the **data folder** (`DATA_DIR`): the `./data` folder next to `docker-compose.yml` in Docker, or the project folder if `DATA_DIR` is not set.

| File | Contents |
|---|---|
| `users.json` | Portal users, password hashes, roles, last-used firewall |
| `firewalls.json` | Firewall inventory; passwords Fernet-encrypted |
| `.firewall.key` | Encryption key for firewall passwords (only if `FIREWALL_KEY` is not set) |
| `.secret_key` | Flask session signing key (only if `FLASK_SECRET_KEY` is not set) |
| `audit.log` | Audit trail, one JSON object per line |
| `firewall_credentials.json` | Legacy single-firewall credentials (auto-migrated into `firewalls.json`) |

> These files contain credentials, keys and history. They are excluded by `.gitignore` and `.dockerignore`. **Back up the data folder** (and your `FIREWALL_KEY`): without the key, every firewall password must be re-entered.

---

## Installation

Get the project onto the machine (copy the folder or `git clone`), then follow one of the options under [Running the portal](#running-the-portal). Every option needs **one admin user** to be created before anyone can log in (shown in each option).

---

## First-time setup

Password rules for portal users (enforced in `auth.py`):

- at least 8 characters
- at least one uppercase letter, one digit and one special character

Usernames must be 3–32 characters: letters, digits, `.`, `-`, `_`.

After the first admin exists, further users can be managed from the **User Management** tab in the portal.

---

## Running the portal

### Option A – Docker on a Linux server (recommended)

The Docker setup is two small files: `Dockerfile` and `docker-compose.yml`. All app data is kept in one folder, `./data`, next to them.

```bash
# 1. Install Docker (Ubuntu) – skip if already installed
curl -fsSL https://get.docker.com | sudo sh

# 2. Go to the project folder and create the data folder
cd FirewallAutomation
mkdir -p data

# 3. Build and start
docker compose up -d --build

# 4. Create the first admin (asks for a password)
docker compose exec firewall-automation python manage_users.py add admin admin
```

Open **http://\<server-ip\>:5555**.

On first start the app creates two key files in `./data`:

- `.firewall.key` – encrypts the firewall passwords. **Back it up.** If it is lost, every firewall password must be entered again.
- `.secret_key` – signs login sessions.

Everyday commands:

```bash
docker compose logs -f              # view logs
docker compose restart              # restart
docker compose down                 # stop
docker compose up -d --build        # rebuild after changing code (data in ./data is kept)
docker compose exec firewall-automation python manage_users.py list
```

Notes:

- The container talks to the firewalls from the **VM's IP address**. Add that IP to each firewall's API *Allowed IP addresses*, and make sure the VM can reach the firewalls on port 4444.
- Users reach the portal over **plain HTTP** on port 5555. For anything beyond a trusted management network, put a reverse proxy with HTTPS in front (see [HTTPS with a reverse proxy](#https-with-a-reverse-proxy)).
- The container uses Flask's built-in server (`python app.py`), which is fine for a small team. For heavier use, change the last line of the `Dockerfile` to `CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]`.
- Optional settings (like `FIREWALL_KEY` instead of the key file) can be added under `environment:` in `docker-compose.yml`. See [Configuration](#configuration).

### Option B – Linux without Docker

```bash
sudo apt update && sudo apt install -y python3 python3-venv
cd /opt/FirewallAutomation            # or wherever the project is
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export DATA_DIR=/var/lib/firewall-portal
export FIREWALL_KEY="<generated key>"
export FLASK_SECRET_KEY="<random hex>"
sudo mkdir -p $DATA_DIR && sudo chown $USER $DATA_DIR

python manage_users.py add admin admin
gunicorn -c gunicorn.conf.py app:app  # listens on 0.0.0.0:5555
```

To run it as a service, create `/etc/systemd/system/firewall-portal.service`:

```ini
[Unit]
Description=Sophos Firewall Automation Portal
After=network-online.target

[Service]
User=fwportal
WorkingDirectory=/opt/FirewallAutomation
EnvironmentFile=/opt/FirewallAutomation/.env
Environment=DATA_DIR=/var/lib/firewall-portal
ExecStart=/opt/FirewallAutomation/venv/bin/gunicorn -c gunicorn.conf.py app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home fwportal
sudo chown -R fwportal /var/lib/firewall-portal
sudo systemctl daemon-reload && sudo systemctl enable --now firewall-portal
```

### Option C – Windows

```powershell
python -m venv firewallautomation
.\firewallautomation\Scripts\Activate.ps1
pip install -r requirements.txt      # gunicorn is skipped on Windows

python manage_users.py add admin admin
python app.py
```

Open **http://127.0.0.1:5555**. By default the built-in server only accepts connections from the same PC; to let other machines connect, set `$env:HOST = "0.0.0.0"` before `python app.py`.

### Moving an existing Windows setup to Linux

Older versions encrypted firewall passwords with **Windows DPAPI**, which Linux cannot read. Convert them once, **on the original Windows PC as the same Windows user**:

```powershell
cd FirewallAutomation
.\firewallautomation\Scripts\Activate.ps1
pip install -r requirements.txt
python migrate_credentials.py
```

This re-encrypts every firewall password with a new key, saved as `.firewall.key` in the project folder, and keeps a backup of the old file (`firewalls.json.dpapi-backup-<date>`).

Then copy these 4 files from the Windows project folder into the `data/` folder on the server, and restart:

```
users.json   firewalls.json   audit.log   .firewall.key
```

```bash
docker compose restart
```

If you skip the conversion, the portal still starts on Linux, but each firewall shows *"encrypted with Windows DPAPI and cannot be read"*. Edit each firewall and re-enter its password to fix it.

### HTTPS with a reverse proxy

Example with **Caddy** on the same VM (gets a certificate automatically for a public DNS name; use `tls internal` for an internal name):

```
fwportal.example.com {
    reverse_proxy 127.0.0.1:5555
}
```

Then in `docker-compose.yml` change the port to `"127.0.0.1:5555:5555"` and add under `environment:`:

```yaml
      - SESSION_COOKIE_SECURE=true
      - TRUST_PROXY=true
```

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

### 5. IP & subnet tools
These work on data **loaded into the portal's memory** from the firewalls. Open **Subnet Search** and click **Fetch connected firewall** or **Fetch all firewalls** first. The data is kept until the portal restarts, and it is shared by all users. Fetch again to refresh it.
- **Subnet Search** shows where an IP or network is used: IP hosts, interfaces / VLANs, firewall rules and NAT rules that use those hosts, and IPsec VPNs. You can search all loaded firewalls or only the connected one.
- **Free Subnets** proposes private subnets of a chosen size (/8–/30) that do not overlap any IP host, interface or VPN network on the loaded firewalls. Routes are not checked, and firewalls that are not loaded are listed as a warning.
- **Live Hosts** pings an IPv4 address or network (/24 or smaller), then checks TCP 21, 22, 80, 443, 8080 and 8443 on addresses that did not reply. The scan runs **from the portal server**, so it needs the `nmap` program (included in the Docker image). The container runs as root, which the SYN scan requires.
- **Firewall Data** (needs a connected firewall) lists everything that was loaded for that firewall.

Rules that use an IP host only through an **IP host group** are not found yet, because host groups are not fetched.

### 6. User Management (admins only)
Create users, delete users, reset passwords, change roles. Safeguards: you cannot delete yourself, remove your own admin role, or remove the last admin. Resetting a password signs out that user's open sessions.

### 7. Activity Log (admins only)
Filter by user, firewall, category (`auth`, `firewall`, `iphost`, `machost`, `dhcp`, `subnet`, `users`, `audit`), result, date range or free text, and export to CSV. Times are stored in UTC.

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

The modules can also be run directly against a single firewall configured by environment variables (see [Configuration](#configuration)). In Docker, prefix commands with `docker compose exec firewall-automation`.

```bash
export SOPHOS_URL="https://192.168.1.1:4444"     # PowerShell: $env:SOPHOS_URL = "..."
export SOPHOS_USER="admin"
export SOPHOS_PASSWORD="********"

# Portal users
python manage_users.py list
python manage_users.py add <username> [admin|user]   # also resets an existing user's password
python manage_users.py remove <username>

# Convert old Windows DPAPI firewall passwords to Fernet (run on Windows)
python migrate_credentials.py

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
| `DATA_DIR` | all | project folder (`/app/data` in Docker) | Where users, firewalls, audit log and keys are stored |
| `FIREWALL_KEY` | `credential_store.py` | random key saved to `<DATA_DIR>/.firewall.key` | Fernet key that encrypts firewall passwords. **Back it up.** |
| `FLASK_SECRET_KEY` | `app.py` | random key saved to `<DATA_DIR>/.secret_key` | Signs session cookies |
| `HOST` | `app.py`, gunicorn | `127.0.0.1` (`python app.py`), `0.0.0.0` (gunicorn/Docker) | Address to listen on |
| `PORT` | `app.py`, gunicorn | `5555` | Port to listen on |
| `SESSION_COOKIE_SECURE` | `app.py` | `false` | `true` when served over HTTPS |
| `TRUST_PROXY` | `app.py` | `false` | `true` behind a reverse proxy, so the audit log shows real client IPs |
| `GUNICORN_THREADS` | `gunicorn.conf.py` | `8` | Concurrent requests |
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

- **Firewall passwords** are encrypted with Fernet (AES + HMAC) using the key in `.firewall.key` (or `FIREWALL_KEY` if set). Anyone with the key and `firewalls.json` can decrypt them, so keep `.env` / `.firewall.key` readable only by the service account, and store a copy of the key somewhere safe (password manager).
- **Portal passwords** are stored as Werkzeug hashes, never in plain text.
- Sessions use `HttpOnly` + `SameSite=Strict` cookies, a 30-minute idle timeout, and are invalidated when the password changes.
- Login timing is equalized for unknown users, and repeated failures trigger a temporary lockout.
- Every login, change and failure is written to `audit.log`; the app never edits or deletes entries.
- **TLS verification is off by default** because most firewalls use self-signed certificates. Turn on `SOPHOS_VERIFY_SSL=true` if your firewalls have trusted certificates.
- **Runtime files are not tracked in git.** Before 2026-10-15, `.secret_key`, `users.json`, `firewalls.json`, `firewall_credentials.json` and `audit.log` were committed by mistake. They have been removed from the index, but they **remain in the git history**. If this repository was ever pushed or shared, rotate the Flask secret key and change the firewall and portal passwords.
- All data and keys stay in the `./data` folder; no secrets are copied into the Docker image (see `.dockerignore`). Keep that folder readable only by admins on the VM (`chmod 700 data`).
- The portal speaks **plain HTTP**. Keep it on a trusted management network, or put it behind an HTTPS reverse proxy and set `SESSION_COOKIE_SECURE=true`.
- Never commit `.env`, `data/`, `users.json`, `firewalls.json`, `firewall_credentials.json`, `.secret_key`, `.firewall.key` or `audit.log`.

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

## Changelog

Built from the git history (`git log`), newest first.

### 2026-10-18 – VPN details documentation
- New **Documents → VPN Details** page, next to Port Forwarding Rules: a manual record of VPN tunnels with VPN name, Local GW, Remote GW, Local Subnet, Remote Subnet and Description (optional). Stored in `vpndocs.json`; not read from or pushed to any firewall.
- Add, edit, CSV import (template at `/api/vpndocs/template`), export of all or selected rows, and admin-only bulk delete. Gateways accept an IPv4 address or a host name; subnets accept several IPv4 networks separated by commas. VPN names must be unique. A new VPN is refused when its local **and** remote subnets both overlap (by CIDR range, e.g. 192.168.0.0/25 inside 192.168.0.0/23) the local and remote subnets of the **same** existing tunnel; an overlap on only one side, or spread across different tunnels, is allowed. Tests: `python -m unittest discover -s tests -v`. A Local GW + Remote GW pair can be used only once (the same pair again is refused with the name of the VPN that already uses it; the same gateway in a different pair is fine). Audited as category `vpndoc`.

### 2026-10-18 – Port forward documentation
- New **Documents → Port Forwarding Rules** section in the side menu (separate from the firewall tools): a manual record of port-forwarding rules with the fields Rule No (optional), Port (optional), Public IP, Private IP, External Port, Internal Port, Requestor (optional), Sites and Description (optional). Records are stored in `portforwards.json` and are not pushed to any firewall.
- Add and edit one at a time, **import** from CSV (template at `/api/portforwards/template`; invalid or duplicate rows are skipped and reported) and **export** to CSV (all records, or only the rows ticked with the checkboxes). All users can add, edit, import, select and export; only admins can delete, one at a time or in bulk with the row checkboxes and a select-all box (which selects the rows currently shown). Every change is audited under category `portforward`.
- Ports accept a number, a range (`8000-8010`) or a list (`80,443` or `80/443`). A duplicate Public IP + External Port + Port is rejected.

### 2026-10-15 – IP & subnet tools merged
- Merged the stand-alone `IP_Subnet_Checkers` tool into the portal as `subnet_tools.py`, with new tabs: **Subnet Search**, **Free Subnets**, **Live Hosts** and **Firewall Data**. It now uses the portal's login, roles, audit log (category `subnet`) and firewall inventory. Its Windows-only DPAPI password store and its separate user and firewall files are no longer used.
- Fixes compared with the old tool:
  - Free-subnet search no longer fails for prefixes /8–/15.
  - A failed firewall login is reported instead of silently wiping the loaded data.
  - The full dataset is no longer printed to the console.
  - Data is cached per firewall id and cleared when a firewall is edited or deleted.
- Docker image: installs `nmap` and `python-nmap`, and the duplicated `ENV` lines are cleaned up. `DATA_DIR` now defaults to `/app/data`, matching `docker-compose.yml`.
- Firewall login errors now show the firewall's own message, for example *API operations are not allowed from the requester IP address*.
- Verified the portal runs correctly on an Ubuntu host.
- Repository cleanup: stopped tracking runtime and secret files (`.secret_key`, `users.json`, `firewalls.json`, `firewall_credentials.json`, `audit.log`) and compiled `__pycache__/*.pyc` files. Removed a stray empty template file and an accidental self-referencing `Firewall-Automation_1` submodule entry.
- README: added this changelog, updated the project structure and expanded the security notes.

### 2026-10-14 – Linux / Docker support
- Added `config.py` with `DATA_DIR`, so all runtime data lives in one folder (`./data` in Docker).
- `credential_store.py` now encrypts firewall passwords with **Fernet** (`FIREWALL_KEY` / `.firewall.key`) instead of Windows DPAPI.
- Added `migrate_credentials.py`, a one-time conversion from DPAPI to Fernet.
- Added `Dockerfile`, `docker-compose.yml`, `gunicorn.conf.py`, `.env.example`, `.gitignore` and `.dockerignore`.
- Pinned dependencies in `requirements.txt` and converted the file to plain UTF-8.
- Kept the pre-port versions in `_backup_before_linux/`.
- Rewrote the README for Linux, Docker and Windows deployment.

### 2026-10-13
- Added `sophos_firewall_api.py`, a stand-alone REST (v2) client example.

### 2026-10-07 – 2026-10-12
- DHCP improvements in `Sophos_Dhcp.py`, `app.py` and `templates/index.html`, including the MAC/IP binding lookup across all DHCP servers.
- Firewall inventory updates.

### 2026-09-29
- Audit logging of user actions.
- Stronger portal password rules: at least 8 characters, with an uppercase letter, a digit and a special character (`auth.py`).

### 2026-09-28
- Firewall selection dropdown to connect a session to a specific firewall.
- **MAC host** support: `MACHost.py`, the `/api/machosts` endpoints and a MAC Hosts tab in the UI.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Login page says there are no users | Run `python manage_users.py add <name> admin`. |
| `Cannot reach firewall at …` | Wrong URL/port, firewall offline, or network/ACL blocking port 4444. |
| `Login failed: …` | Wrong firewall credentials, **API not enabled**, or the portal machine's IP is not in the firewall's API allowed list. |
| `… encrypted with Windows DPAPI and cannot be read on this system` | Old Windows data copied to Linux. Run `migrate_credentials.py` on the Windows PC, or edit the firewall and re-enter its password. |
| `… encrypted with a different key (check FIREWALL_KEY)` | `FIREWALL_KEY` changed or `.firewall.key` was lost. Restore the original key, or re-enter the passwords. |
| Portal not reachable from other PCs | Docker: check `ports:` in `docker-compose.yml` and the VM firewall (`sudo ufw allow 5555/tcp`). Windows: set `HOST=0.0.0.0`. |
| `No firewall connected` | Connect to a firewall on the **Firewalls** tab first. |
| `Session expired` | 30 minutes idle, or your password was changed/reset. Log in again. |
| `Too many failed attempts` | Wait 5 minutes (lockout resets on app restart). |
| Lease rows skipped on import | Check the reason column in the preview (subnet, dynamic range, duplicates). |
| Adding IPs/MACs fails | The target must already exist on the firewall as an **IP List** / **MAC List** host. |
