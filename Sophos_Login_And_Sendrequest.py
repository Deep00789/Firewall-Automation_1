import os
import threading
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from xml.sax.saxutils import escape

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Credentials come from environment variables (or the GUI) - never hardcode them.
#   SOPHOS_URL, SOPHOS_USER, SOPHOS_PASSWORD, SOPHOS_VERIFY_SSL
CONFIG = {
    "firewall_url": os.environ.get("SOPHOS_URL", "https://192.168.159.133:4444"),
    "username": os.environ.get("SOPHOS_USER", "admin"),
    "password": os.environ.get("SOPHOS_PASSWORD", ""),
    "verify_ssl": os.environ.get("SOPHOS_VERIFY_SSL", "false").lower() == "true",
    "timeout": 30,
}


class SophosError(Exception):
    """Raised when the firewall cannot be reached or rejects the request."""


def configure(firewall_url=None, username=None, password=None):
    """Update connection settings at runtime (used by the GUI)."""
    if firewall_url:
        CONFIG["firewall_url"] = firewall_url.rstrip("/")
    if username:
        CONFIG["username"] = username
    if password:
        CONFIG["password"] = password


def clear_password():
    """Forget a password entered in the GUI (keeps one set via environment)."""
    CONFIG["password"] = os.environ.get("SOPHOS_PASSWORD", "")


# The GUI serves many users on many firewalls at once: each request thread can
# activate its own firewall. Without one, the global CONFIG is used (CLI scripts).
_local = threading.local()


def current():
    return getattr(_local, "config", None) or CONFIG


def activate(firewall_url, username, password, timeout=None):
    _local.config = {**CONFIG, "firewall_url": firewall_url.rstrip("/"), "username": username,
                     "password": password, "timeout": timeout or CONFIG["timeout"]}


def deactivate():
    _local.config = None


@contextmanager
def using(firewall_url, username, password, timeout=None):
    """Temporarily talk to another firewall in this thread."""
    previous = getattr(_local, "config", None)
    activate(firewall_url, username, password, timeout)
    try:
        yield
    finally:
        _local.config = previous


def api_url():
    return f"{current()['firewall_url'].rstrip('/')}/webconsole/APIController"


def send_request(xml_payload):
    """Send API request to Sophos Firewall"""
    cfg = current()
    try:
        response = requests.post(
            api_url(),
            files={"reqxml": (None, xml_payload)},
            verify=cfg["verify_ssl"],
            timeout=cfg["timeout"],
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise SophosError(f"Cannot reach firewall at {cfg['firewall_url']}: {e}") from e
    return response


def login(xml_payload=""):
    """Login to Sophos Firewall and send XML request"""
    cfg = current()
    if not cfg["password"]:
        raise SophosError("No password configured. Set SOPHOS_PASSWORD or enter it in the GUI.")

    login_payload = f"""<Request>
    <Login>
        <Username>{escape(cfg['username'])}</Username>
        <Password>{escape(cfg['password'])}</Password>
    </Login>
    {xml_payload}
    </Request>"""
    response = send_request(login_payload)

    # Sophos answers HTTP 200 even when the login fails, so check the body.
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        raise SophosError(f"Firewall returned invalid XML: {e}") from e
    login_status = root.findtext(".//Login/status", "")
    if "success" not in login_status.lower():
        # e.g. <Status code="534">API operations are not allowed from the requester IP address.</Status>
        reason = login_status or (root.findtext("Status") or "").strip() or "no login status in response"
        raise SophosError(f"Login failed: {reason}")
    return response


def parse_status(response_text):
    """Return (code, message) of the first <Status> element in a Set response."""
    try:
        status = ET.fromstring(response_text).find(".//Status")
    except ET.ParseError:
        return None, "Invalid XML response"
    if status is None:
        return None, "No status in response"
    return status.get("code"), (status.text or "").strip()
