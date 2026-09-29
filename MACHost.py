import copy
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import Sophos_Login_And_Sendrequest as sophoslogin

MAC_RE = re.compile(r"^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$")
SKIP_TAGS = ("Name", "Description", "Status")


def normalize_mac(mac):
    """'aa-bb-cc-dd-ee-ff' -> 'AA:BB:CC:DD:EE:FF', or None if invalid."""
    mac = (mac or "").strip().upper().replace("-", ":")
    return mac if MAC_RE.match(mac) else None


def _macs_in(machost):
    """Every MAC address inside a MACHost element, whatever tags the firmware uses."""
    found = []
    for el in machost.iter():
        if el is machost or el.tag in SKIP_TAGS or not el.text:
            continue
        for part in el.text.split(","):
            mac = normalize_mac(part)
            if mac and mac not in found:
                found.append(mac)
    return found


def _host_to_dict(machost):
    macs = _macs_in(machost)
    host_type = machost.findtext("Type", "").strip()
    is_list = host_type.upper() == "MACLIST"
    return {
        "Name": machost.findtext("Name", "").strip(),
        "Description": machost.findtext("Description", "").strip(),
        "Type": host_type,  # "MACAddress" or "MACLIST"
        "MACAddress": "" if is_list else (macs[0] if macs else ""),
        "ListOfMACAddresses": macs if is_list else [],
    }


def _fetch(host_name=None):
    xml_payload = f"<Get><MACHost><Name>{escape(host_name)}</Name></MACHost></Get>" if host_name else "<Get><MACHost/></Get>"
    response = sophoslogin.login(xml_payload)
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        raise sophoslogin.SophosError(f"XML Parsing Error: {e}") from e
    elements = [h for h in root.findall(".//MACHost") if h.find("Name") is not None]
    if host_name:
        elements = [h for h in elements if h.findtext("Name", "").strip() == host_name.strip()]
    return elements


def get_MACHosts(host_name="ALL"):
    """Fetch MAC host(s). host_name None/empty/"ALL" returns all."""
    fetch_all = not host_name or host_name.strip().upper() == "ALL"
    return [_host_to_dict(h) for h in _fetch(None if fetch_all else host_name)]


def _set_macs(host_el, macs):
    """Put `macs` into a copy of the firewall's own MACHost XML, keeping its structure."""
    # Case 1: a container whose children hold one MAC each (e.g. ListOfMACAddresses/MACAddress).
    for el in host_el.iter():
        if el is host_el:
            continue
        kids = [k for k in el if k.text and normalize_mac(k.text)]
        if kids:
            tag = kids[0].tag
            for k in kids:
                el.remove(k)
            for mac in macs:
                ET.SubElement(el, tag).text = mac
            return
    # Case 2: one element holding a comma-separated list.
    for el in host_el.iter():
        if el is not host_el and el.tag not in SKIP_TAGS and el.text and "," in el.text and _macs_in(el):
            el.text = ",".join(macs)
            return
    # Case 3: nothing to copy from (e.g. empty list): documented Sophos format.
    container = host_el.find("ListOfMACAddresses")
    if container is None:
        container = ET.SubElement(host_el, "ListOfMACAddresses")
    for k in list(container):
        container.remove(k)
    for mac in macs:
        ET.SubElement(container, "MACAddress").text = mac


def edit_MACHost(MacHostName, MacList):
    """Append MAC addresses to an existing MAC List host. Returns a result dict."""
    elements = _fetch(MacHostName)
    if not elements:
        return {"ok": False, "message": f"MAC host '{MacHostName}' not found."}
    host_el = elements[0]
    host = _host_to_dict(host_el)
    if host["Type"].upper() != "MACLIST":
        return {"ok": False, "message": f"MAC host '{MacHostName}' is a single MAC address; only MAC List hosts can be extended."}

    existing = host["ListOfMACAddresses"]
    added, skipped = [], []
    for raw in MacList:
        raw = raw.strip()
        if not raw:
            continue
        mac = normalize_mac(raw)
        if mac is None:
            skipped.append(f"{raw} (invalid MAC)")
        elif mac in existing or mac in added:
            skipped.append(f"{mac} (already in list)")
        else:
            added.append(mac)

    if not added:
        return {"ok": False, "message": "No new MAC addresses to add.", "added": [], "skipped": skipped}

    # Send back the firewall's own XML for this host with the new MACs added, so the
    # payload matches exactly what this firmware version expects.
    new_el = copy.deepcopy(host_el)
    new_el.attrib.clear()
    for status in new_el.findall(".//Status"):
        for parent in new_el.iter():
            if status in list(parent):
                parent.remove(status)
    _set_macs(new_el, existing + added)
    xml_payload = f'<Set operation="update">{ET.tostring(new_el, encoding="unicode")}</Set>'

    response = sophoslogin.login(xml_payload)
    code, message = sophoslogin.parse_status(response.text)
    ok = code in ("200", "202")
    return {"ok": ok, "message": f"[{code}] {message}", "added": added if ok else [], "skipped": skipped}


if __name__ == "__main__":
    # Diagnostic: print how this firewall returns MAC hosts (uses SOPHOS_* environment settings).
    import sys
    name = sys.argv[1] if len(sys.argv) > 1 else None
    for el in _fetch(name):
        print(ET.tostring(el, encoding="unicode"))
