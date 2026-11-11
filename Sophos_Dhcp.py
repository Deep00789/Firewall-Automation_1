import csv
import io
import ipaddress
import os
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import Sophos_Login_And_Sendrequest as sophoslogin

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAC_RE = re.compile(r"^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$")

# DHCP settings that must be sent back unchanged when updating the server.
PARAM_TAGS = [
    "Interface", "UseInterfaceIPasGateway", "Gateway", "SubnetMask",
    "DefaultLeaseTime", "MaxLeaseTime", "ConflictDetection", "UseApplianceDNSSettings",
    "PrimaryDNSServer", "SecondaryDNSServer", "PrimaryWINSServer", "SecondaryWINSServer",
    "DomainName",
]


def _server_to_dict(dhcp_server):
    return {
        "name": dhcp_server.findtext("Name", "").strip(),
        "params": {tag: dhcp_server.findtext(tag, "").strip() for tag in PARAM_TAGS},
        "dynamic_ranges": [ip.text.strip() for ip in dhcp_server.findall("IPLease/IP") if ip.text and ip.text.strip()],
        "leases": [
            {
                "HName": lease.findtext("HostName", "").strip(),
                "MAC_Add": lease.findtext("MACAddress", "").strip(),
                "IpAdd": lease.findtext("IPAddress", "").strip(),
            }
            for lease in dhcp_server.findall("StaticLease/Lease")
        ],
    }


def _fetch_servers(xml_payload):
    response = sophoslogin.login(xml_payload)
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        raise sophoslogin.SophosError(f"XML Parsing Error: {e}") from e
    return [_server_to_dict(s) for s in root.findall(".//DHCPServer") if s.find("Name") is not None]


def get_dhcp_servers():
    """Fetch ALL DHCP servers configured on the firewall."""
    return _fetch_servers("<Get><DHCPServer/></Get>")


def get_existing_leases(DSerName):
    """Fetch DHCP settings, dynamic ranges and static leases of one DHCP server."""
    for server in _fetch_servers(f"<Get><DHCPServer><Name>{escape(DSerName)}</Name></DHCPServer></Get>"):
        if server["name"] == DSerName:
            return server
    raise sophoslogin.SophosError(f"DHCP server '{DSerName}' not found.")


def find_bindings(query):
    """Search the static leases of ALL DHCP servers for a MAC (full or partial) or an IP.

    Returns {"kind": "mac" | "mac-partial" | "ip", "query": normalized, "matches": [...]}.
    """
    query = (query or "").strip()
    try:
        ip = str(ipaddress.IPv4Address(query))
        kind, key = "ip", ip
    except ValueError:
        digits = re.sub(r"[^0-9A-Fa-f]", "", query).upper()
        if len(digits) == 12 and re.fullmatch(r"[0-9A-Fa-f:.\- ]+", query):
            kind, key = "mac", ":".join(digits[i:i + 2] for i in range(0, 12, 2))
        elif len(digits) >= 4 and re.fullmatch(r"[0-9A-Fa-f:.\- ]+", query):
            kind, key = "mac-partial", digits
        else:
            raise ValueError("Enter a MAC address (full, or at least 4 hex digits) or an IP address.")

    matches = []
    for server in get_dhcp_servers():
        for lease in server["leases"]:
            lease_digits = re.sub(r"[^0-9A-F]", "", lease["MAC_Add"].upper())
            if (kind == "ip" and lease["IpAdd"] == key) or \
               (kind == "mac" and lease_digits == key.replace(":", "")) or \
               (kind == "mac-partial" and key in lease_digits):
                matches.append({
                    "server": server["name"],
                    "interface": server["params"]["Interface"],
                    "HName": lease["HName"],
                    "MAC_Add": lease["MAC_Add"],
                    "IpAdd": lease["IpAdd"],
                })
    return {"kind": kind, "query": key, "matches": matches}


def _in_dynamic_range(ip, dynamic_ranges):
    for ip_range in dynamic_ranges:
        start, _, end = ip_range.partition("-")
        if ipaddress.IPv4Address(start.strip()) <= ip <= ipaddress.IPv4Address((end or start).strip()):
            return True
    return False


def read_lease_csv(file_or_text):
    """Read HostName,MAC_Address,IP_Address rows from a CSV path, text or file object."""
    if isinstance(file_or_text, str) and os.path.exists(file_or_text):
        with open(file_or_text, newline="", encoding="utf-8-sig") as f:
            text = f.read()
    elif isinstance(file_or_text, str):
        text = file_or_text
    else:
        text = file_or_text.read().decode("utf-8-sig")

    reader = csv.DictReader(io.StringIO(text))
    headers = {(h or "").strip().lower(): h for h in reader.fieldnames or []}
    missing = [h for h in ("hostname", "mac_address", "ip_address") if h not in headers]
    if missing:
        raise ValueError(f"CSV is missing column(s): {', '.join(missing)}. Expected HostName,MAC_Address,IP_Address")
    return [
        {
            "HName": (row[headers["hostname"]] or "").strip(),
            "MAC_Add": (row[headers["mac_address"]] or "").strip(),
            "IpAdd": (row[headers["ip_address"]] or "").strip(),
        }
        for row in reader
        if any((v or "").strip() for v in row.values())
    ]


def _dhcp_subnet(params):
    if params["Gateway"] and params["SubnetMask"]:
        try:
            return ipaddress.IPv4Network(f"{params['Gateway']}/{params['SubnetMask']}", strict=False)
        except ValueError:
            pass
    return None


def normalize_mac(text):
    """AA:BB:CC:DD:EE:FF for any 12-digit MAC written with : - . or no separator; otherwise the text unchanged."""
    digits = re.sub(r"[:.\-\s]", "", text or "")
    if re.fullmatch(r"[0-9A-Fa-f]{12}", digits):
        return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()
    return (text or "").strip()


def _is_mac(text):
    return bool(MAC_RE.match(normalize_mac(text)))


def parse_quick_leases(text):
    """Read one lease per line: "hostname,mac,ip". Hostname and IP are optional:
    "mac" | "hostname,mac" | "mac,ip" | "hostname,mac,ip" (leave a field empty to skip it, e.g. ",mac,ip").
    Blank lines and lines starting with # are ignored."""
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        row = {"HName": "", "MAC_Add": "", "IpAdd": ""}
        if len(parts) == 1:
            row["MAC_Add"] = parts[0]
        elif len(parts) == 2:
            # "mac,ip" when the first field is a MAC (even if the IP is mistyped), else "hostname,mac".
            if _is_mac(parts[0]) and not _is_mac(parts[1]):
                row["MAC_Add"], row["IpAdd"] = parts
            else:
                row["HName"], row["MAC_Add"] = parts
        elif len(parts) == 3:
            row["HName"], row["MAC_Add"], row["IpAdd"] = parts
        else:
            row["MAC_Add"], row["error"] = line, "Too many fields (use hostname,mac,ip)"
        rows.append(row)
    return rows


def fill_hostnames(rows):
    """A missing hostname becomes the MAC without separators, lower case (aa:aa:aa:bb:bb:bb -> aaaaaabbbbbb)."""
    for r in rows:
        mac = normalize_mac(r["MAC_Add"])
        if not r["HName"].strip() and MAC_RE.match(mac):
            r["HName"], r["note"] = mac.replace(":", "").lower(), "hostname from MAC"
    return rows


def macs_bound_elsewhere(server_name, servers):
    """{MAC: other DHCP server name} for the static leases of every server except server_name."""
    return {normalize_mac(l["MAC_Add"]): s["name"] for s in servers if s["name"] != server_name for l in s["leases"]}


def _free_ips(server, subnet):
    """Candidate addresses of the subnet in ascending order, skipping the dynamic ranges."""
    ranges = []
    for r in server["dynamic_ranges"]:
        start, _, end = r.partition("-")
        ranges.append((int(ipaddress.IPv4Address(start.strip())), int(ipaddress.IPv4Address((end or start).strip()))))
    hosts = subnet.num_addresses > 2
    ip, last = int(subnet.network_address) + hosts, int(subnet.broadcast_address) - hosts
    while ip <= last:
        inside = next((end for start, end in ranges if start <= ip <= end), None)
        if inside is not None:
            ip = inside + 1  # jump over the whole range
            continue
        yield str(ipaddress.IPv4Address(ip))
        ip += 1


def validate_new_leases(server, new_leases, auto_ip=False, bound_elsewhere=None):
    """Mark each new lease as ok or skipped (with reason). Returns a list of dicts, in input order.

    auto_ip: a lease without an IP gets the lowest free address of the DHCP subnet (outside the dynamic range, not
             the gateway, not taken). Leases with an IP are checked first, so a free address is only handed out
             once the explicit IPs are known, and only to a lease that passed every other check.
    bound_elsewhere: {MAC: server name}; such a MAC is skipped (see macs_bound_elsewhere).
    """
    subnet = _dhcp_subnet(server["params"])

    taken_names = {l["HName"].lower() for l in server["leases"]}
    taken_macs = {normalize_mac(l["MAC_Add"]) for l in server["leases"]}
    taken_ips = {l["IpAdd"] for l in server["leases"]}
    bound_elsewhere = bound_elsewhere or {}
    free = None

    order = range(len(new_leases))
    if auto_ip:
        order = sorted(order, key=lambda i: not new_leases[i]["IpAdd"].strip())
    results = [None] * len(new_leases)
    for i in order:
        lease = new_leases[i]
        name, mac, ip = lease["HName"].strip(), normalize_mac(lease["MAC_Add"]), lease["IpAdd"].strip()
        note = lease.get("note", "")
        reason = None
        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            ip_obj = None

        if lease.get("error"):
            reason = lease["error"]
        elif not MAC_RE.match(mac):
            reason = "Invalid MAC address"
        elif not name:
            reason = "Hostname is empty"
        elif name.lower() in taken_names:
            reason = "Hostname already exists"
        elif mac in taken_macs:
            reason = "MAC already exists"
        elif mac in bound_elsewhere:
            reason = f"MAC already bound on DHCP server '{bound_elsewhere[mac]}'"
        elif auto_ip and not ip:
            if subnet is None:
                reason = "Cannot pick a free IP: the DHCP server has no gateway/subnet mask"
            else:
                if free is None:
                    free = _free_ips(server, subnet)
                ip = next((c for c in free if c not in taken_ips and c != server["params"]["Gateway"]), "")
                if ip:
                    note = ", ".join(filter(None, [note, "IP auto-assigned"]))
                else:
                    reason = "No free IP left in the DHCP subnet"
        elif ip_obj is None:
            reason = "Invalid IP address"
        elif subnet and ip_obj not in subnet:
            reason = f"IP is outside DHCP subnet {subnet}"
        elif _in_dynamic_range(ip_obj, server["dynamic_ranges"]):
            reason = "IP is in dynamic range"
        elif ip in taken_ips:
            reason = "IP already exists"

        if reason is None:
            # Also catches duplicates inside the uploaded sheet itself.
            taken_names.add(name.lower())
            taken_macs.add(mac)
            taken_ips.add(ip)
        results[i] = {"HName": name, "MAC_Add": mac, "IpAdd": ip, "ok": reason is None, "reason": reason or "", "note": note}
    return results


def add_static_leases(DSerName, new_leases, check_other_servers=False):
    """Validate and add new static leases while keeping all existing settings and leases.
    check_other_servers: also skip a MAC that is already bound on another DHCP server."""
    if check_other_servers:
        servers = get_dhcp_servers()
        server = next((s for s in servers if s["name"] == DSerName), None)
        if server is None:
            raise sophoslogin.SophosError(f"DHCP server '{DSerName}' not found.")
        checked = validate_new_leases(server, new_leases, bound_elsewhere=macs_bound_elsewhere(DSerName, servers))
    else:
        server = get_existing_leases(DSerName)
        checked = validate_new_leases(server, new_leases)
    to_add = [l for l in checked if l["ok"]]
    if not to_add:
        return {"ok": False, "message": "No valid new leases to add.", "results": checked}

    p = {k: escape(v) for k, v in server["params"].items()}
    ranges = "".join(f"<IP>{escape(r)}</IP>" for r in server["dynamic_ranges"])
    leases = "".join(
        f"""<Lease transactionid="{i}">
                <HostName>{escape(l['HName'])}</HostName>
                <MACAddress>{escape(l['MAC_Add'])}</MACAddress>
                <IPAddress>{escape(l['IpAdd'])}</IPAddress>
            </Lease>"""
        for i, l in enumerate(server["leases"] + to_add, start=1)
    )
    xml_payload = f"""
    <Set operation="update">
        <DHCPServer>
            <Name>{escape(DSerName)}</Name>
            <Interface>{p['Interface']}</Interface>
            <UseInterfaceIPasGateway>{p['UseInterfaceIPasGateway']}</UseInterfaceIPasGateway>
            <IPLease>{ranges}</IPLease>
            <Gateway>{p['Gateway']}</Gateway>
            <SubnetMask>{p['SubnetMask']}</SubnetMask>
            <DefaultLeaseTime>{p['DefaultLeaseTime']}</DefaultLeaseTime>
            <MaxLeaseTime>{p['MaxLeaseTime']}</MaxLeaseTime>
            <ConflictDetection>{p['ConflictDetection']}</ConflictDetection>
            <UseApplianceDNSSettings>{p['UseApplianceDNSSettings']}</UseApplianceDNSSettings>
            <PrimaryDNSServer>{p['PrimaryDNSServer']}</PrimaryDNSServer>
            <SecondaryDNSServer>{p['SecondaryDNSServer']}</SecondaryDNSServer>
            <PrimaryWINSServer>{p['PrimaryWINSServer']}</PrimaryWINSServer>
            <SecondaryWINSServer>{p['SecondaryWINSServer']}</SecondaryWINSServer>
            <DomainName>{p['DomainName']}</DomainName>
            <StaticLease>{leases}</StaticLease>
        </DHCPServer>
    </Set>
    """
    response = sophoslogin.login(xml_payload)
    code, message = sophoslogin.parse_status(response.text)
    ok = code == "200"
    if not ok:
        for l in to_add:
            l["ok"], l["reason"] = False, "Firewall rejected update"
    return {"ok": ok, "message": f"[{code}] {message}", "results": checked, "added": len(to_add) if ok else 0}


def leases_to_csv(leases):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["HostName", "MAC_Address", "IP_Address"])
    for l in leases:
        writer.writerow([l["HName"], l["MAC_Add"], l["IpAdd"]])
    return out.getvalue()


def Add_Static_Binding(csv_path=os.path.join(BASE_DIR, "datasheet.csv")):
    """CLI: add static leases from a CSV sheet."""
    DSerName = input("Please Enter the dhcp server name  :-  ")
    result = add_static_leases(DSerName, read_lease_csv(csv_path))
    for r in result["results"]:
        print(("✅ " if r["ok"] else "⚠️  Skipping ") + f"{r['HName']} {r['MAC_Add']} {r['IpAdd']} {r['reason']}")
    print(result["message"])


def get_existing_leases_file(DSerName, csv_file=os.path.join(BASE_DIR, "leasesheet.csv")):
    """Export the static leases of a DHCP server to CSV (with header, re-importable)."""
    leases = get_existing_leases(DSerName)["leases"]
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        f.write(leases_to_csv(leases))
    print(f"✅ {len(leases)} DHCP leases written to {csv_file}")


if __name__ == "__main__":
    get_existing_leases_file("vlan29")
    # Add_Static_Binding()
