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


def validate_new_leases(server, new_leases):
    """Mark each new lease as ok or skipped (with reason). Returns a list of dicts."""
    params = server["params"]
    subnet = None
    if params["Gateway"] and params["SubnetMask"]:
        try:
            subnet = ipaddress.IPv4Network(f"{params['Gateway']}/{params['SubnetMask']}", strict=False)
        except ValueError:
            pass

    taken_names = {l["HName"].lower() for l in server["leases"]}
    taken_macs = {l["MAC_Add"].upper().replace("-", ":") for l in server["leases"]}
    taken_ips = {l["IpAdd"] for l in server["leases"]}

    results = []
    for lease in new_leases:
        name, mac, ip = lease["HName"], lease["MAC_Add"].upper().replace("-", ":"), lease["IpAdd"]
        reason = None
        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            ip_obj = None

        if not name:
            reason = "Hostname is empty"
        elif not MAC_RE.match(mac):
            reason = "Invalid MAC address"
        elif ip_obj is None:
            reason = "Invalid IP address"
        elif subnet and ip_obj not in subnet:
            reason = f"IP is outside DHCP subnet {subnet}"
        elif _in_dynamic_range(ip_obj, server["dynamic_ranges"]):
            reason = "IP is in dynamic range"
        elif name.lower() in taken_names:
            reason = "Hostname already exists"
        elif mac in taken_macs:
            reason = "MAC already exists"
        elif ip in taken_ips:
            reason = "IP already exists"

        if reason is None:
            # Also catches duplicates inside the uploaded sheet itself.
            taken_names.add(name.lower())
            taken_macs.add(mac)
            taken_ips.add(ip)
        results.append({"HName": name, "MAC_Add": mac, "IpAdd": ip, "ok": reason is None, "reason": reason or ""})
    return results


def add_static_leases(DSerName, new_leases):
    """Validate and add new static leases while keeping all existing settings and leases."""
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
