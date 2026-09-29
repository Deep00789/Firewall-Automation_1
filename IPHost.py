import ipaddress
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

import Sophos_Login_And_Sendrequest as sophoslogin


def _host_to_dict(iphost):
    return {
        "Name": iphost.findtext("Name", "").strip(),
        "Description": iphost.findtext("Description", "").strip(),
        "HostType": iphost.findtext("HostType", "").strip(),
        "IPFamily": iphost.findtext("IPFamily", "").strip(),
        "IPAddress": iphost.findtext("IPAddress", "").strip(),
        "Subnet": iphost.findtext("Subnet", "").strip(),
        "StartIPAddress": iphost.findtext("StartIPAddress", "").strip(),
        "EndIPAddress": iphost.findtext("EndIPAddress", "").strip(),
        "ListOfIPAddresses": iphost.findtext("ListOfIPAddresses", "").strip(),
        "HostGroup": [g.text.strip() for g in iphost.findall("HostGroupList/HostGroup") if g.text],
    }


def get_IPHosts(host_name="ALL"):
    """
    Fetch IPHost(s) from Sophos Firewall.
    - If host_name is None/empty/"ALL" -> returns ALL IPHosts
    - If host_name is provided -> returns only that host
    """
    fetch_all = not host_name or host_name.strip().upper() == "ALL"
    if fetch_all:
        xml_payload = "<Get><IPHost/></Get>"
    else:
        xml_payload = f"<Get><IPHost><Name>{escape(host_name)}</Name></IPHost></Get>"

    response = sophoslogin.login(xml_payload)
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        raise sophoslogin.SophosError(f"XML Parsing Error: {e}") from e

    hosts = [_host_to_dict(h) for h in root.findall(".//IPHost") if h.find("Name") is not None]
    if not fetch_all:
        hosts = [h for h in hosts if h["Name"] == host_name.strip()]
    return hosts


def edit_IPHost(IpHostName, IpList):
    """Append IPs to an existing IPList host. Returns a result dict."""
    hosts = get_IPHosts(IpHostName)
    if not hosts:
        return {"ok": False, "message": f"Host '{IpHostName}' not found."}
    host = hosts[0]
    if host["HostType"] != "IPList":
        return {"ok": False, "message": f"Host '{IpHostName}' is type {host['HostType']}; only IPList hosts can be extended."}

    existing = [ip.strip() for ip in host["ListOfIPAddresses"].split(",") if ip.strip()]
    added, skipped = [], []
    for ip in IpList:
        ip = ip.strip()
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            skipped.append(f"{ip} (invalid IP)")
            continue
        if ip in existing or ip in added:
            skipped.append(f"{ip} (already in list)")
            continue
        added.append(ip)

    if not added:
        return {"ok": False, "message": "No new IPs to add.", "added": [], "skipped": skipped}

    # Send Description and HostGroups back, otherwise the update wipes them.
    groups = "".join(f"<HostGroup>{escape(g)}</HostGroup>" for g in host["HostGroup"])
    xml_payload = f"""
    <Set operation="update">
        <IPHost>
            <Name>{escape(host['Name'])}</Name>
            <Description>{escape(host['Description'])}</Description>
            <IPFamily>{escape(host['IPFamily'])}</IPFamily>
            <HostType>IPList</HostType>
            <ListOfIPAddresses>{escape(",".join(existing + added))}</ListOfIPAddresses>
            <HostGroupList>{groups}</HostGroupList>
        </IPHost>
    </Set>
    """
    response = sophoslogin.login(xml_payload)
    code, message = sophoslogin.parse_status(response.text)
    return {
        "ok": code in ("200", "202"),
        "message": f"[{code}] {message}",
        "added": added if code in ("200", "202") else [],
        "skipped": skipped,
    }


if __name__ == "__main__":
    li1 = ["192.168.37.88", "177.25.68.36"]
    IpHostname = "list-host"
    print(edit_IPHost(IpHostname, li1))
    print(get_IPHosts(IpHostname))
