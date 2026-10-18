"""IP / subnet planning across firewalls (merged from the IP_Subnet_Checkers tool).

Fetches IP hosts, interfaces/VLANs, IPsec VPNs, firewall rules and NAT rules from each
firewall and keeps them in memory, so the portal can answer:

  * Where is this IP or network used?         search()
  * Which private subnets are still free?     free_subnets()
  * Which addresses in a /24 are alive?       live_hosts()  (needs the nmap program)

The cache is per process (see gunicorn.conf.py: one worker) and keyed by firewall id.
"""
import ipaddress
import shutil
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import Sophos_Login_And_Sendrequest as sophoslogin

POOLS = [ipaddress.ip_network(n) for n in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12")]
LIVE_PORTS = "21,22,80,443,8080,8443"
SECTIONS = ("IPHost", "Interface", "VPN", "FirewallRule", "NATRule")

_cache = {}  # fw_id -> {"name", "loaded_at", "IPHost": {...}, "Interface": [...], ...}
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _get(entity):
    """Fetch one entity type from the active firewall. Raises SophosError if login fails."""
    return ET.fromstring(sophoslogin.login(f"<Get><{entity}></{entity}></Get>").text)


def to_network(text):
    try:
        return ipaddress.ip_network(text, strict=False)
    except (ValueError, TypeError):
        return None


# ---- Parsers (one per section)
def _hosts():
    hosts = {}
    for h in _get("IPHost").findall("IPHost"):
        hosts[h.findtext("Name")] = {
            "HostType": h.findtext("HostType"),
            "IPAddress": h.findtext("IPAddress"),
            "ListOfIPAddresses": h.findtext("ListOfIPAddresses"),
            "Subnet": h.findtext("Subnet"),
            "StartIPAddress": h.findtext("StartIPAddress"),
            "EndIPAddress": h.findtext("EndIPAddress"),
        }
    return hosts


def _interfaces():
    interfaces = []
    for entity, zone_tag in (("Interface", "NetworkZone"), ("VLAN", "Zone")):
        for item in _get(entity).findall(entity):
            if not item.findtext("Hardware"):
                continue
            ip, mask = item.findtext("IPAddress"), item.findtext("Netmask")
            net = to_network(f"{ip}/{mask}") if ip and mask else None
            interfaces.append({"Name": item.findtext("Hardware"), "Type": entity, "Zone": item.findtext(zone_tag),
                               "IPAddress": ip, "Netmask": mask, "Network": str(net) if net else ""})
    return interfaces


def _vpns():
    return [{
        "Name": v.findtext("Name"),
        "RemoteNetwork": [n.text for n in v.findall("RemoteNetwork/Network")],
        "LocalSubnet": [s.text for s in v.findall("LocalSubnet")],
        "NATedLAN": [n.text for n in v.findall("NATedLAN")],
        "RemoteHost": v.findtext("RemoteHost"),
    } for v in _get("VPNIPSecConnection").findall(".//VPNIPSecConnection/Configuration")]


def _firewall_rules():
    return [{
        "Name": r.findtext("Name"),
        "Status": r.findtext("Status"),
        "Action": r.findtext(".//Action"),
        "SourceZones": [z.text for z in r.findall(".//SourceZones/Zone")],
        "SourceNetworks": [n.text for n in r.findall(".//SourceNetworks/Network")],
        "DestinationZones": [z.text for z in r.findall(".//DestinationZones/Zone")],
        "DestinationNetworks": [n.text for n in r.findall(".//DestinationNetworks/Network")],
        "Services": [s.text for s in r.findall(".//Services/Service")],
    } for r in _get("FirewallRule").findall("FirewallRule")]


def _nat_rules():
    return [{
        "Name": r.findtext("Name"),
        "Status": r.findtext("Status"),
        "OriginalSourceNetworks": [n.text for n in r.findall(".//OriginalSourceNetworks/Network")],
        "OriginalDestinationNetworks": [n.text for n in r.findall(".//OriginalDestinationNetworks/Network")],
        "OriginalServices": [s.text for s in r.findall(".//OriginalServices/Service")],
        "TranslatedSource": r.findtext("TranslatedSource"),
        "TranslatedDestination": r.findtext("TranslatedDestination"),
    } for r in _get("NATRule").findall("NATRule")]


_FETCHERS = (("IPHost", "IP hosts", _hosts), ("Interface", "interfaces", _interfaces), ("VPN", "VPN", _vpns),
             ("FirewallRule", "firewall rules", _firewall_rules), ("NATRule", "NAT rules", _nat_rules))


def load(fw):
    """Fetch every section from one firewall (dict from firewalls.get(..., with_password=True)).

    A section that fails keeps its previously loaded data. Returns a list of error strings.
    """
    errors, fresh = [], {}
    with sophoslogin.using(fw["url"], fw["username"], fw["password"]):
        for key, label, fetch in _FETCHERS:
            try:
                fresh[key] = fetch()
            except sophoslogin.SophosError as e:
                errors.append(f"{fw['name']} - {label}: {e}")
                if "Login failed" in str(e) or "Cannot reach" in str(e):
                    break  # every other section would fail the same way
            except ET.ParseError as e:
                errors.append(f"{fw['name']} - {label}: invalid XML ({e})")

    if not fresh:
        return errors

    # System hosts such as #Port1 carry no address; their address is the interface address.
    by_name = {i["Name"]: i for i in fresh.get("Interface", []) if i["IPAddress"]}
    for name, host in fresh.get("IPHost", {}).items():
        if host["HostType"] == "System Host" and name.startswith("#") and not host["IPAddress"] and name[1:] in by_name:
            host["IPAddress"], host["Subnet"] = by_name[name[1:]]["IPAddress"], "255.255.255.255"

    with _lock:
        entry = _cache.setdefault(fw["id"], {key: [] for key in SECTIONS} | {"IPHost": {}})
        entry.update(fresh, name=fw["name"], loaded_at=_now())
    return errors


def forget(fw_id):
    with _lock:
        _cache.pop(fw_id, None)


def status():
    """What is loaded: [{id, name, loaded_at, counts}]."""
    with _lock:
        return sorted(({"id": fw_id, "name": e["name"], "loaded_at": e["loaded_at"],
                        "counts": {k: len(e[k]) for k in SECTIONS}} for fw_id, e in _cache.items()),
                      key=lambda s: s["name"].lower())


def _snapshot(fw_ids=None):
    with _lock:
        return {fw_id: e for fw_id, e in _cache.items() if fw_ids is None or fw_id in fw_ids}


# ---- Search
def host_networks(details):
    """Every network a host object covers: a single IP, a network, an IP list or an IP range."""
    nets = []
    if details.get("IPAddress") and details.get("Subnet"):
        nets.append(to_network(f"{details['IPAddress']}/{details['Subnet']}"))
    elif details.get("IPAddress"):
        nets.append(to_network(details["IPAddress"]))
    for ip in (details.get("ListOfIPAddresses") or "").split(","):
        if ip.strip():
            nets.append(to_network(ip.strip()))
    start, end = details.get("StartIPAddress"), details.get("EndIPAddress")
    if start and end:
        try:
            nets.extend(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
        except (ValueError, TypeError):
            pass
    return [n for n in nets if n is not None]


def _overlaps(net, target):
    return net is not None and net.version == target.version and net.overlaps(target)


def search(value, fw_ids=None):
    """Where is this IP / network used? Returns [{name, IPHost, Interface, FirewallRule, NATRule, VPN}]."""
    try:
        target = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValueError("Enter a valid IP or network, for example 10.20.28.1 or 10.20.28.0/22.")

    results = []
    for fw_id, data in _snapshot(fw_ids).items():
        hosts = {n: d for n, d in data["IPHost"].items() if any(_overlaps(net, target) for net in host_networks(d))}
        names = set(hosts)

        def vpn_match(v):
            used = v["RemoteNetwork"] + v["LocalSubnet"] + v["NATedLAN"]
            return bool(names & set(used)) or any(_overlaps(to_network(x), target) for x in used + [v["RemoteHost"]] if x)

        results.append({
            "id": fw_id, "name": data["name"], "loaded_at": data["loaded_at"],
            "IPHost": [{"Name": n, **d} for n, d in hosts.items()],
            "Interface": [i for i in data["Interface"] if _overlaps(to_network(i["Network"]), target)],
            "FirewallRule": [r for r in data["FirewallRule"] if names & set(r["SourceNetworks"] + r["DestinationNetworks"])],
            "NATRule": [r for r in data["NATRule"] if names & set(r["OriginalSourceNetworks"] + r["OriginalDestinationNetworks"]
                                                              + [r["TranslatedSource"], r["TranslatedDestination"]])],
            "VPN": [v for v in data["VPN"] if vpn_match(v)],
        })
    return sorted(results, key=lambda r: r["name"].lower())


def overview(fw_id):
    data = _snapshot({fw_id}).get(fw_id)
    if data is None:
        return None
    return {"name": data["name"], "loaded_at": data["loaded_at"], "IPHost": [{"Name": n, **d} for n, d in data["IPHost"].items()],
            **{k: data[k] for k in ("Interface", "VPN", "FirewallRule", "NATRule")}}


# ---- Free subnets
def _used_networks():
    used = []
    for data in _snapshot().values():
        for details in data["IPHost"].values():
            used.extend(host_networks(details))
        used.extend(to_network(i["Network"]) for i in data["Interface"] if i["Network"])
        for v in data["VPN"]:
            used.extend(to_network(x) for x in v["RemoteNetwork"] + v["LocalSubnet"] + v["NATedLAN"] if x)
    return [n for n in used if n is not None and n.version == 4 and n.prefixlen > 0]


def free_subnets(prefix, count):
    """Private IPv4 subnets of size /prefix that overlap nothing on any loaded firewall."""
    if not (8 <= prefix <= 30 and 1 <= count <= 300):
        raise ValueError("Prefix must be 8-30 and count 1-300.")
    used = _used_networks()
    free = []
    for pool in POOLS:
        if prefix < pool.prefixlen:
            continue  # e.g. a /12 cannot fit inside 192.168.0.0/16
        for candidate in pool.subnets(new_prefix=prefix):
            if not any(candidate.overlaps(n) for n in used):
                free.append(str(candidate))
                if len(free) == count:
                    return free
    return free


# ---- Live hosts (nmap)
def live_hosts(target):
    """Ping a network (/24 or smaller), then probe common TCP ports on hosts that did not answer."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        raise ValueError("Enter a valid IP or network, for example 172.16.64.0/26.")
    if network.version != 4 or network.prefixlen < 24:
        raise ValueError("Use an IPv4 address or a network of /24 or smaller.")
    if not shutil.which("nmap"):
        raise ValueError("The nmap program is not installed on the portal server (it is included in the Docker image).")

    import nmap  # python-nmap; imported here so the rest of the portal works without it

    all_ips = [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    live = {}

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=str(network), arguments="-sn -PE")
        for ip in nm.all_hosts():
            if nm[ip].state() == "up":
                live[ip] = "Ping reply"

        no_reply = [ip for ip in all_ips if ip not in live]
        if no_reply:
            # -sS (SYN scan) needs root / CAP_NET_RAW: the Docker container runs as root.
            nm.scan(hosts=" ".join(no_reply), ports=LIVE_PORTS, arguments="-Pn -T4 -sS")
            for ip in nm.all_hosts():
                open_ports = sorted(p for p, info in nm[ip].get("tcp", {}).items() if info["state"] == "open")
                if open_ports:
                    live[ip] = f"No ping, open ports {', '.join(map(str, open_ports))}"
    except nmap.PortScannerError as e:
        raise ValueError(f"Scan failed: {e}")

    rows = [{"IP": ip, "Result": live[ip]} for ip in sorted(live, key=ipaddress.ip_address)]
    return rows, len(all_ips)
