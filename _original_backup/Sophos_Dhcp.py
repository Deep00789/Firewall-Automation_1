#import requests
import xml.etree.ElementTree as ET
import pandas as pd
import ipaddress
import Sophos_Login_And_Sendrequest as sophoslogin


def get_existing_leases(DSerName):
    """Fetch existing DHCP static leases and dynamic ranges"""
    leases = []
    dynamic_leases = []
    DHCP_Parameter = []

    xml_payload = f"""
    <Get>
        <DHCPServer>
            <Name>{DSerName}</Name>
        </DHCPServer>
    </Get>
    """

    response = sophoslogin.login(xml_payload)
    if response is None or response.status_code != 200:
        print("❌ Failed to retrieve existing leases.")
        return [], [], []

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        print("❌ XML Parsing Error:", e)
        return [], [], []

    global dynamic_ip_range
    dynamic_ip_range = []

    for dhcp_server in root.findall(".//DHCPServer"):
        if dhcp_server.findtext("Name") == DSerName:
            
            # Fetch dynamic IP leases (Multiple IPLease entries)             
            for lease in dhcp_server.findall("IPLease"):
                for Iplease in lease.findall("IP"):
                    ip_range = Iplease.text.strip()
                    if ip_range:
                        dynamic_leases.append({"IP_range": ip_range})
                        start_ip, end_ip = ip_range.split("-")
                        start = int(ipaddress.IPv4Address(start_ip))
                        end = int(ipaddress.IPv4Address(end_ip))
                        for Ip in range(start, end + 1):
                            dynamic_ip_range.append(str(ipaddress.IPv4Address(Ip)))

            # Fetch DHCP settings
            DHCP_Parameter.append({
                "Interfaceasagateway": dhcp_server.findtext("UseInterfaceIPasGateway", "").strip(),
                "ConflictDetection_": dhcp_server.findtext("ConflictDetection", "").strip(),
                "Subnet_": dhcp_server.findtext("SubnetMask", "").strip(),
                "Gateway_": dhcp_server.findtext("Gateway", "").strip(),
                "DefaultLeaseTime_": dhcp_server.findtext("DefaultLeaseTime", "").strip(),
                "MaxLeaseTIme_": dhcp_server.findtext("MaxLeaseTime", "").strip(),
                "UseApplianceDNSSettings_": dhcp_server.findtext("UseApplianceDNSSettings", "").strip(),
                "Interface_": dhcp_server.findtext("Interface", "").strip(),
                "PrimaryDNSServer_": dhcp_server.findtext("PrimaryDNSServer", "").strip(),
                "SecondaryDNSServer_": dhcp_server.findtext("SecondaryDNSServer", "").strip(),
                "PrimaryWINSServer_": dhcp_server.findtext("PrimaryWINSServer", "").strip(),
                "SecondaryWINSServer_": dhcp_server.findtext("SecondaryWINSServer", "").strip()
            })

            # Fetch static leases
            static_lease = dhcp_server.find("StaticLease")
            if static_lease is not None:
                for lease in static_lease.findall("Lease"):
                    leases.append({
                        "HName": lease.findtext("HostName", "").strip(),
                        "MAC_Add": lease.findtext("MACAddress", "").strip(),
                        "IpAdd": lease.findtext("IPAddress", "").strip()
                    })
            break  # Stop searching after finding the correct DHCPServer

    print("\n🔹 Dynamic IP Ranges:", dynamic_leases)
    return leases, DHCP_Parameter, dynamic_leases

def Add_Static_Binding():
    """Add new static DHCP leases while keeping ALL existing IPLease entries"""
    DSerName = input("Please Enter the dhcp server name  :-  ")

    # Import the CSV sheet for add the static lease
    Lease_Sheet = pd.read_csv("C:\\Users\\deepkumar.p\\Documents\\ER Tech Pros Support\\FirewallAutomation\\datasheet.csv")

    new_static_leases = []

    existing_leases, DHCP_Param, dynamic_leases = get_existing_leases(DSerName)

    # Check for conflicts with dynamic range
    for host, mac, ip in zip(Lease_Sheet["HostName"], Lease_Sheet["MAC_Address"], Lease_Sheet["IP_Address"]):
        if str(ip) in dynamic_ip_range:
            print(f"⚠️  Skipping {ip}: IP is in dynamic range.")
            continue
        new_static_leases.append({"HName": host, "MAC_Add": mac, "IpAdd": ip})

    print("\n🔹 New Static Leases Before Filtering:", new_static_leases)

    # Remove duplicates
    for Nitem in new_static_leases[:]:
        for Eitem in existing_leases:
            if Nitem["HName"].lower() == Eitem["HName"].lower():
                print(f"⚠️  Skipping {Nitem['HName']}: Hostname already exists.")
                new_static_leases.remove(Nitem)
                break
            elif Nitem["MAC_Add"] == Eitem["MAC_Add"]:
                print(f"⚠️  Skipping {Nitem['MAC_Add']}: MAC already exists.")
                new_static_leases.remove(Nitem)
                break
            elif Nitem["IpAdd"] == Eitem["IpAdd"]:
                print(f"⚠️  Skipping {Nitem['IpAdd']}: IP already exists.")
                new_static_leases.remove(Nitem)
                break

    print("\n🔹 New Static Leases After Filtering:", new_static_leases)
    if not new_static_leases:
        print("❌ No new leases to add. Exiting.")
        return

    combined_leases = existing_leases + new_static_leases

    if not DHCP_Param:
        print("❌ Missing required DHCP parameters. Cannot proceed.")
        return

    # Construct XML payload while keeping all existing IPLease entries
    xml_payload = f"""
    <Set operation="update">
        <DHCPServer>
            <Name>{DSerName}</Name>
            <Interface>{DHCP_Param[0].get('Interface_', '')}</Interface>
            <UseInterfaceIPasGateway>{DHCP_Param[0].get('Interfaceasagateway', '')}</UseInterfaceIPasGateway>
            <IPLease>
    """

    # **Preserve all existing dynamic IP leases**
    for count, lease in enumerate(dynamic_leases, start=1):
        xml_payload += f"""
                <IP>{lease['IP_range']}</IP>
                """
                    
    xml_payload += f"""
            </IPLease>
            <Gateway>{DHCP_Param[0].get('Gateway_', '')}</Gateway>
            <SubnetMask>{DHCP_Param[0].get('Subnet_', '')}</SubnetMask>
            <DefaultLeaseTime>{DHCP_Param[0].get('DefaultLeaseTime_', '')}</DefaultLeaseTime>
            <MaxLeaseTime>{DHCP_Param[0].get('MaxLeaseTIme_', '')}</MaxLeaseTime>
            <ConflictDetection>{DHCP_Param[0].get('ConflictDetection_', '')}</ConflictDetection>
            <UseApplianceDNSSettings>{DHCP_Param[0].get('UseApplianceDNSSettings_', '')}</UseApplianceDNSSettings>
            <PrimaryDNSServer>{DHCP_Param[0].get('PrimaryDNSServer_', '')}</PrimaryDNSServer>
		    <SecondaryDNSServer>{DHCP_Param[0].get('SecondaryDNSServer_', '')}</SecondaryDNSServer>
		    <PrimaryWINSServer>{DHCP_Param[0].get('PrimaryWINSServer_', '')}</PrimaryWINSServer>
		    <SecondaryWINSServer>{DHCP_Param[0].get('SecondaryWINSServer_', '')}</SecondaryWINSServer>
            <DomainName>{DHCP_Param[0].get('DomainName_', '')}</DomainName>
            <StaticLease>
    """

    # **Add static leases**
    for i, lease in enumerate(combined_leases, start=1):
        xml_payload += f"""
                <Lease transactionid="{i}">
                    <HostName>{lease['HName']}</HostName>
                    <MACAddress>{lease['MAC_Add']}</MACAddress>
                    <IPAddress>{lease['IpAdd']}</IPAddress>
                </Lease>
        """

    xml_payload += """
            </StaticLease>
        </DHCPServer>
    </Set>
    """

    #print("\n🔹 Final XML Payload Being Sent:\n", xml_payload)

    response = sophoslogin.login(xml_payload)

    if '<Status code="501">' in response.text:
        print("❌ Failed to update static leases. Check required parameters.")
    else:
        print("✅ Successfully updated Static Leases.")
    print(DHCP_Param[0].get('Gateway_', ''))

def get_existing_leases_file(DSerName):

    """Fetch existing DHCP static leases and dynamic ranges"""
    leases = []
    

    xml_payload = f"""
    <Get>
        <DHCPServer>
            <Name>{DSerName}</Name>
        </DHCPServer>
    </Get>
    """

    response = sophoslogin.login(xml_payload)
    print(response.text)
    if response is None or response.status_code != 200:
        print("❌ Failed to retrieve existing leases.")
        return [], [], []

    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        print("❌ XML Parsing Error:", e)
        return [], [], []

    for dhcp_server in root.findall(".//DHCPServer"):
        if dhcp_server.findtext("Name") == DSerName:
            static_lease = dhcp_server.find("StaticLease")
            if static_lease is not None:
                for lease in static_lease.findall("Lease"):
                    leases.append({
                        "HName": lease.findtext("HostName", "").strip(),
                        "MAC_Add": lease.findtext("MACAddress", "").strip(),
                        "IpAdd": lease.findtext("IPAddress", "").strip()
                    })
            break  # Stop searching after finding the correct DHCPServer
    csv_file = "C:\\Users\\deepkumar.p\\Documents\\ER Tech Pros Support\\FirewallAutomation\\leasesheet.csv"

    # Convert lease data to a DataFrame
    df_new = pd.DataFrame(leases)

    if not df_new.empty:
        try:
            # Append to CSV (create if it doesn't exist)
            df_new.to_csv(csv_file, mode='w', index=False, header=False)
            print("✅ DHCP leases appended to CSV successfully.")
        except Exception as e:
            print(f"❌ Error writing to CSV: {e}")
    else:
        print("ℹ️ No new leases found.")

x="vlan29"
get_existing_leases_file(x)
#Add_Static_Binding()
#get_existing_leases_file(x)