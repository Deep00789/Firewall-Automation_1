import xml.etree.ElementTree as ET
import Sophos_Login_And_Sendrequest as sophoslogin


def get_IPHosts(host_name):
    """
    Fetch IPHost(s) from Sophos Firewall.
    - If host_name is None -> returns ALL IPHosts
    - If host_name is provided -> returns only that host
    """
    iphostsall = []
    iphosts=[]
    if  host_name.upper() != all :
        xml_payload = f"""
        <Get>
            <IPHost>
                <Name>{host_name}</Name>
            </IPHost>
        </Get>
        """
        response = sophoslogin.login(xml_payload)
    else:
        xml_payload = """
        <Get>
            <IPHost/>
        </Get>
        """
        response = sophoslogin.login(xml_payload)
    print("XML Payload",response.text)
    
    if response is None or response.status_code != 200:
        print("❌ Failed to retrieve IPHost(s).")
        return []

    try:
        root = ET.fromstring(response.text)
        
      
        for iphost in root.findall(".//IPHost"):
            if host_name.upper() == "ALL":
                host_data = {
                    "Name": iphost.findtext("Name"),
                    "Description": iphost.findtext("Description"),
                    "HostType": iphost.findtext("HostType"),
                    "IPFamily": iphost.findtext("IPFamily"),
                    "IPAddress": iphost.findtext("IPAddress"),
                    "Subnet": iphost.findtext("Subnet"),
                    "StartIPAddress": iphost.findtext("StartIPAddress"),
                    "EndIPAddress": iphost.findtext("EndIPAddress"),
                    "ListOfIPAddresses": iphost.findtext("ListOfIPAddresses"),
                    "HostGroup":iphost.findtext("HostGroupList"),
                }
                iphostsall.append(host_data)
            
       
            elif host_name == iphost.findtext("Name").strip():
                host_data = {
                    "Name": iphost.findtext("Name"),
                    "Description": iphost.findtext("Description"),
                    "HostType": iphost.findtext("HostType"),
                    "IPFamily": iphost.findtext("IPFamily"),
                    "IPAddress": iphost.findtext("IPAddress"),
                    "Subnet": iphost.findtext("Subnet"),
                    "StartIPAddress": iphost.findtext("StartIPAddress"),
                    "EndIPAddress": iphost.findtext("EndIPAddress"),
                    "ListOfIPAddresses": iphost.findtext("ListOfIPAddresses"),
                    "HostGroup":iphost.findtext("HostGroupList"),
                }
                iphosts.append(host_data)
    
   
    except ET.ParseError as e:
        print("❌ XML Parsing Error:", e)
        return "Nothing Is parse"
    if  iphostsall != None:
        return iphostsall
    else:
        return iphosts

# Example usage:

def edit_IPHost(IpHostName, IpList):
    def Payload(Name, IPFamily, HostType, ListOfIPAddresses=None):
        if HostType == "IPList":
            xml_payload = f"""
            <Set operation="update">
            <IPHost transactionid="">
            <Name>{Name}</Name>
            <Description/>
            <IPFamily>{IPFamily}</IPFamily>
            <HostType>{HostType}</HostType>
            <IPAddress></IPAddress>
            <Subnet></Subnet>
            <StartIPAddress></StartIPAddress>
            <EndIPAddress></EndIPAddress>
            <ListOfIPAddresses>{ListOfIPAddresses}</ListOfIPAddresses>
            </IPHost>
            </Set>
            """
        else:
            xml_payload = f"""
            <Set operation="update">
            <Set operation="update">
            <IPHost transactionid="">
            <Name>{Name}</Name>
            <Description/>
            <IPFamily>{IPFamily}</IPFamily>
            <HostType>{HostType}</HostType>
            <IPAddress></IPAddress>
            <Subnet></Subnet>
            <StartIPAddress></StartIPAddress>
            <EndIPAddress></EndIPAddress>
            <ListOfIPAddresses>{ListOfIPAddresses}</ListOfIPAddresses>
            </IPHost>
            </Set>
            """
        return xml_payload.strip()

    print("This is called")
    all_host = get_IPHosts(IpHostName)
    print(all_host)
    print("This is called 1")
    for h in all_host:
        print("This is called")
        IPFamily = h["IPFamily"]
        HostType = h["HostType"]
        Hostname = h["Name"]
        ListOfIPAdd=h["ListOfIPAddresses"]

        print(f"Editing Host: {Hostname}, Type: {HostType}")

        if HostType == "IPList":
            Mylist_String = ",".join(IpList)
            Mylist_String=Mylist_String+","+ListOfIPAdd
            print(f"String list: {Mylist_String}")
            xml_payload_ = Payload(Hostname, IPFamily, HostType, Mylist_String)
        else:
            xml_payload_ = Payload(Hostname, IPFamily, HostType)

        print("XML Payload to be sent:\n", xml_payload_)

        response = sophoslogin.login(xml_payload_)
        print(response.text)

        if '<Status code="500">' in response.text:
            print("❌ Host could not be updated.")
        elif '<Status code="200">' in response.text:
            print("✅ Successfully updated host.")
        elif '<Status code="202">' in response.text:
            print("✅ Host renamed and updated successfully.")
        else:
            print("⚠️ Unexpected response:", response.text)


# Example usage
li1 = ["192.168.37.88", "177.25.68.36"]
IpHostname = "list-host"
edit_IPHost(IpHostname,li1)
print(get_IPHosts(IpHostname))
