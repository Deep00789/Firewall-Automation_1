import requests

FIREWALL_IP = "https://192.168.159.133:4444"
API_URL = f"{FIREWALL_IP}/webconsole/APIController"
USERNAME = "admin"
PASSWORD = "Ert@Adm2025"
requests.packages.urllib3.disable_warnings()

def send_request(xml_payload):
    """Send API request to Sophos Firewall"""
    response = requests.post(API_URL, files={'reqxml': (None, xml_payload)}, verify=False)
    print(f"\nStatus Code: {response.status_code}")
    #print(f"Response:\n{response.text.strip()}\n")
    return response

def login(xml_payload):
    """Login to Sophos Firewall and send XML request"""
    login_payload = f"""<Request>
    <Login>
        <Username>{USERNAME}</Username>
        <Password>{PASSWORD}</Password>
    </Login>
    <!-- Insert New XML Here -->
    </Request>"""
    return send_request(login_payload.replace("<!-- Insert New XML Here -->", xml_payload))