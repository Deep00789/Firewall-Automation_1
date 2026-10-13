import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings (for self-signed certificates)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SophosFirewallAPI:
    def __init__(self, firewall_ip, username, password, verify_ssl=False):
        """
        Initialize Sophos Firewall API client

        Args:
            firewall_ip: IP address or hostname of the Sophos Firewall (e.g., '192.168.1.1')
            username: Username for authentication
            password: Password for authentication
            verify_ssl: Whether to verify SSL certificate (default: False for self-signed certs)
        """
        self.firewall_ip = firewall_ip
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{firewall_ip}/api/v2"
        self.session_token = None
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def login(self):
        """
        Authenticate to the Sophos Firewall and get session token

        Returns:
            bool: True if login successful, False otherwise
        """
        try:
            login_url = f"{self.base_url}/authentication/login"

            payload = {
                "username": self.username,
                "password": self.password
            }

            response = requests.post(
                login_url,
                json=payload,
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 200:
                response_data = response.json()
                self.session_token = response_data.get('token')
                print(f"✓ Login successful!")
                print(f"  Session Token: {self.session_token[:20]}...")
                return True
            else:
                print(f"✗ Login failed with status code: {response.status_code}")
                print(f"  Response: {response.text}")
                return False

        except requests.exceptions.ConnectionError as e:
            print(f"✗ Connection error: {e}")
            return False
        except requests.exceptions.Timeout as e:
            print(f"✗ Request timeout: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error during login: {e}")
            return False

    def get_ip_hosts(self):
        """
        Fetch all IP hosts from the Sophos Firewall

        Returns:
            list: List of IP host objects, or empty list if failed
        """
        if not self.session_token:
            print("✗ Not authenticated. Please login first.")
            return []

        try:
            # Update headers with session token
            headers = self.headers.copy()
            headers['X-Sophos-Session'] = self.session_token

            hosts_url = f"{self.base_url}/objects/iphost"

            response = requests.get(
                hosts_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code == 200:
                response_data = response.json()
                hosts = response_data.get('iphost', [])
                print(f"✓ Retrieved {len(hosts)} IP hosts")
                return hosts
            elif response.status_code == 401:
                print("✗ Unauthorized: Session token expired or invalid")
                return []
            else:
                print(f"✗ Failed to fetch IP hosts with status code: {response.status_code}")
                print(f"  Response: {response.text}")
                return []

        except requests.exceptions.ConnectionError as e:
            print(f"✗ Connection error: {e}")
            return []
        except requests.exceptions.Timeout as e:
            print(f"✗ Request timeout: {e}")
            return []
        except Exception as e:
            print(f"✗ Unexpected error fetching IP hosts: {e}")
            return []

    def get_ip_host_by_name(self, host_name):
        """
        Fetch a specific IP host by name

        Args:
            host_name: Name of the IP host

        Returns:
            dict: IP host object or empty dict if not found
        """
        hosts = self.get_ip_hosts()
        for host in hosts:
            if host.get('name') == host_name:
                return host
        print(f"✗ Host '{host_name}' not found")
        return {}

    def get_ip_host_by_ip(self, ip_address):
        """
        Fetch a specific IP host by IP address

        Args:
            ip_address: IP address to search for

        Returns:
            dict: IP host object or empty dict if not found
        """
        hosts = self.get_ip_hosts()
        for host in hosts:
            if host.get('ipaddress') == ip_address:
                return host
        print(f"✗ Host with IP '{ip_address}' not found")
        return {}

    def print_hosts_table(self):
        """Print all IP hosts in a formatted table"""
        hosts = self.get_ip_hosts()

        if not hosts:
            print("No IP hosts found")
            return

        print("\n" + "="*100)
        print(f"{'Name':<30} {'IP Address':<20} {'Description':<50}")
        print("="*100)

        for host in hosts:
            name = host.get('name', 'N/A')
            ip_address = host.get('ipaddress', 'N/A')
            description = host.get('description', '')[:47] + '...' if len(host.get('description', '')) > 50 else host.get('description', '')

            print(f"{name:<30} {ip_address:<20} {description:<50}")

        print("="*100 + "\n")

    def logout(self):
        """Logout from the Sophos Firewall"""
        if not self.session_token:
            print("✗ Not authenticated")
            return False

        try:
            headers = self.headers.copy()
            headers['X-Sophos-Session'] = self.session_token

            logout_url = f"{self.base_url}/authentication/logout"

            response = requests.post(
                logout_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=10
            )

            if response.status_code in [200, 204]:
                print("✓ Logged out successfully")
                self.session_token = None
                return True
            else:
                print(f"✗ Logout failed with status code: {response.status_code}")
                return False

        except Exception as e:
            print(f"✗ Error during logout: {e}")
            return False


# =====================================================================
# USAGE EXAMPLE
# =====================================================================

if __name__ == "__main__":
    # Configure your firewall credentials here
    FIREWALL_IP = "192.168.1.1"          # Replace with your firewall IP
    USERNAME = "admin"                     # Replace with your username
    PASSWORD = "your_password"             # Replace with your password

    # Initialize API client
    api = SophosFirewallAPI(
        firewall_ip=FIREWALL_IP,
        username=USERNAME,
        password=PASSWORD,
        verify_ssl=False  # Set to True if using valid SSL certificate
    )

    # Login
    if api.login():
        print("\n" + "-"*100)
        print("Fetching IP Hosts")
        print("-"*100)

        # Get all IP hosts and print in table format
        api.print_hosts_table()

        # Example: Get specific host by name
        print("\nFetching specific host by name:")
        host = api.get_ip_host_by_name("Server1")
        if host:
            print(f"  Found: {json.dumps(host, indent=2)}")

        # Example: Get specific host by IP
        print("\nFetching specific host by IP:")
        host = api.get_ip_host_by_ip("192.168.1.100")
        if host:
            print(f"  Found: {json.dumps(host, indent=2)}")

        # Get all hosts as JSON
        print("\nAll IP Hosts (JSON):")
        all_hosts = api.get_ip_hosts()
        print(json.dumps(all_hosts, indent=2))

        # Logout
        api.logout()
    else:
        print("Failed to authenticate with the firewall")
