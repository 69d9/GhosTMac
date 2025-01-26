#!/usr/bin/env python3

import subprocess
import re
import sys
import random
import argparse
import json
import os
import platform
import ctypes
import requests
import ipaddress
from datetime import datetime
from colorama import init, Fore, Back, Style

# Initialize colorama for Windows support
init()

class NetworkConfigurator:
    def __init__(self, os_type):
        self.os_type = os_type

    def get_interface_info(self, interface):
        """Get detailed information about a network interface."""
        try:
            if self.os_type == 'windows':
                # Get IP configuration
                output = subprocess.check_output(['ipconfig', '/all']).decode()
                interface_section = None
                for section in output.split('\n\n'):
                    if interface in section:
                        interface_section = section
                        break
                if interface_section:
                    return self._parse_windows_interface_info(interface_section)
            else:
                # Use ip addr show for Linux
                output = subprocess.check_output(['ip', 'addr', 'show', interface]).decode()
                return self._parse_linux_interface_info(output)
        except subprocess.CalledProcessError:
            return None

    def _parse_windows_interface_info(self, info):
        """Parse Windows ipconfig output."""
        result = {
            'ip_address': None,
            'netmask': None,
            'broadcast': None,
            'mtu': None,
            'ipv6_addresses': [],
            'status': None
        }
        
        for line in info.split('\n'):
            if 'IPv4 Address' in line:
                result['ip_address'] = re.search(r'\d+\.\d+\.\d+\.\d+', line).group()
            elif 'Subnet Mask' in line:
                result['netmask'] = re.search(r'\d+\.\d+\.\d+\.\d+', line).group()
            elif 'IPv6 Address' in line:
                ipv6 = re.search(r'([0-9a-fA-F:]+)', line)
                if ipv6:
                    result['ipv6_addresses'].append(ipv6.group(1))
        
        return result

    def _parse_linux_interface_info(self, info):
        """Parse Linux ip addr output."""
        result = {
            'ip_address': None,
            'netmask': None,
            'broadcast': None,
            'mtu': None,
            'ipv6_addresses': [],
            'status': None,
            'stats': {
                'rx_packets': 0,
                'rx_bytes': 0,
                'tx_packets': 0,
                'tx_bytes': 0
            }
        }
        
        # Extract MTU
        mtu_match = re.search(r'mtu (\d+)', info)
        if mtu_match:
            result['mtu'] = int(mtu_match.group(1))
        
        # Extract IPv4 information
        ipv4_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', info)
        if ipv4_match:
            result['ip_address'] = ipv4_match.group(1)
            # Convert CIDR to netmask
            result['netmask'] = str(ipaddress.IPv4Network(f'0.0.0.0/{ipv4_match.group(2)}', strict=False).netmask)
        
        # Extract IPv6 information
        for ipv6_match in re.finditer(r'inet6 ([0-9a-fA-F:]+)/(\d+)', info):
            result['ipv6_addresses'].append(f"{ipv6_match.group(1)}/{ipv6_match.group(2)}")
        
        # Extract interface status
        if 'UP' in info:
            result['status'] = 'UP'
        elif 'DOWN' in info:
            result['status'] = 'DOWN'
        
        # Get statistics using ip -s link
        try:
            stats_output = subprocess.check_output(['ip', '-s', 'link', 'show', interface]).decode()
            rx_match = re.search(r'RX:\s+bytes\s+packets\s+errors.*\n\s+(\d+)\s+(\d+)\s+(\d+)', stats_output)
            tx_match = re.search(r'TX:\s+bytes\s+packets\s+errors.*\n\s+(\d+)\s+(\d+)\s+(\d+)', stats_output)
            
            if rx_match:
                result['stats']['rx_bytes'] = int(rx_match.group(1))
                result['stats']['rx_packets'] = int(rx_match.group(2))
            if tx_match:
                result['stats']['tx_bytes'] = int(tx_match.group(1))
                result['stats']['tx_packets'] = int(tx_match.group(2))
        except:
            pass
        
        return result

    def set_ip_address(self, interface, ip_address, netmask=None, gateway=None):
        """Set IP address for an interface."""
        try:
            if not self._validate_ip_address(ip_address):
                return False, "Invalid IP address format"
            
            if self.os_type == 'windows':
                # Windows IP configuration
                cmd = ['netsh', 'interface', 'ip', 'set', 'address', 
                      interface, 'static', ip_address]
                if netmask:
                    cmd.append(netmask)
                if gateway:
                    cmd.append(gateway)
            else:
                # Linux IP configuration
                if netmask:
                    # Convert netmask to CIDR notation
                    cidr = self._netmask_to_cidr(netmask)
                    ip_with_cidr = f"{ip_address}/{cidr}"
                else:
                    ip_with_cidr = f"{ip_address}/24"  # Default to /24 if no netmask
                
                cmd = ['ip', 'addr', 'add', ip_with_cidr, 'dev', interface]
            
            subprocess.check_output(cmd)
            return True, "IP address set successfully"
        except subprocess.CalledProcessError as e:
            return False, f"Error setting IP address: {str(e)}"

    def set_mtu(self, interface, mtu):
        """Set MTU for an interface."""
        try:
            if not isinstance(mtu, int) or mtu < 68 or mtu > 65535:
                return False, "Invalid MTU value (must be between 68 and 65535)"
            
            if self.os_type == 'windows':
                cmd = ['netsh', 'interface', 'ipv4', 'set', 'subinterface', 
                      interface, f'mtu={mtu}', 'store=persistent']
            else:
                cmd = ['ip', 'link', 'set', interface, 'mtu', str(mtu)]
            
            subprocess.check_output(cmd)
            return True, "MTU set successfully"
        except subprocess.CalledProcessError as e:
            return False, f"Error setting MTU: {str(e)}"

    def _validate_ip_address(self, ip):
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _netmask_to_cidr(self, netmask):
        """Convert subnet mask to CIDR notation."""
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

class MACChanger:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mac_history.json')
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        self.network_config = NetworkConfigurator(self.os_type)
        self.load_config()
        print(f"{Fore.CYAN}╔══════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║      Network Configuration Tool      ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════╝{Style.RESET_ALL}")

    def load_config(self):
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                'favorite_macs': {},
                'excluded_vendors': []
            }
            self.save_config()

    def save_config(self):
        """Save configuration to file."""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def _get_random_mac(self):
        """Generate a random MAC address."""
        first = random.randint(0, 15) * 2 + 2
        mac = [first] + [random.randint(0, 255) for _ in range(5)]
        return ':'.join([f"{b:02x}" for b in mac])

    def _validate_mac(self, mac_address):
        """Validate MAC address format."""
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac_address))

    def _get_adapter_registry_path(self, interface):
        """Get the registry path for a network adapter on Windows."""
        try:
            # Get network adapters from registry
            cmd = 'reg query "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" /s /v "NetCfgInstanceId"'
            output = subprocess.check_output(cmd, shell=True).decode()
            
            # Get adapter information using netsh
            netsh_cmd = 'netsh interface show interface'
            netsh_output = subprocess.check_output(netsh_cmd, shell=True).decode()
            
            # Parse registry output
            paths = []
            current_path = None
            for line in output.split('\n'):
                if 'HKEY_LOCAL_MACHINE' in line:
                    current_path = line.strip()
                elif 'NetCfgInstanceId' in line and current_path:
                    guid = line.split()[-1]
                    paths.append((current_path, guid))
            
            # Match interface name with registry path
            for path, guid in paths:
                # Check if this adapter matches our interface
                if interface.lower() in netsh_output.lower() and guid in netsh_output:
                    return path
                    
            return None
        except subprocess.CalledProcessError:
            return None

    def _get_current_mac(self, interface):
        """Get the current MAC address of the interface."""
        try:
            if self.os_type == 'windows':
                output = subprocess.check_output(['getmac', '/v', '/fo', 'csv']).decode()
                for line in output.split('\n'):
                    if interface.lower() in line.lower():
                        mac = re.search(r'([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})', line)
                        return mac.group(0).replace('-', ':') if mac else None
            else:
                output = subprocess.check_output(['ip', 'link', 'show', interface]).decode()
                current_mac = re.search(r'ether\s+([0-9a-fA-F:]{17})', output)
                return current_mac.group(1) if current_mac else None
        except subprocess.CalledProcessError:
            return None

    def _list_interfaces(self):
        """List all network interfaces."""
        try:
            if self.os_type == 'windows':
                output = subprocess.check_output(['netsh', 'interface', 'show', 'interface']).decode()
                interfaces = []
                for line in output.split('\n')[3:]:  # Skip header lines
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            interfaces.append(parts[-1])
            else:
                output = subprocess.check_output(['ip', 'link', 'show']).decode()
                interfaces = re.findall(r'\d+:\s(\w+):', output)
            
            print(f"\n{Fore.GREEN}Available network interfaces:{Style.RESET_ALL}")
            for i, interface in enumerate(interfaces, 1):
                print(f"{Fore.YELLOW}{i}. {interface}{Style.RESET_ALL}")
            return interfaces
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error listing interfaces: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def _is_admin(self):
        """Check if the script is running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() if self.os_type == 'windows' else os.geteuid() == 0
        except:
            return False

    def _log_mac_change(self, interface, old_mac, new_mac):
        """Log MAC address changes to history file."""
        history = []
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                history = json.load(f)
        
        history.append({
            'interface': interface,
            'old_mac': old_mac,
            'new_mac': new_mac,
            'timestamp': datetime.now().isoformat(),
            'os': self.os_type
        })
        
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=4)

    def lookup_vendor(self, mac_address):
        """Look up the vendor of a MAC address."""
        try:
            oui = mac_address.replace(':', '')[:6]
            response = requests.get(f'https://api.macvendors.com/{oui}')
            if response.status_code == 200:
                return response.text
            return "Unknown vendor"
        except:
            return "Vendor lookup failed"

    def change_mac(self, interface, new_mac):
        """Change MAC address of the specified interface."""
        if not self._is_admin():
            print(f"{Fore.RED}This operation requires administrator privileges!{Style.RESET_ALL}")
            sys.exit(1)

        try:
            print(f"\n{Fore.CYAN}Changing MAC address for {interface}...{Style.RESET_ALL}")
            old_mac = self._get_current_mac(interface)
            
            if self.os_type == 'windows':
                # Get registry path for the adapter
                registry_path = self._get_adapter_registry_path(interface)
                if not registry_path:
                    print(f"{Fore.RED}Could not find registry path for interface {interface}{Style.RESET_ALL}")
                    return

                # Disable network adapter
                subprocess.check_output(['netsh', 'interface', 'set', 'interface', interface, 'admin=disable'])
                
                # Change MAC in registry
                mac_value = new_mac.replace(':', '')
                reg_cmd = f'reg add "{registry_path}" /v NetworkAddress /t REG_SZ /d "{mac_value}" /f'
                subprocess.check_output(reg_cmd, shell=True)
                
                # Enable network adapter
                subprocess.check_output(['netsh', 'interface', 'set', 'interface', interface, 'admin=enable'])
            else:
                subprocess.check_output(['ip', 'link', 'set', 'dev', interface, 'down'])
                subprocess.check_output(['ip', 'link', 'set', 'dev', interface, 'address', new_mac])
                subprocess.check_output(['ip', 'link', 'set', 'dev', interface, 'up'])
            
            # Wait for interface to come back up
            print(f"{Fore.YELLOW}Waiting for interface to initialize...{Style.RESET_ALL}")
            import time
            time.sleep(5)
            
            # Verify the change
            current_mac = self._get_current_mac(interface)
            if current_mac and current_mac.lower() == new_mac.lower():
                print(f"{Fore.GREEN}Success! MAC address changed to: {current_mac}{Style.RESET_ALL}")
                vendor = self.lookup_vendor(current_mac)
                print(f"{Fore.CYAN}Vendor: {vendor}{Style.RESET_ALL}")
                self._log_mac_change(interface, old_mac, new_mac)
            else:
                print(f"{Fore.RED}Failed to change MAC address{Style.RESET_ALL}")
                if current_mac:
                    print(f"{Fore.YELLOW}Current MAC: {current_mac}{Style.RESET_ALL}")
                
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error changing MAC address: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def show_history(self):
        """Display MAC address change history."""
        if not os.path.exists(self.history_file):
            print(f"{Fore.YELLOW}No MAC address change history found.{Style.RESET_ALL}")
            return
        
        with open(self.history_file, 'r') as f:
            history = json.load(f)
        
        print(f"\n{Fore.CYAN}MAC Address Change History:{Style.RESET_ALL}")
        for entry in history:
            print(f"\n{Fore.GREEN}Timestamp: {entry['timestamp']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Interface: {entry['interface']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Old MAC: {entry['old_mac']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}New MAC: {entry['new_mac']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}OS: {entry['os']}{Style.RESET_ALL}")

    def show_interface_details(self, interface):
        """Display detailed information about a network interface."""
        info = self.network_config.get_interface_info(interface)
        if info:
            print(f"\n{Fore.CYAN}Interface Details for {interface}:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Status: {info['status']}{Style.RESET_ALL}")
            if info['ip_address']:
                print(f"{Fore.YELLOW}IPv4 Address: {info['ip_address']}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Netmask: {info['netmask']}{Style.RESET_ALL}")
            if info['ipv6_addresses']:
                print(f"{Fore.YELLOW}IPv6 Addresses:{Style.RESET_ALL}")
                for ipv6 in info['ipv6_addresses']:
                    print(f"  {ipv6}")
            if info['mtu']:
                print(f"{Fore.YELLOW}MTU: {info['mtu']}{Style.RESET_ALL}")
            
            if 'stats' in info:
                print(f"\n{Fore.CYAN}Interface Statistics:{Style.RESET_ALL}")
                print(f"{Fore.GREEN}RX Packets: {info['stats']['rx_packets']}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}RX Bytes: {info['stats']['rx_bytes']:,} bytes{Style.RESET_ALL}")
                print(f"{Fore.GREEN}TX Packets: {info['stats']['tx_packets']}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}TX Bytes: {info['stats']['tx_bytes']:,} bytes{Style.RESET_ALL}")

    def configure_interface(self, interface):
        """Configure network interface settings."""
        while True:
            print(f"\n{Fore.YELLOW}Network Configuration Options:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1. Change MAC Address{Style.RESET_ALL}")
            print(f"{Fore.CYAN}2. Set IP Address{Style.RESET_ALL}")
            print(f"{Fore.CYAN}3. Set MTU{Style.RESET_ALL}")
            print(f"{Fore.CYAN}4. Show Interface Details{Style.RESET_ALL}")
            print(f"{Fore.CYAN}5. Back to Main Menu{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.GREEN}Enter your choice (1-5): {Style.RESET_ALL}").strip()
            
            if choice == "1":
                self._handle_mac_change(interface)
            elif choice == "2":
                self._handle_ip_change(interface)
            elif choice == "3":
                self._handle_mtu_change(interface)
            elif choice == "4":
                self.show_interface_details(interface)
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

    def _handle_ip_change(self, interface):
        """Handle IP address configuration."""
        print(f"\n{Fore.CYAN}Current Configuration:{Style.RESET_ALL}")
        self.show_interface_details(interface)
        
        ip = input(f"\n{Fore.YELLOW}Enter new IP address: {Style.RESET_ALL}").strip()
        netmask = input(f"{Fore.YELLOW}Enter netmask (press Enter for default 255.255.255.0): {Style.RESET_ALL}").strip()
        if not netmask:
            netmask = "255.255.255.0"
        
        success, message = self.network_config.set_ip_address(interface, ip, netmask)
        if success:
            print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}{message}{Style.RESET_ALL}")

    def _handle_mtu_change(self, interface):
        """Handle MTU configuration."""
        print(f"\n{Fore.CYAN}Current Configuration:{Style.RESET_ALL}")
        self.show_interface_details(interface)
        
        try:
            mtu = int(input(f"\n{Fore.YELLOW}Enter new MTU value (68-65535): {Style.RESET_ALL}"))
            success, message = self.network_config.set_mtu(interface, mtu)
            if success:
                print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}{message}{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid MTU value{Style.RESET_ALL}")

    def _handle_mac_change(self, interface):
        """Handle MAC address change."""
        current_mac = self._get_current_mac(interface)
        if current_mac:
            print(f"\n{Fore.GREEN}Current MAC address: {current_mac}{Style.RESET_ALL}")
            vendor = self.lookup_vendor(current_mac)
            print(f"{Fore.CYAN}Current vendor: {vendor}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Choose an option:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. Enter specific MAC address{Style.RESET_ALL}")
        print(f"{Fore.CYAN}2. Generate random MAC address{Style.RESET_ALL}")
        choice = input(f"\n{Fore.GREEN}Enter your choice (1-2): {Style.RESET_ALL}").strip()

        if choice == "1":
            while True:
                new_mac = input(f"{Fore.CYAN}Enter new MAC address (format xx:xx:xx:xx:xx:xx): {Style.RESET_ALL}").strip()
                if self._validate_mac(new_mac):
                    break
                print(f"{Fore.RED}Invalid MAC address format. Please try again.{Style.RESET_ALL}")
        elif choice == "2":
            new_mac = self._get_random_mac()
            print(f"{Fore.GREEN}Generated random MAC address: {new_mac}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
            return

        confirm = input(f"\n{Fore.YELLOW}Do you want to change the MAC address of {interface} to {new_mac}? (y/n): {Style.RESET_ALL}").strip().lower()
        if confirm == 'y':
            self.change_mac(interface, new_mac)

    def run(self, args=None):
        """Run the Network Configuration Tool."""
        if not self._is_admin():
            print(f"{Fore.RED}Please run this script with administrator privileges!{Style.RESET_ALL}")
            sys.exit(1)

        if args:
            if args.show_history:
                self.show_history()
                return
            
            if args.interface and args.mac:
                if not self._validate_mac(args.mac):
                    print(f"{Fore.RED}Invalid MAC address format{Style.RESET_ALL}")
                    return
                self.change_mac(args.interface, args.mac)
                return
        
        # Interactive mode
        while True:
            interfaces = self._list_interfaces()
            
            print(f"\n{Fore.YELLOW}Choose an option:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1. Configure Interface{Style.RESET_ALL}")
            print(f"{Fore.CYAN}2. Show MAC Address History{Style.RESET_ALL}")
            print(f"{Fore.CYAN}3. Exit{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.GREEN}Enter your choice (1-3): {Style.RESET_ALL}").strip()
            
            if choice == "1":
                while True:
                    interface = input(f"\n{Fore.CYAN}Enter the interface name (e.g., 'Wi-Fi' or Ethernet): {Style.RESET_ALL}").strip()
                    if interface in interfaces:
                        self.configure_interface(interface)
                        break
                    print(f"{Fore.RED}Invalid interface. Please choose from the available interfaces.{Style.RESET_ALL}")
            elif choice == "2":
                self.show_history()
            elif choice == "3":
                print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Network Configuration Tool')
    parser.add_argument('-i', '--interface', help='Network interface to modify')
    parser.add_argument('-m', '--mac', help='New MAC address')
    parser.add_argument('--show-history', action='store_true', help='Show MAC address change history')
    
    args = parser.parse_args()
    
    try:
        mac_changer = MACChanger()
        mac_changer.run(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
