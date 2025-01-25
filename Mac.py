#!/usr/bin/env python3

import subprocess
import re
import sys
import random
import argparse
import json
import os
import time
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
                output = subprocess.check_output(['ipconfig', '/all']).decode()
                interface_section = None
                for section in output.split('\n\n'):
                    if interface in section:
                        interface_section = section
                        break
                if interface_section:
                    return self._parse_windows_interface_info(interface_section)
            else:
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

    def randomize_all(self, interface):
        """Randomize all interface settings."""
        try:
            # First bring down the interface
            if self.os_type == 'windows':
                subprocess.check_output(['netsh', 'interface', 'set', 'interface', interface, 'admin=disable'])
            else:
                subprocess.check_output(['ip', 'link', 'set', 'dev', interface, 'down'])

            # Generate random settings
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            netmask = "255.255.255.0"
            mtu = random.randint(1200, 1500)  # Safe MTU range

            try:
                if self.os_type == 'windows':
                    # Set IP and netmask
                    subprocess.check_output(['netsh', 'interface', 'ip', 'set', 'address', 
                                          'name=' + interface, 'static', ip, netmask], stderr=subprocess.PIPE)
                    # Set MTU
                    subprocess.check_output(['netsh', 'interface', 'ipv4', 'set', 'subinterface', 
                                          interface, f'mtu={mtu}', 'store=persistent'], stderr=subprocess.PIPE)
                else:
                    # Set IP and netmask
                    subprocess.check_output(['ip', 'addr', 'flush', 'dev', interface], stderr=subprocess.PIPE)
                    subprocess.check_output(['ip', 'addr', 'add', f"{ip}/24", 'dev', interface], stderr=subprocess.PIPE)
                    # Set MTU
                    subprocess.check_output(['ip', 'link', 'set', interface, 'mtu', str(mtu)], stderr=subprocess.PIPE)

            except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}Error configuring network settings: {e.stderr.decode() if e.stderr else str(e)}{Style.RESET_ALL}")
                return False, "Failed to configure network settings"

            # Bring the interface back up
            if self.os_type == 'windows':
                subprocess.check_output(['netsh', 'interface', 'set', 'interface', interface, 'admin=enable'])
            else:
                subprocess.check_output(['ip', 'link', 'set', 'dev', interface, 'up'])

            # Wait for interface to stabilize
            print(f"{Fore.YELLOW}Waiting for interface to stabilize...{Style.RESET_ALL}")
            import time
            time.sleep(5)

            return True, f"IP: {ip}, Netmask: {netmask}, MTU: {mtu}"
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode() if hasattr(e, 'stderr') and e.stderr else str(e)
            print(f"{Fore.RED}Error: {error_msg}{Style.RESET_ALL}")
            return False, str(e)
        except Exception as e:
            print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
            return False, str(e)

class MACChanger:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mac_history.json')
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        self.network_config = NetworkConfigurator(self.os_type)
        self.load_config()
        
        # Print the banner
        banner = r"""  ____ _              _____   _          _      ____            
 / ___| |__   ___  __|_   _| | |   _   _| |____/ ___|  ___  ___ 
| |  _| '_ \ / _ \/ __|| |   | |  | | | | |_  /\___ \ / _ \/ __|
| |_| | | | | (_) \__ \| |   | |__| |_| | |/ /  ___) |  __/ (__ 
 \____|_| |_|\___/|___/|_|   |_____\__,_|_/___||____/ \___|\___|

                                                                 """
        print(f"{Fore.RED}{banner}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╔══════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║          Ghost MAC Tool             ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Coded By Ghost LulzSec{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Telegram: @WW6WW6WW6{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}GitHub: https://github.com/6d69{Style.RESET_ALL}")
        print(f"{Fore.RED}All rights reserved.{Style.RESET_ALL}")

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {'favorite_macs': {}}
            self.save_config()

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def _get_random_mac(self):
        first = random.randint(0, 15) * 2 + 2
        mac = [first] + [random.randint(0, 255) for _ in range(5)]
        return ':'.join([f"{b:02x}" for b in mac])

    def _validate_mac(self, mac_address):
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac_address))

    def _get_current_mac(self, interface):
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

    def _get_permanent_mac(self, interface):
        """Get the permanent/burned-in MAC address."""
        try:
            if self.os_type == 'windows':
                output = subprocess.check_output(['getmac', '/v', '/fo', 'csv']).decode()
                for line in output.split('\n'):
                    if interface.lower() in line.lower():
                        # Look for the transport name which often contains the permanent MAC
                        transport = line.split(',')[-1].strip('"')
                        if transport:
                            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', transport)
                            if mac_match:
                                return mac_match.group(0)
            else:
                # Try ethtool first
                try:
                    output = subprocess.check_output(['ethtool', '-P', interface]).decode()
                    mac_match = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', output)
                    if mac_match:
                        return mac_match.group(0)
                except:
                    pass
                
                # Try reading from sysfs as fallback
                try:
                    with open(f'/sys/class/net/{interface}/address', 'r') as f:
                        return f.read().strip()
                except:
                    pass
        except:
            pass
        return None

    def _list_interfaces(self):
        try:
            if self.os_type == 'windows':
                output = subprocess.check_output(['netsh', 'interface', 'show', 'interface']).decode()
                interfaces = []
                for line in output.split('\n')[3:]:
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

    def show_interface_details(self, interface):
        """Display detailed information about a network interface."""
        info = self.network_config.get_interface_info(interface)
        if info:
            print(f"\n{Fore.CYAN}Interface Details for {interface}:{Style.RESET_ALL}")
            mac = self._get_current_mac(interface)
            if mac:
                print(f"{Fore.GREEN}MAC Address: {mac}{Style.RESET_ALL}")
                vendor = self.lookup_vendor(mac)
                print(f"{Fore.GREEN}Vendor: {vendor}{Style.RESET_ALL}")
                
                # Add permanent MAC display if available
                perm_mac = self._get_permanent_mac(interface)
                if perm_mac and perm_mac.lower() != mac.lower():
                    print(f"{Fore.YELLOW}Permanent MAC: {perm_mac}{Style.RESET_ALL}")
                    perm_vendor = self.lookup_vendor(perm_mac)
                    print(f"{Fore.YELLOW}Permanent Vendor: {perm_vendor}{Style.RESET_ALL}")
            
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
                print(f"{Fore.GREEN}RX Packets: {info['stats']['rx_packets']:,}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}RX Bytes: {info['stats']['rx_bytes']:,} bytes{Style.RESET_ALL}")
                print(f"{Fore.GREEN}TX Packets: {info['stats']['tx_packets']:,}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}TX Bytes: {info['stats']['tx_bytes']:,} bytes{Style.RESET_ALL}")

    def _is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() if self.os_type == 'windows' else os.geteuid() == 0
        except:
            return False

    def change_mac(self, interface, new_mac):
        """Change MAC address of the specified interface."""
        if not self._is_admin():
            print(f"{Fore.RED}This operation requires administrator privileges!{Style.RESET_ALL}")
            return False

        try:
            print(f"\n{Fore.CYAN}Changing MAC address for {interface}...{Style.RESET_ALL}")
            old_mac = self._get_current_mac(interface)

            # Check if running in a VM
            is_vm = self._check_if_vm()
            if is_vm:
                print(f"{Fore.YELLOW}Virtual Machine detected. Some network adapters may not allow MAC address changes.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}You may need to change the MAC address in your VM settings instead.{Style.RESET_ALL}")

            # First bring down the interface
            if self.os_type == 'windows':
                try:
                    # Stop the network adapter service
                    subprocess.check_output(['net', 'stop', 'netadapter', '/y'], stderr=subprocess.PIPE, shell=True)
                    
                    # Disable the adapter
                    subprocess.check_output(['netsh', 'interface', 'set', 'interface', interface, 'admin=disable'], stderr=subprocess.PIPE)
                    
                    # Try multiple registry paths for VM adapters
                    registry_paths = [
                        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
                        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Network"
                    ]
                    
                    success = False
                    for base_path in registry_paths:
                        try:
                            # Search for the network adapter in registry
                            cmd = f'reg query "{base_path}" /s /f "{interface}" /d'
                            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE).decode()
                            
                            # Find the correct subkey
                            for line in output.split('\n'):
                                if interface.lower() in line.lower():
                                    subkey = line.strip()
                                    if "HKEY_LOCAL_MACHINE" in subkey:
                                        # Try to set the MAC address
                                        mac_cmd = f'reg add "{subkey}" /v NetworkAddress /t REG_SZ /d {new_mac.replace(":", "")} /f'
                                        subprocess.check_output(mac_cmd, shell=True, stderr=subprocess.PIPE)
                                        success = True
                                        break
                            
                            if success:
                                break
                                
                        except subprocess.CalledProcessError:
                            continue
                    
                    if not success:
                        print(f"{Fore.RED}Could not find network adapter in registry{Style.RESET_ALL}")
                        return False
                    
                    # Start the network adapter service
                    subprocess.check_output(['net', 'start', 'netadapter'], stderr=subprocess.PIPE, shell=True)
                    
                    # Enable the adapter
                    subprocess.check_output(['netsh', 'interface', 'set', 'interface', interface, 'admin=enable'], stderr=subprocess.PIPE)
                    
                except subprocess.CalledProcessError as e:
                    error_msg = e.stderr.decode() if e.stderr else str(e)
                    print(f"{Fore.RED}Error changing MAC address: {error_msg}{Style.RESET_ALL}")
                    return False
            else:
                try:
                    # For Linux, try multiple methods
                    methods = [
                        ['ip', 'link', 'set', 'dev', interface, 'down'],
                        ['ifconfig', interface, 'down'],
                    ]
                    
                    # Try each method to bring down the interface
                    for method in methods:
                        try:
                            subprocess.check_output(method, stderr=subprocess.PIPE)
                            break
                        except:
                            continue
                    
                    # Try to change MAC using ip command first
                    try:
                        subprocess.check_output(['ip', 'link', 'set', 'dev', interface, 'address', new_mac], stderr=subprocess.PIPE)
                    except:
                        # If ip command fails, try macchanger
                        try:
                            subprocess.check_output(['macchanger', '--mac', new_mac, interface], stderr=subprocess.PIPE)
                        except:
                            print(f"{Fore.RED}Failed to change MAC address. Try installing macchanger: sudo apt-get install macchanger{Style.RESET_ALL}")
                            return False
                    
                    # Try each method to bring up the interface
                    for method in [['ip', 'link', 'set', 'dev', interface, 'up'], ['ifconfig', interface, 'up']]:
                        try:
                            subprocess.check_output(method, stderr=subprocess.PIPE)
                            break
                        except:
                            continue
                            
                except subprocess.CalledProcessError as e:
                    error_msg = e.stderr.decode() if e.stderr else str(e)
                    print(f"{Fore.RED}Error changing MAC address: {error_msg}{Style.RESET_ALL}")
                    return False
            
            print(f"{Fore.YELLOW}Waiting for interface to initialize...{Style.RESET_ALL}")
            time.sleep(5)
            
            # Verify the change
            current_mac = self._get_current_mac(interface)
            if current_mac and current_mac.lower() == new_mac.lower():
                print(f"{Fore.GREEN}Success! MAC address changed to: {current_mac}{Style.RESET_ALL}")
                vendor = self.lookup_vendor(current_mac)
                print(f"{Fore.CYAN}Vendor: {vendor}{Style.RESET_ALL}")
                return True
            else:
                if is_vm:
                    print(f"{Fore.RED}Failed to change MAC address. For virtual machines, try:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}1. Power off the VM{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}2. Change MAC address in VM settings{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}3. Power on the VM{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Failed to change MAC address{Style.RESET_ALL}")
                if current_mac:
                    print(f"{Fore.YELLOW}Current MAC: {current_mac}{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
            return False

    def _check_if_vm(self):
        """Check if running in a virtual machine."""
        try:
            if self.os_type == 'windows':
                # Check Windows system information
                output = subprocess.check_output('systeminfo', shell=True).decode().lower()
                vm_indicators = ['vmware', 'virtual', 'vbox', 'hyperv']
                return any(indicator in output for indicator in vm_indicators)
            else:
                # Check Linux system information
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read().lower()
                vm_indicators = ['vmware', 'virtualbox', 'kvm', 'qemu']
                return any(indicator in cpuinfo for indicator in vm_indicators)
        except:
            return False

    def lookup_vendor(self, mac_address):
        try:
            oui = mac_address.replace(':', '')[:6]
            response = requests.get(f'https://api.macvendors.com/{oui}')
            if response.status_code == 200:
                return response.text
            return "Unknown vendor"
        except:
            return "Vendor lookup failed"

    def run(self):
        """Run the Network Configuration Tool."""
        if not self._is_admin():
            print(f"{Fore.RED}Please run this script with administrator privileges!{Style.RESET_ALL}")
            sys.exit(1)

        while True:
            try:
                interfaces = self._list_interfaces()
                if not interfaces:
                    print(f"{Fore.RED}No network interfaces found!{Style.RESET_ALL}")
                    sys.exit(1)
                
                print(f"\n{Fore.YELLOW}Choose an option:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}1. Show Interface Details{Style.RESET_ALL}")
                print(f"{Fore.CYAN}2. Change MAC Address{Style.RESET_ALL}")
                print(f"{Fore.CYAN}3. Exit{Style.RESET_ALL}")
                
                try:
                    choice = input(f"\n{Fore.GREEN}Enter your choice (1-3): {Style.RESET_ALL}").strip()
                    if choice not in ['1', '2', '3']:
                        print(f"{Fore.RED}Invalid choice. Please enter a number between 1 and 3.{Style.RESET_ALL}")
                        continue
                    
                    if choice == '3':
                        print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                        break
                    
                    # Show available interfaces with numbers
                    print(f"\n{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
                    for idx, iface in enumerate(interfaces, 1):
                        mac = self._get_current_mac(iface) or "Unknown MAC"
                        print(f"{Fore.YELLOW}{idx}. {iface} - {mac}{Style.RESET_ALL}")
                    
                    # Allow selection by number or name
                    iface_input = input(f"\n{Fore.CYAN}Enter interface number or name: {Style.RESET_ALL}").strip()
                    try:
                        idx = int(iface_input)
                        if 1 <= idx <= len(interfaces):
                            interface = interfaces[idx-1]
                        else:
                            print(f"{Fore.RED}Invalid interface number{Style.RESET_ALL}")
                            continue
                    except ValueError:
                        interface = iface_input
                        if interface not in interfaces:
                            print(f"{Fore.RED}Invalid interface. Available interfaces: {', '.join(interfaces)}{Style.RESET_ALL}")
                            continue

                    if choice == '1':
                        self.show_interface_details(interface)
                    elif choice == '2':
                        print(f"\n{Fore.YELLOW}MAC Address Options:{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}1. Enter specific MAC address{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}2. Generate random MAC address{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}3. Back to main menu{Style.RESET_ALL}")
                        
                        mac_choice = input(f"\n{Fore.GREEN}Enter your choice (1-3): {Style.RESET_ALL}").strip()
                        
                        if mac_choice == '1':
                            while True:
                                new_mac = input(f"{Fore.CYAN}Enter MAC address (format: xx:xx:xx:xx:xx:xx): {Style.RESET_ALL}").strip()
                                if self._validate_mac(new_mac):
                                    break
                                print(f"{Fore.RED}Invalid MAC address format. Please use format xx:xx:xx:xx:xx:xx{Style.RESET_ALL}")
                        elif mac_choice == '2':
                            new_mac = self._get_random_mac()
                            print(f"{Fore.GREEN}Generated random MAC address: {new_mac}{Style.RESET_ALL}")
                        elif mac_choice == '3':
                            continue
                        else:
                            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
                            continue
                        
                        if mac_choice in ['1', '2']:
                            # Show current MAC before changing
                            current_mac = self._get_current_mac(interface)
                            if current_mac:
                                print(f"\n{Fore.YELLOW}Current MAC: {current_mac}{Style.RESET_ALL}")
                            
                            confirm = input(f"{Fore.YELLOW}Do you want to change to {new_mac}? (y/n): {Style.RESET_ALL}").strip().lower()
                            if confirm == 'y':
                                self.change_mac(interface, new_mac)
                
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
                    continue
                except ValueError as e:
                    print(f"{Fore.RED}Invalid input: {str(e)}{Style.RESET_ALL}")
                    continue
                
            except Exception as e:
                print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)

def main():
    try:
        mac_changer = MACChanger()
        mac_changer.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)

if __name__ == "__main__":
    main()
