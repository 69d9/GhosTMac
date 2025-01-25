# GhosTMac

A sophisticated and powerful Python-based MAC address and network interface manipulation tool. GhosTMac provides advanced features for network administrators and security professionals to manage and modify network interface configurations on both Windows and Linux systems.

## Key Features

- **Cross-Platform Support**: Full compatibility with both Windows and Linux systems
- **Interactive CLI Interface**: User-friendly command-line interface with colored output
- **Advanced MAC Operations**:
  - Change MAC address to custom values
  - Generate random MAC addresses
  - View current and permanent MAC addresses
  - Automatic vendor lookup for MAC addresses
- **Network Interface Management**:
  - List all available network interfaces
  - Show detailed interface information
  - Display interface statistics (RX/TX packets and bytes)
  - View IPv4 and IPv6 configurations
  - MTU configuration support
- **Smart System Detection**:
  - Automatic VM environment detection
  - OS-specific optimization
  - Administrator privileges verification
- **Enhanced Security Features**:
  - Input validation for MAC addresses
  - Safe interface handling
  - Proper error handling and recovery
- **Network Configuration**:
  - Interface up/down management
  - IP address configuration
  - Netmask management
  - MTU customization

## Requirements

- Python 3.x
- Administrator/Root privileges
- Required Python packages:
  ```
  colorama
  requests
  ipaddress
  ```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/6d69/GhosTMac.git
   cd GhosTMac
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Tool

```bash
# On Windows (Run as Administrator):
python Mac.py

# On Linux:
sudo python3 Mac.py
```

### Main Menu Options

1. **Show Interface Details**
   - View comprehensive interface information
   - Display current and permanent MAC addresses
   - Show vendor information
   - View IP configurations and statistics

2. **Change MAC Address**
   - Enter a specific MAC address
   - Generate a random MAC address
   - Automatic vendor verification

3. **Exit**
   - Safely exit the program

## Special Features

### Virtual Machine Detection
- Automatically detects if running in a VM environment
- Provides specific guidance for VM network adapters
- Handles VM-specific registry paths on Windows

### Vendor Lookup
- Automatic MAC address vendor identification
- Uses macvendors.com API
- Displays vendor information for both current and permanent MACs

### Network Statistics
- RX/TX packet counting
- Bandwidth usage statistics
- Interface status monitoring

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure you're running with administrator/root privileges

2. **MAC Change Failed**
   - For VMs: Change MAC in VM settings
   - Verify interface supports MAC changes
   - Check for hardware limitations

3. **Interface Not Found**
   - Verify interface name
   - Check if interface is enabled
   - Ensure proper drivers are installed

## Author

- **Developer**: Ghost LulzSec
- **Contact**: @WW6WW6WW6 (Telegram)
- **GitHub**: [https://github.com/6d69](https://github.com/6d69)

## License

All rights reserved. Ghost LulzSec

## Disclaimer

This tool is intended for legitimate network administration and security testing purposes only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.
