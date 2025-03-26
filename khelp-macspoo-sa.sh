#!/bin/bash

# Display a logo
display_logo() {
    cat << "EOF"
 ___   _  __   __  _______  ___      _______ 
|   | | ||  | |  ||       ||   |    |       |
|   |_| ||  |_|  ||    ___||   |    |    _  |
|      _||       ||   |___ |   |    |   |_| |
|     |_ |       ||    ___||   |___ |    ___|
|    _  ||   _   ||   |___ |       ||   |    
|___| |_||__| |__||_______||_______||___|    
  
EOF
}

display_logo

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Logging function with log levels and log rotation
log() {
    local level="$1"
    local message="$2"
    local log_file="/var/log/proxy_script.log"

    # Rotate log file if it exceeds 1MB
    if [ -f "$log_file" ] && [ $(stat -c%s "$log_file") -gt 1048576 ]; then
        mv "$log_file" "$log_file.$(date +'%Y%m%d%H%M%S')"
    fi

    echo "$(date +'%Y-%m-%d %H:%M:%S') [$level] - $message" | tee -a "$log_file"
}

# Example usage of the log function
log "INFO" "This is an informational message."
log "ERROR" "This is an error message."
log "WARNING" "This is a warning message."

# Check if required commands are available
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log "ERROR" "Required command '$cmd' not found. Please install it and try again."
        exit 1
    fi
}

# Check for internet connectivity
check_internet() {
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log "ERROR" "No internet connectivity. Please check your network connection."
        exit 1
    fi
}

# Set SSHL as Standanlone 
log "INFO" "Preconfiguring sslh to install as standalone..."
echo "sslh sslh/inetd_or_standalone select standalone" | sudo debconf-set-selections

# Update & full-upgrade system with retry mechanism
update_system() {
    log "INFO" "Updating and upgrading system"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt update && apt full-upgrade -y && apt autoremove -y && apt autoclean; then
            log "INFO" "System update and upgrade completed."
            return 0
        else
            log "ERROR" "System update and upgrade failed. Retrying in $((attempts * 5)) seconds..."
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    log "ERROR" "System update and upgrade failed after $max_attempts attempts. Please check your network connection and try again."
    exit 1
}

# Update the system
update_system

# Documentation
mkdir -p /usr/local/share/system_update
cat << 'EOF' > /usr/local/share/system_update/README.md
# System Update Script

## Description
This script updates and upgrades the system with a retry mechanism in case of failures.

## Functions
- log(level, message): Logs messages with a specified log level.
- update_system: Updates and upgrades the system with a retry mechanism.

## Log File
Logs are saved to /var/log/system_update.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `apt` package manager must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of the update and upgrade process.
EOF

# Install helper packages with retry mechanism
install_packages() {
    log "INFO" "Installing tools and packages."
    local attempts=0
    local max_attempts=3
    local packages="ufw tor curl jq iptables fail2ban sslh kali-linux-large kali-tools-windows-resources terminator bpytop htop shellcheck seclists inxi fastfetch guake impacket-scripts bloodhound powershell-empire"

    while [ $attempts -lt $max_attempts ]; do
        if sudo apt install -y $packages; then
            log "INFO" "Installed all useful helper tools."
            return 0
        else
            log "ERROR" "Package installation failed. Retrying in $((attempts * 5)) seconds..."
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    log "ERROR" "Package installation failed after $max_attempts attempts. Please check your network connection and try again."
    exit 1
}

# Install packages
install_packages

# Documentation
mkdir -p /usr/local/share/package_installer
cat << 'EOF' > /usr/local/share/package_installer/README.md
# Package Installer Script

## Description
This script installs a set of useful helper packages with a retry mechanism in case of failures.

## Functions
- log(level, message): Logs messages with a specified log level.
- install_packages: Installs a set of packages with a retry mechanism.

## Log File
Logs are saved to /var/log/package_installer.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `apt` package manager must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of package installations.
EOF

# Main script execution
check_internet
update_system
install_packages

# Create and enable MAC spoofing service
log "INFO" "Creating and enabling MAC spoofing service..."

# Create the MAC spoofing script
cat << 'EOF' > /usr/local/bin/mspoo.sh
#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Check if 'ip' command is available
if ! command -v ip &> /dev/null; then
    echo "'ip' command not found. Please install it and try again."
    exit 1
fi

# Function to generate a random MAC address
generate_random_mac() {
    echo -n "02"
    for i in {1..5}; do
        printf ":%02x" $((RANDOM % 256))
    done
    echo
}

# Function to validate MAC address format
validate_mac() {
    local mac="$1"
    if [[ ! $mac =~ ^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$ ]]; then
        log "ERROR" "Invalid MAC address format: $mac"
        return 1
    fi
    return 0
}

# Function to spoof MAC address for a given interface
spoof_mac() {
    local interface=$1
    local new_mac=$(generate_random_mac)
    log "INFO" "Spoofing MAC address for interface $interface with new MAC: $new_mac"

    if ! ip link set dev $interface down; then
        log "ERROR" "Failed to bring down the network interface $interface."
        return 1
    fi

    if ! ip link set dev $interface address $new_mac; then
        log "ERROR" "Failed to change the MAC address for $interface."
        return 1
    fi

    if ! ip link set dev $interface up; then
        log "ERROR" "Failed to bring up the network interface $interface."
        return 1
    fi

    ip link show $interface | grep ether
    log "INFO" "MAC address for $interface changed to $new_mac"
    return 0
}

# Get all network interfaces except loopback
interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo)

# Spoof MAC address for each interface
for interface in $interfaces; do
    if spoof_mac $interface; then
        log "INFO" "Successfully spoofed MAC address for $interface"
    else
        log "ERROR" "Failed to spoof MAC address for $interface"
    fi
done
EOF

# Make the script executable
chmod +x /usr/local/bin/mspoo.sh

# Documentation
mkdir -p usr/local/share/mac_spoofer
cat << EOF > /usr/local/share/mac_spoofer/README.md
# MAC Spoofer Script 
MACSPOO

## Description
This script changes the MAC address of all network interfaces (except loopback) to a randomly generated address.

## Functions
- log(level, message): Logs messages with a specified log level.
- generate_random_mac: Generates a random MAC address.
- validate_mac(mac): Validates the format of a MAC address.
- spoof_mac(interface): Changes the MAC address of a specified network interface.

## Log File
Logs are saved to /var/log/mac_spoofer.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `ip` command must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the generated MAC address format.
EOF

# Create the systemd service unit file for MAC spoofing
cat << EOF > /etc/systemd/system/mspoo.service
[Unit]
Description=MSPOO MACSpoofing Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mspoo.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

chmod +x /etc/systemd/system/mspoo.service

systemctl daemon-reload
systemctl enable mspoo.service
systemctl start mspoo.service
log "INFO" "MAC spoofing service created and enabled successfully."

# Log the completion of MAC spoofing service creation and enabling
log "INFO" "MAC spoofing service created and enabled."

# Summary and Reboot
log "INFO" ""
log "INFO" "khelp is done! Everything is looking good!"
log "INFO" ""
log "INFO" "khelp setups a Tor / Proxy Routing by fetching proxies from 10 APIs"
log "INFO" "It also sets up HOGEN and MSPOO Service."
log "INFO" "After reboot it will provide a window with the status of all changes."

display_logo

log "INFO" "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log "INFO" "Cancelling the reboot..."
    shutdown -c
else
    log "INFO" "Reboot will proceed in 1 minute."