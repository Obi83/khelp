#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Logging function with log levels and log rotation
log() {
    local level="$1"
    local message="$2"
    local mspoo_log_file="/var/log/khelp_mspoo.log"

    # Rotate log file if it exceeds 1MB
    if [ -f "$mspoo_log_file" ] && [ $(stat -c%s "$mspoo_log_file") -gt 1048576 ]; then
        mv "$mspoo_log_file" "$mspoo_log_file.$(date +'%Y%m%d%H%M%S')"
    fi

    echo "$(date +'%Y-%m-%d %H:%M:%S') [$level] - $message" | tee -a "$mspoo_log_file"
}

# Example usage of the log function
log "INFO" "This is an informational message."
log "ERROR" "This is an error message."
log "WARNING" "This is a warning message."

# Environment variables for paths and configurations
export mspoo_log_file="/var/log/khelp_mspoo.log"

# Debugging: Print environment variables
log "INFO" "mspoo_log_file=$mspoo_log_file"

# Check if required commands are available
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log "ERROR" "Required command '$cmd' not found. Please install it and try again."
        exit 1
    fi
}

# Disable internet connectivity check for troubleshooting
#check_internet() {
#    if ! ping -c 1 8.8.8.8 &> /dev/null; then
#        log "ERROR" "No internet connectivity. Please check your network connection."
#        exit 1
#    fi
#}

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

# Wait for network interfaces to be fully ready
sleep 3  # Adjusted sleep duration for troubleshooting

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
log "INFO" "MAC spoofing service created and enabled successfully."

# Documentation
mkdir -p /usr/local/share/khelp_mspoof
cat << 'EOF' > /usr/local/share/khelp_mspoof/README.md
# MAC Spoofer Script 
MSPOO

## Description
This script changes the MAC address of all network interfaces (except loopback) to a randomly generated address.

## Functions
- log(level, message): Logs messages with a specified log level.
- generate_random_mac: Generates a random MAC address.
- validate_mac(mac): Validates the format of a MAC address.
- spoof_mac(interface): Changes the MAC address of a specified network interface.

## Log File
Logs are saved to /var/log/khelp_mspoo.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `ip` command must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the generated MAC address format.
EOF


# Summary and Reboot
log "INFO" ""
log "INFO" "khelp is done! Everything is looking good!"
log "INFO" ""
log "INFO" "It enables MSPOO - Service."

log "INFO" "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log "INFO" "Cancelling the reboot..."
    shutdown -c
else
    log "INFO" "Reboot will proceed in 1 minute."
fi
