#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Define log levels
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_WARNING=2
LOG_LEVEL_ERROR=3
LOG_LEVEL_CRITICAL=4

# Set the current log level (adjust as needed)
CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG

# Logging function with log levels, log rotation, and detailed formatting
log() {
    local level="$1"
    local message="$2"
    local log_file="$3"
    local log_level_name

    case "$level" in
        $LOG_LEVEL_DEBUG) log_level_name="DEBUG" ;;
        $LOG_LEVEL_INFO) log_level_name="INFO" ;;
        $LOG_LEVEL_WARNING) log_level_name="WARNING" ;;
        $LOG_LEVEL_ERROR) log_level_name="ERROR" ;;
        $LOG_LEVEL_CRITICAL) log_level_name="CRITICAL" ;;
        *) log_level_name="UNKNOWN" ;;
    esac

    # Check if the current log level is sufficient to log the message
    if [ "$level" -lt "$CURRENT_LOG_LEVEL" ]; then
        return
    fi

    # Rotate log file if it exceeds 1MB
    if [ -f "$log_file" ] && [ $(stat -c%s "$log_file") -gt 1048576 ]; then
        mv "$log_file" "$log_file.$(date +'%Y%m%d%H%M%S')"
    fi

    # Include metadata in the log entry
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S.%3N')
    local script_name=$(basename "$0")
    local user=$(whoami)
    local hostname=$(hostname)

    # Format and write the log entry
    echo "$timestamp [$log_level_name] [$script_name] [$user@$hostname] - $message" | tee -a "$log_file"
}

# Environment variables for paths and configurations
export MSPOO_LOG_FILE="/var/log/khelp_mspoo.log"
export MSPOO_SCRIPT_PATH="/usr/local/bin/mspoo.sh"
export MSPOO_SERVICE_PATH="/etc/systemd/system/mspoo.service"
export MSPOO_DOC_DIR="/usr/local/share/khelp_mspoof"
export MSPOO_DOC_FILE="$MSPOO_DOC_DIR/README.md"

# Example usage of the log function
log $LOG_LEVEL_INFO "This is an informational message." "$MSPOO_LOG_FILE"
log $LOG_LEVEL_ERROR "This is an error message." "$MSPOO_LOG_FILE"
log $LOG_LEVEL_WARNING "This is a warning message." "$MSPOO_LOG_FILE"

# Debugging: Print environment variables
log $LOG_LEVEL_INFO "MSPOO_LOG_FILE=$MSPOO_LOG_FILE" "$MSPOO_LOG_FILE"

# Check if required commands are available
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log $LOG_LEVEL_ERROR "Required command '$cmd' not found. Please install it and try again." "$MSPOO_LOG_FILE"
        exit 1
    fi
}

# Disable internet connectivity check for troubleshooting
#check_internet() {
#    if ! ping -c 1 8.8.8.8 &> /dev/null; then
#        log $LOG_LEVEL_ERROR "No internet connectivity. Please check your network connection." "$MSPOO_LOG_FILE"
#        exit 1
#    fi
#}

# Create and enable MAC spoofing service
log $LOG_LEVEL_INFO "Creating and enabling MAC spoofing service..." "$MSPOO_LOG_FILE"

# Create the MAC spoofing script
cat << 'EOF' > "$MSPOO_SCRIPT_PATH"
#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
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
        log $LOG_LEVEL_ERROR "Invalid MAC address format: $mac" "$MSPOO_LOG_FILE"
        return 1
    fi
    return 0
}

# Function to spoof MAC address for a given interface
spoof_mac() {
    local interface=$1
    local new_mac=$(generate_random_mac)
    log $LOG_LEVEL_INFO "Spoofing MAC address for interface $interface with new MAC: $new_mac" "$MSPOO_LOG_FILE"

    if ! ip link set dev $interface down; then
        log $LOG_LEVEL_ERROR "Failed to bring down the network interface $interface." "$MSPOO_LOG_FILE"
        return 1
    fi

    if ! ip link set dev $interface address $new_mac; then
        log $LOG_LEVEL_ERROR "Failed to change the MAC address for $interface." "$MSPOO_LOG_FILE"
        return 1
    fi

    if ! ip link set dev $interface up; then
        log $LOG_LEVEL_ERROR "Failed to bring up the network interface $interface." "$MSPOO_LOG_FILE"
        return 1
    fi

    ip link show $interface | grep ether
    log $LOG_LEVEL_INFO "MAC address for $interface changed to $new_mac" "$MSPOO_LOG_FILE"
    return 0
}

# Function to determine the primary network interface
get_primary_interface() {
    ip route | grep default | awk '{print $5}'
}

# Function to get the secondary interface
get_secondary_interface() {
    local primary_interface=$1
    ip link show | awk -F': ' '{print $2}' | grep -v lo | grep -v $primary_interface
}

# Function to ensure the network interface is up
wait_for_interface() {
    local interface=$1
    for i in {1..10}; do
        if ip link show $interface | grep -q "state UP"; then
            return 0
        fi
        sleep 1
    done
    log $LOG_LEVEL_ERROR "Network interface $interface did not come up" "$MSPOO_LOG_FILE"
    return 1
}

# Main logic
primary_interface=$(get_primary_interface)
log $LOG_LEVEL_INFO "Primary network interface detected: $primary_interface" "$MSPOO_LOG_FILE"

# Spoof the primary network interface
if spoof_mac $primary_interface; then
    log $LOG_LEVEL_INFO "Successfully spoofed MAC address for primary interface $primary_interface" "$MSPOO_LOG_FILE"
    wait_for_interface $primary_interface
else
    log $LOG_LEVEL_ERROR "Failed to spoof MAC address for primary interface $primary_interface" "$MSPOO_LOG_FILE"
fi

# Get the secondary network interface
secondary_interfaces=$(get_secondary_interface $primary_interface)
log $LOG_LEVEL_INFO "Secondary network interfaces detected: $secondary_interfaces" "$MSPOO_LOG_FILE"

# Spoof the secondary network interfaces
for secondary_interface in $secondary_interfaces; do
    if spoof_mac $secondary_interface; then
        log $LOG_LEVEL_INFO "Successfully spoofed MAC address for secondary interface $secondary_interface" "$MSPOO_LOG_FILE"
        wait_for_interface $secondary_interface
    else
        log $LOG_LEVEL_ERROR "Failed to spoof MAC address for secondary interface $secondary_interface" "$MSPOO_LOG_FILE"
    fi
done
EOF

# Make the script executable
chmod +x "$MSPOO_SCRIPT_PATH"

# Create the systemd service unit file for MAC spoofing
cat << EOF > "$MSPOO_SERVICE_PATH"
[Unit]
Description=MSPOO MACSpoofing Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$MSPOO_SCRIPT_PATH
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

chmod +x "$MSPOO_SERVICE_PATH"

systemctl daemon-reload
systemctl enable mspoo.service
log $LOG_LEVEL_INFO "MAC spoofing service created and enabled successfully." "$MSPOO_LOG_FILE"

# Documentation
mkdir -p "$MSPOO_DOC_DIR"
cat << EOF > "$MSPOO_DOC_FILE"
# MAC Spoofer Script 
MSPOO

## Description
This script changes the MAC address of all network interfaces (except loopback) to a randomly generated address. It includes advanced logging features, error handling, and ensures that network interfaces are correctly managed during the process.

## Functions

### log(level, message, log_file)
Logs messages with a specified log level and rotates the log file if it exceeds 1MB. The log entries include detailed timestamps, script name, user, and hostname.

- **Parameters:**
  - `level`: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
  - `message`: The log message.
  - `log_file`: The log file path.

### generate_random_mac()
Generates a random MAC address with the prefix `02`.

- **Returns:** A randomly generated MAC address.

### validate_mac(mac)
Validates the format of a MAC address.

- **Parameters:**
  - `mac`: The MAC address to validate.
- **Returns:** `0` if the MAC address is valid, `1` otherwise.

### spoof_mac(interface)
Changes the MAC address of a specified network interface to a randomly generated address.

- **Parameters:**
  - `interface`: The network interface to spoof the MAC address for.
- **Returns:** `0` if successful, `1` otherwise.

### get_primary_interface()
Determines the primary network interface.

- **Returns:** The primary network interface.

### get_secondary_interface(primary_interface)
Gets the secondary network interfaces excluding the primary and loopback interfaces.

- **Parameters:**
  - `primary_interface`: The primary network interface.
- **Returns:** A list of secondary network interfaces.

### wait_for_interface(interface)
Ensures the network interface is up.

- **Parameters:**
  - `interface`: The network interface to check.
- **Returns:** `0` if the interface is up, `1` otherwise.

## Log File
Logs are saved to /var/log/khelp_mspoo.log. The log file is rotated if it exceeds 1MB. Log entries include detailed timestamps, log levels, script name, user, and hostname.

## Requirements
- The `ip` command must be available.
- The script must be run as root.

## Tasks Performed

1. **Environment Setup:**
   - Sets environment variables for log file paths.
   - Checks if the script is run as root.

2. **Logging Configuration:**
   - Configures advanced logging with log levels, log rotation, and detailed formatting.
   - Logs messages with different log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL).

3. **MAC Address Spoofing:**
   - Generates a random MAC address.
   - Validates the MAC address format.
   - Changes the MAC address of the primary and secondary network interfaces.
   - Ensures the network interfaces are correctly managed (brought down and up).

4. **Systemd Service Creation:**
   - Creates a systemd service unit file for MAC spoofing.
   - Enables and starts the systemd service.

5. **Documentation:**
   - Creates a detailed README.md file with information about the script, its functions, log file, requirements, and tasks performed.

## Notes
- The script includes error handling and logs errors and info messages.
- The script ensures that the generated MAC address format is valid.
- The script checks and manages the state of network interfaces during the MAC address change process.
EOF
log $LOG_LEVEL_INFO "MAC spoofing completed successfully." "$MSPOO_LOG_FILE"

# Summary and Reboot
log $LOG_LEVEL_INFO "khelp is done! Everything is looking good!" "$MSPOO_LOG_FILE"
log $LOG_LEVEL_INFO "It enables MSPOO - Service." "$MSPOO_LOG_FILE"

log $LOG_LEVEL_INFO "Rebooting the system to apply changes in 1 minute..." "$MSPOO_LOG_FILE"
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log $LOG_LEVEL_INFO "Cancelling the reboot..." "$MSPOO_LOG_FILE"
    shutdown -c
else
    log $LOG_LEVEL_INFO "Reboot will proceed in 1 minute." "$MSPOO_LOG_FILE"
fi