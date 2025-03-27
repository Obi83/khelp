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
CURRENT_LOG_LEVEL=${CURRENT_LOG_LEVEL:-$LOG_LEVEL_DEBUG}

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
export MSPOO_LOG_FILE=${MSPOO_LOG_FILE:-"/var/log/khelp_mspoo.log"}
export MSPOO_SCRIPT_PATH=${MSPOO_SCRIPT_PATH:-"/usr/local/bin/mspoo.sh"}
export MSPOO_SERVICE_PATH=${MSPOO_SERVICE_PATH:-"/etc/systemd/system/mspoo.service"}
export MSPOO_DOC_DIR=${MSPOO_DOC_DIR:-"/usr/local/share/khelp_mspoof"}
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

# Ensure ip command is available
check_command ip

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
if [ -z "$primary_interface" ]; then
    log $LOG_LEVEL_ERROR "No primary network interface detected." "$MSPOO_LOG_FILE"
    exit 1
fi
log $