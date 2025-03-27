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
export HOGEN_LOG_FILE=${HOGEN_LOG_FILE:-"/var/log/khelp_hogen.log"}
export HOGEN_SCRIPT_PATH=${HOGEN_SCRIPT_PATH:-"/usr/local/bin/hogen.sh"}
export HOGEN_SERVICE_PATH=${HOGEN_SERVICE_PATH:-"/etc/systemd/system/hogen.service"}
export HOGEN_DOC_DIR=${HOGEN_DOC_DIR:-"/usr/local/share/khelp_hogen"}
export HOGEN_DOC_FILE="$HOGEN_DOC_DIR/README.md"

# Example usage of the log function
log $LOG_LEVEL_INFO "This is an informational message." "$HOGEN_LOG_FILE"
log $LOG_LEVEL_ERROR "This is an error message." "$HOGEN_LOG_FILE"
log $LOG_LEVEL_WARNING "This is a warning message." "$HOGEN_LOG_FILE"

# Debugging: Print environment variables
log $LOG_LEVEL_INFO "HOGEN_LOG_FILE=$HOGEN_LOG_FILE" "$HOGEN_LOG_FILE"

# Check if required commands are available
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log $LOG_LEVEL_ERROR "Required command '$cmd' not found. Please install it and try again." "$HOGEN_LOG_FILE"
        exit 1
    fi
}

# Check for internet connectivity
check_internet() {
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log $LOG_LEVEL_ERROR "No internet connectivity. Please check your network connection." "$HOGEN_LOG_FILE"
        exit 1
    fi
}

# Ensure curl is installed
log $LOG_LEVEL_INFO "Checking if curl is installed..." "$HOGEN_LOG_FILE"
if ! command -v curl &> /dev/null; then
    log $LOG_LEVEL_INFO "curl is not installed. Installing curl..." "$HOGEN_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y curl; then
            log $LOG_LEVEL_INFO "curl installed successfully." "$HOGEN_LOG_FILE"
            break
        else
            log $LOG_LEVEL_ERROR "Failed to install curl. Retrying in $((attempts * 5)) seconds..." "$HOGEN_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi

        if [ $attempts -eq $max_attempts ]; then
            log $LOG_LEVEL_ERROR "Failed to install curl after $max_attempts attempts. Please check your network connection and try again." "$HOGEN_LOG_FILE"
            exit 1
        fi
    done
else
    log $LOG_LEVEL_INFO "curl is already installed." "$HOGEN_LOG_FILE"
fi

# Ensure jq is installed
log $LOG_LEVEL_INFO "Checking if jq is installed..." "$HOGEN_LOG_FILE"
if ! command -v jq &> /dev/null; then
    log $LOG_LEVEL_INFO "jq is not installed. Installing jq..." "$HOGEN_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y jq; then
            log $LOG_LEVEL_INFO "jq installed successfully." "$HOGEN_LOG_FILE"
            break
        else
            log $LOG_LEVEL_ERROR "Failed to install jq. Retrying in $((attempts * 5)) seconds..." "$HOGEN_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi

        if [ $attempts -eq $max_attempts]; then
            log $LOG_LEVEL_ERROR "Failed to install jq after $max_attempts attempts. Please check your network connection and try again." "$HOGEN_LOG_FILE"
            exit 1
        fi
    done
else
    log $LOG_LEVEL_INFO "jq is already installed." "$HOGEN_LOG_FILE"
fi

# Create and enable hostname generator service
log $LOG_LEVEL_INFO "Creating and enabling hostname generator service..." "$HOGEN_LOG_FILE"

# Create the hostname generator script
cat << 'EOF' > "$HOGEN_SCRIPT_PATH"
#!/bin/bash

# Function to fetch a random name from the Random User Generator API
fetch_random_name() {
    local api_url="https://randomuser.me/api/"
    local response=$(curl -s $api_url)
    
    if [ -z "$response" ]; then
        log $LOG_LEVEL_ERROR "Failed to fetch data from the API." "$HOGEN_LOG_FILE"
        exit 1
    fi

    local first_name=$(echo $response | jq -r '.results[0].name.first')
    local last_name=$(echo $response | jq -r '.results[0].name.last')
    
    if [ -z "$first_name" ] || [ -z "$last_name" ]; then
        log $LOG_LEVEL_ERROR "Failed to extract names from the API response." "$HOGEN_LOG_FILE"
        exit 1
    fi

    # Capitalize the first letter of the first name and last name
    first_name=$(echo $first_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    last_name=$(echo $last_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    local name="${first_name}${last_name}"
    
    echo $name
}

newhn=$(fetch_random_name)
log $LOG_LEVEL_INFO "Fetched random name: $newhn" "$HOGEN_LOG_FILE"

if hostnamectl set-hostname "$newhn"; then
    log $LOG_LEVEL_INFO "Hostname set to $newhn" "$HOGEN_LOG_FILE"
else
    log $LOG_LEVEL_ERROR "Failed to set hostname to $newhn" "$HOGEN_LOG_FILE"
    exit 1
fi

# Ensure /etc/hosts has the correct entries
update_hosts_file() {
    local entry="$1"
    if ! grep -q "$entry" /etc/hosts; then
        echo "$entry" >> /etc/hosts
        log $LOG_LEVEL_INFO "Added $entry to /etc/hosts" "$HOGEN_LOG_FILE"
    fi
}

update_hosts_file "127.0.0.1    localhost"
update_hosts_file "127.0.0.1    $newhn"

# Ensure the current hostname is also mapped correctly
current_hostname=$(hostname)
update_hosts_file "127.0.0.1    $current_hostname"

log $LOG_LEVEL_INFO "Hostname set to $newhn and /etc/hosts updated" "$HOGEN_LOG_FILE"
echo "Hostname set to $newhn and /etc/hosts updated"
EOF

# Make the script executable
chmod +x "$HOGEN_SCRIPT_PATH"

# Create the systemd service unit file for hostname generator
cat << EOF > "$HOGEN_SERVICE_PATH"
[Unit]
Description=HOGEN Hostname Generator
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$HOGEN_SCRIPT_PATH
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

chmod +x "$HOGEN_SERVICE_PATH"

systemctl daemon-reload
systemctl enable hogen.service
log $LOG_LEVEL_INFO "Hostname generator service created and enabled successfully." "$HOGEN_LOG_FILE"

# Documentation
mkdir -p "$HOGEN_DOC_DIR"
cat << 'EOF' > "$HOGEN_DOC_FILE"
# Hostname Spoofer Script 
HOGEN

## Description
This script changes the system hostname to a randomly generated name fetched from the Random User Generator API.

## Functions

### log(level, message, log_file)
Logs messages with a specified log level and rotates the log file if it exceeds 1MB. The log entries include detailed timestamps, script name, user, and hostname.

- **Parameters:**
  - `level`: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
  - `message`: The log message.
  - `log_file`: The log file path.

### fetch_random_name
Fetches a random name from the Random User Generator API.

- **Returns:** A randomly fetched name.

### update_hosts_file(entry)
Ensures the entry is present in the /etc/hosts file.

- **Parameters:**
  - `entry`: The entry to add to /etc/hosts.

## Log File
Logs are saved to /var/log/khelp_hogen.log. The log file is rotated if it exceeds 1MB. Log entries include detailed timestamps, log levels, script name, user, and hostname.

## Requirements
- The `curl` and `jq` commands must be available.
- The script must be run as root.

## Tasks Performed

1. **Environment Setup:**
   - Sets environment variables for log file paths.
   - Checks if the script is run as root.

2. **Logging Configuration:**
   - Configures advanced logging with log levels, log rotation, and detailed formatting.
   - Logs messages with different log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL).

3. **Hostname Generation:**
   - Fetches a random name from the Random User Generator API.
   - Validates the API response and ensures the hostname is set correctly.
   - Ensures /etc/hosts is updated with the correct entries.

4. **Systemd Service Creation:**
   - Creates a systemd service unit file for hostname generation.
   - Enables and starts the systemd service.

5. **Documentation:**
   - Creates a detailed README.md file with information about the script, its functions, log file, requirements, and tasks performed.

## Notes
- The script includes error handling and logs errors and info messages.
- The script ensures that the generated hostname is set correctly and /etc/hosts is updated appropriately.
EOF

log $LOG_LEVEL_INFO "Hostname generation completed successfully." "$HOGEN_LOG_FILE"

# Summary and Reboot
log $LOG_LEVEL_INFO "khelp is done! Everything is looking good!" "$HOGEN_LOG_FILE"
log $LOG_LEVEL_INFO "It enables: HOGEN - Service." "$HOGEN_LOG_FILE"

log $LOG_LEVEL_INFO "Rebooting the system to apply changes in 1 minute..." "$HOGEN_LOG_FILE"
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log $LOG_LEVEL_INFO "Cancelling the reboot..." "$HOGEN_LOG_FILE"
    shutdown -c
else
    log $LOG_LEVEL_INFO "Reboot will proceed in 1 minute." "$HOGEN_LOG_FILE"
fi
