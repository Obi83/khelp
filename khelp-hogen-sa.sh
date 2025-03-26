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
    local hogen_log_file="/var/log/hostname_spoofer.log"

    # Rotate log file if it exceeds 1MB
    if [ -f "$hogen_log_file" ] && [ $(stat -c%s "$hogen_log_file") -gt 1048576 ]; then
        mv "$hogen_log_file" "$hogen_log_file.$(date +'%Y%m%d%H%M%S')"
    fi

    echo "$(date +'%Y-%m-%d %H:%M:%S') [$level] - $message" | tee -a "$hogen_log_file"
}

# Example usage of the log function
log "INFO" "This is an informational message."
log "ERROR" "This is an error message."
log "WARNING" "This is a warning message."

# Environment variables for paths and configurations
export USER_HOME=$(eval echo ~${SUDO_USER})
export hogen_log_file="/var/log/hostname_spoofer.log"

# Debugging: Print environment variables
log "INFO" "USER_HOME=$USER_HOME"
log "INFO" "hogen_log_file=$hogen_log_file"

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
Logs are saved to /var/log/hostname_spoofer.log. The log file is rotated if it exceeds 1MB.

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
    local packages="curl jq"

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

# Ensure curl is installed
log "INFO" "Checking if curl is installed..."
if ! command -v curl &> /dev/null; then
    log "INFO" "curl is not installed. Installing curl..."
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y curl; then
            log "INFO" "curl installed successfully."
            break
        else
            log "ERROR" "Failed to install curl. Retrying in $((attempts * 5)) seconds..."
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi

        if [ $attempts -eq $max_attempts ]; then
            log "ERROR" "Failed to install curl after $max_attempts attempts. Please check your network connection and try again."
            exit 1
        fi
    done
else
    log "INFO" "curl is already installed."
fi

# Ensure jq is installed
log "INFO" "Checking if jq is installed..."
if ! command -v jq &> /dev/null; then
    log "INFO" "jq is not installed. Installing jq..."
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y jq; then
            log "INFO" "jq installed successfully."
            break
        else
            log "ERROR" "Failed to install jq. Retrying in $((attempts * 5)) seconds..."
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi

        if [ $attempts -eq $max_attempts ]; then
            log "ERROR" "Failed to install jq after $max_attempts attempts. Please check your network connection and try again."
            exit 1
        fi
    done
else
    log "INFO" "jq is already installed."
fi

# Documentation
mkdir -p /usr/local/share/package_installer
cat << 'EOF' > /usr/local/share/package_installer/README.md
# Package Installer Script

## Description
This script ensures that the required packages (`curl` and `jq`) are installed on the system. If not installed, it attempts to install them with a retry mechanism.

## Functions
- log(level, message): Logs messages with a specified log level.
- install_package(package): Checks if the package is installed. If not, attempts to install it with a retry mechanism.

## Log File
Logs are saved to /var/log/hostname_spoofer.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `apt` package manager must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of package installations.
EOF

# Create and enable hostname generator service
log "INFO" "Creating and enabling hostname generator service..."

# Create the hostname generator script
cat << 'EOF' > /usr/local/bin/hogen.sh
#!/bin/bash

# Function to fetch a random name from the Random User Generator API
fetch_random_name() {
    local api_url="https://randomuser.me/api/"
    local response=$(curl -s $api_url)
    
    if [ -z "$response" ]; then
        log "ERROR" "Failed to fetch data from the API."
        exit 1
    fi

    local first_name=$(echo $response | jq -r '.results[0].name.first')
    local last_name=$(echo $response | jq -r '.results[0].name.last')
    
    if [ -z "$first_name" ] || [ -z "$last_name" ]; then
        log "ERROR" "Failed to extract names from the API response."
        exit 1
    fi

    # Capitalize the first letter of the first name and last name
    first_name=$(echo $first_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    last_name=$(echo $last_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    local name="${first_name}${last_name}"
    
    echo $name
}

newhn=$(fetch_random_name)
log "INFO" "Fetched random name: $newhn"

if hostnamectl set-hostname "$newhn"; then
    log "INFO" "Hostname set to $newhn"
else
    log "ERROR" "Failed to set hostname to $newhn"
    exit 1
fi

# Ensure /etc/hosts has the correct entries
update_hosts_file() {
    local entry="$1"
    if ! grep -q "$entry" /etc/hosts; then
        echo "$entry" >> /etc/hosts
        log "INFO" "Added $entry to /etc/hosts"
    fi
}

update_hosts_file "127.0.0.1    localhost"
update_hosts_file "127.0.0.1    $newhn"

# Ensure the current hostname is also mapped correctly
current_hostname=$(hostname)
update_hosts_file "127.0.0.1    $current_hostname"

log "INFO" "Hostname set to $newhn and /etc/hosts updated"
echo "Hostname set to $newhn and /etc/hosts updated"
EOF

# Make the script executable
chmod +x /usr/local/bin/hogen.sh

# Documentation
mkdir -p /usr/local/share/hostname_spoofer
cat << 'EOF' > /usr/local/share/hostname_spoofer/README.md
# Hostname Spoofer Script 
HOGEN

## Description
This script changes the system hostname to a randomly generated name fetched from the Random User Generator API.

## Functions
- log(level, message): Logs messages with a specified log level.
- fetch_random_name: Fetches a random name from the Random User Generator API.
- update_hosts_file(entry): Ensures the entry is present in the /etc/hosts file.

## Log File
Logs are saved to /var/log/hostname_spoofer.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `curl` and `jq` commands must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the API response and ensures the hostname is set correctly.
EOF

# Create the systemd service unit file for hostname generator
cat << EOF > /etc/systemd/system/hogen.service
[Unit]
Description=HOGEN Hostname Generator
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/hogen.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

chmod +x /etc/systemd/system/hogen.service

systemctl daemon-reload
systemctl enable hogen.service
systemctl start hogen.service
log "INFO" "Hostname generator service created and enabled successfully."

# Summary and Reboot
log "INFO" ""
log "INFO" "khelp is done! Everything is looking good!"
log "INFO" ""
log "INFO" "It enables: HOGEN - Service."

log "INFO" "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log "INFO" "Cancelling the reboot..."
    shutdown -c
else
    log "INFO" "Reboot will proceed in 1 minute."
fi