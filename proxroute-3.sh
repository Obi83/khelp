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

# Enhanced logging function with log levels, log rotation, and detailed formatting
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

# Documentation Logging Function
mkdir -p "$KHELP_LOGGING_DIR"
cat << 'EOF' > "$KHELP_LOGGING_DIR/README.md"
# Logging Function Documentation

## Overview
This section documents the enhanced logging function and log levels used in the scripts. The logging function is designed to provide detailed logging with various log levels, log rotation, and metadata formatting to help in debugging and monitoring the system.

## Log Levels
The following log levels are defined:
- `LOG_LEVEL_DEBUG=0`: Detailed debugging information.
- `LOG_LEVEL_INFO=1`: General informational messages.
- `LOG_LEVEL_WARNING=2`: Warnings about potential issues.
- `LOG_LEVEL_ERROR=3`: Errors that have occurred.
- `LOG_LEVEL_CRITICAL=4`: Critical issues that need immediate attention.

The current log level is set using the `CURRENT_LOG_LEVEL` variable. This can be adjusted as needed to control the verbosity of the logs.

## Logging Function
The logging function `log()` is designed to log messages with different levels of severity, rotate logs if they exceed a certain size, and include detailed metadata in each log entry. Below is the detailed explanation of the function:

### Parameters
- `level`: The log level of the message (e.g., `LOG_LEVEL_INFO`).
- `message`: The message to be logged.
- `log_file`: The file where the log message should be written.

### Function Logic
1. **Determine Log Level Name**: The log level name is determined based on the provided log level.
2. **Check Log Level**: The function checks if the current log level is sufficient to log the message. If not, it returns immediately.
3. **Log Rotation**: If the log file exceeds 1MB, it is rotated by renaming it with a timestamp.
4. **Metadata Inclusion**: Metadata such as timestamp, script name, user, and hostname are included in the log entry.
5. **Log Formatting and Writing**: The log entry is formatted and written to the specified log file using the `tee` command, which also allows the message to be displayed on the console.

### Example Usage
```bash
# Example usage of the log function
log $LOG_LEVEL_INFO "This is an informational message." "/var/log/khelp_proxy.log"
log $LOG_LEVEL_ERROR "This is an error message." "/var/log/khelp_proxy.log"
log $LOG_LEVEL_WARNING "This is a warning message." "/var/log/khelp_proxy.log"
```
This example demonstrates how to use the logging function to log messages with different levels of severity to a specified log file.
EOF

# Environment variables for paths and configurations
export USER_HOME=$(eval echo ~${SUDO_USER})
export UPDATE_LOG_FILE="/var/log/khelp_proxy.log"
export KHELP_UPDATE_DIR="/usr/local/share/khelp_update"
export KHELP_INSTALLER_DIR="/usr/local/share/khelp_installer"
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export PROXY_API_URL1="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"
export PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
export PROXY_API_URL3="https://spys.me/socks.txt"
export PROXY_API_URL4="https://www.proxy-list.download/api/v1/get?type=socks5"
export PROXY_API_URL5="https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5"
export PROXY_API_URL6="https://www.freeproxy.world/api/proxy?protocol=socks5&limit=100"
export PROXY_API_URL7="https://www.free-proxy-list.net/socks5.txt"
export PROXY_API_URL8="https://www.proxynova.com/proxy-server-list/"
export PROXY_API_URL9="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=elite"
export PROXY_API_URL10="https://hidemy.name/en/proxy-list/?type=5&anon=234"
export KHELP_PROXYCHAINS_DIR="/usr/local/share/khelp_proxychains"
export UPDATE_PROXIES_SCRIPT="/usr/local/bin/update_proxies.sh"
export SYSTEMD_UPDATE_PROXIES_SERVICE="/etc/systemd/system/update_proxies.service"
export SYSTEMD_UPDATE_PROXIES_TIMER="/etc/systemd/system/update_proxies.timer"
export CRONTAB_FILE="/etc/crontab"
export KHELP_UFW_DIR="/usr/local/share/khelp_ufw"
export UFW_SCRIPT="/usr/local/bin/ufw.sh"
export UFW_SERVICE="/etc/systemd/system/ufw.service"
export KHELP_FAIL2BAN_DIR="/usr/local/share/khelp_fail2ban"
export FAIL2BAN_CONFIG="/etc/fail2ban/jail.local"
export IPTABLES_RULES_FILE="/etc/iptables/rules.v4"
export IPTABLES_SCRIPT="/usr/local/bin/iptables.sh"
export IPTABLES_SERVICE="/etc/systemd/system/iptables.service"
export KHELP_IPTABLES_DIR="/usr/local/share/khelp_iptables"
export KHELP_TOR_DIR="/usr/local/share/khelp_tor"
export KHELP_TERMINATOR_DIR="/usr/local/share/khelp_terminator"
export STARTUP_SCRIPT_PATH="$USER_HOME/startup_script.sh"
export DESKTOP_ENTRY_PATH="$USER_HOME/.config/autostart/startup_terminal.desktop"
export KHELP_VERIFY_DIR="/usr/local/share/khelp_verify"

# Improved URL validation function
validate_url() {
    local url="$1"
    local log_file="$2"
    
    if [[ ! $url =~ ^https?://.*$ ]]; then
        log $LOG_LEVEL_ERROR "Invalid URL: $url" "$log_file"
        exit 1
    fi
}

# Debugging: Print environment variables
log $LOG_LEVEL_INFO "Environment Variables:"
log $LOG_LEVEL_INFO "USER_HOME=$USER_HOME"
log $LOG_LEVEL_INFO "UPDATE_LOG_FILE=$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_UPDATE_DIR=$KHELP_UPDATE_DIR"
log $LOG_LEVEL_INFO "KHELP_INSTALLER_DIR=$KHELP_INSTALLER_DIR"
log $LOG_LEVEL_INFO "PROXYCHAINS_CONF=$PROXYCHAINS_CONF"
log $LOG_LEVEL_INFO "PROXY_API_URL1=$PROXY_API_URL1"
log $LOG_LEVEL_INFO "PROXY_API_URL2=$PROXY_API_URL2"
log $LOG_LEVEL_INFO "PROXY_API_URL3=$PROXY_API_URL3"
log $LOG_LEVEL_INFO "PROXY_API_URL4=$PROXY_API_URL4"
log $LOG_LEVEL_INFO "PROXY_API_URL5=$PROXY_API_URL5"
log $LOG_LEVEL_INFO "PROXY_API_URL6=$PROXY_API_URL6"
log $LOG_LEVEL_INFO "PROXY_API_URL7=$PROXY_API_URL7"
log $LOG_LEVEL_INFO "PROXY_API_URL8=$PROXY_API_URL8"
log $LOG_LEVEL_INFO "PROXY_API_URL9=$PROXY_API_URL9"
log $LOG_LEVEL_INFO "PROXY_API_URL10=$PROXY_API_URL10"
log $LOG_LEVEL_INFO "KHELP_PROXYCHAINS_DIR=$KHELP_PROXYCHAINS_DIR"
log $LOG_LEVEL_INFO "UPDATE_PROXIES_SCRIPT=$UPDATE_PROXIES_SCRIPT"
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_SERVICE=$SYSTEMD_UPDATE_PROXIES_SERVICE"
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_TIMER=$SYSTEMD_UPDATE_PROXIES_TIMER"
log $LOG_LEVEL_INFO "CRONTAB_FILE=$CRONTAB_FILE"
log $LOG_LEVEL_INFO "KHELP_UFW_DIR=$KHELP_UFW_DIR"
log $LOG_LEVEL_INFO "UFW_SCRIPT=$UFW_SCRIPT"
log $LOG_LEVEL_INFO "UFW_SERVICE=$UFW_SERVICE"
log $LOG_LEVEL_INFO "KHELP_FAIL2BAN_DIR=$KHELP_FAIL2BAN_DIR"
log $LOG_LEVEL_INFO "FAIL2BAN_CONFIG=$FAIL2BAN_CONFIG"
log $LOG_LEVEL_INFO "IPTABLES_RULES_FILE=$IPTABLES_RULES_FILE"
log $LOG_LEVEL_INFO "IPTABLES_SCRIPT=$IPTABLES_SCRIPT"
log $LOG_LEVEL_INFO "IPTABLES_SERVICE=$IPTABLES_SERVICE"
log $LOG_LEVEL_INFO "KHELP_IPTABLES_DIR=$KHELP_IPTABLES_DIR"
log $LOG_LEVEL_INFO "KHELP_TOR_DIR=$KHELP_TOR_DIR"
log $LOG_LEVEL_INFO "KHELP_TERMINATOR_DIR=$KHELP_TERMINATOR_DIR"
log $LOG_LEVEL_INFO "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH"
log $LOG_LEVEL_INFO "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH"
log $LOG_LEVEL_INFO "KHELP_VERIFY_DIR=$KHELP_VERIFY_DIR"

# Function to update and upgrade the system
update_and_upgrade() {
    log $LOG_LEVEL_INFO "Starting system update and upgrade..." "$UPDATE_LOG_FILE"
    if apt update -o Acquire::Queue-Mode="access" -o Acquire::http::Pipeline-Depth=200 --retry=3 -y && \
       apt upgrade -o Acquire::Queue-Mode="access" -o Acquire::http::Pipeline-Depth=200 --retry=3 -y; then
        log $LOG_LEVEL_INFO "System update and upgrade completed successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to update and upgrade the system." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Function to install packages
install_packages() {
    local packages=("$@")
    log $LOG_LEVEL_INFO "Installing packages: ${packages[*]}..." "$UPDATE_LOG_FILE"
    if apt install -o Acquire::Queue-Mode="access" -o Acquire::http::Pipeline-Depth=200 --retry=3 -y "${packages[@]}"; then
        log $LOG_LEVEL_INFO "Packages installed successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to install packages: ${packages[*]}." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Function to remove packages
remove_packages() {
    local packages=("$@")
    log $LOG_LEVEL_INFO "Removing packages: ${packages[*]}..." "$UPDATE_LOG_FILE"
    if apt remove -o Acquire::Queue-Mode="access" -o Acquire::http::Pipeline-Depth=200 --retry=3 -y "${packages[@]}"; then
        log $LOG_LEVEL_INFO "Packages removed successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to remove packages: ${packages[*]}." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Function to clean up the system
autoclean_system() {
    log $LOG_LEVEL_INFO "Cleaning up the system..." "$UPDATE_LOG_FILE"
    if apt autoclean -o Acquire::Queue-Mode="access" -o Acquire::http::Pipeline-Depth=200 --retry=3 -y && \
       apt autoremove -o Acquire::Queue-Mode="access" -o Acquire::http::Pipeline-Depth=200 --retry=3 -y; then
        log $LOG_LEVEL_INFO "System cleanup completed successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to clean up the system." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Documentation System Update
mkdir -p "$KHELP_UPDATE_DIR"
cat << 'EOF' > "$KHELP_UPDATE_DIR/README.md"
# System Update Documentation

## Overview
This section documents the `update_system` function, which is designed to update and upgrade the system packages. It includes retry logic to handle potential network or package manager issues.

## Function Explanation
### Parameters
- No parameters are required for this function.

### Function Logic
1. **Logging**: Logs the start of the system update process with an informational log level.
2. **Retry Mechanism**: Attempts to update and upgrade the system up to three times in case of failures.
3. **Update and Upgrade**: Uses `apt update`, `apt full-upgrade -y`, `apt autoremove -y`, and `apt autoclean` to update and clean the system packages.
4. **Logging Success**: Logs a message indicating the completion of the update and upgrade process.
5. **Retry Logic**: If the update fails, it waits and retries up to a maximum of three attempts.
6. **Logging Failure**: Logs an error message if the update fails after the maximum attempts and exits with an error code.

### Example Usage
```bash
# Example usage of the update_system function
update_system
```
### Detailed Steps
1. **Initial Logging**: The function starts by logging an informational message indicating the beginning of the system update.
2. **Loop for Retry**: A loop is used to attempt the update up to three times. If the update is successful, it logs the success and returns.
3. **Update and Upgrade Commands**: The following commands are executed to update the system:
   - `apt update`: Fetches the list of available updates.
   - `apt full-upgrade -y`: Installs the available updates.
   - `apt autoremove -y`: Removes unnecessary packages.
   - `apt autoclean`: Cleans up the local repository of package files.
4. **Failure Handling**: If any of the commands fail, it logs an error message, increments the attempt counter, and waits for a specified time before retrying.
5. **Final Failure Logging**: If all attempts fail, it logs an error message and exits with an error code.

This function ensures that the system is updated and cleaned, with proper logging and retry mechanisms to handle potential issues.
EOF

# Install helper packages with retry mechanism
install_packages() {
    log $LOG_LEVEL_INFO "Installing tools and packages." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3
    local packages="ufw tor curl jq iptables fail2ban sslh terminator"

    while [ $attempts -lt $max_attempts ]; do
        if sudo apt install -y $packages; then
            log $LOG_LEVEL_INFO "Installed all useful helper tools." "$UPDATE_LOG_FILE"
            return 0
        else
            log $LOG_LEVEL_ERROR "Package installation failed. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Package installation failed after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    exit 1
}

# Install packages
install_packages

# Documentation Install Packages
mkdir -p "$KHELP_INSTALLER_DIR"
cat << 'EOF' > "$KHELP_INSTALLER_DIR/README.md"
# Package Installation Documentation

## Overview
This section documents the `install_packages` function, which is designed to install essential helper tools and packages with a retry mechanism to handle potential issues during the installation process.

## Function Explanation
### Parameters
- No parameters are required for this function.

### Function Logic
1. **Logging**: Logs the start of the package installation process with an informational log level.
2. **Retry Mechanism**: Attempts to install the packages up to three times in case of failures.
3. **Package Installation**: Uses `sudo apt install -y` to install the specified packages.
4. **Logging Success**: Logs a message indicating the successful installation of the packages.
5. **Retry Logic**: If the installation fails, it waits and retries up to a maximum of three attempts.
6. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.

### Example Usage
```bash
# Install packages
install_packages
```
### Detailed Steps
1. **Initial Logging**: The function starts by logging an informational message indicating the beginning of the package installation.
2. **Loop for Retry**: A loop is used to attempt the installation up to three times. If the installation is successful, it logs the success and returns.
3. **Package Installation Command**: The following command is executed to install the packages:
   - `sudo apt install -y ufw tor curl jq iptables fail2ban sslh terminator`
4. **Failure Handling**: If the installation command fails, it logs an error message, increments the attempt counter, and waits for a specified time before retrying.
5. **Final Failure Logging**: If all attempts fail, it logs an error message and exits with an error code.

This function ensures that the necessary helper tools and packages are installed, with proper logging and retry mechanisms to handle potential issues.
EOF

# Main script execution
check_internet
update_system
install_packages

# Ensure ProxyChains is installed
log $LOG_LEVEL_INFO "Checking if ProxyChains is installed..." "$UPDATE_LOG_FILE"
if ! command -v proxychains &> /dev/null; then
    log $LOG_LEVEL_INFO "ProxyChains is not installed. Installing ProxyChains..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y proxychains; then
            log $LOG_LEVEL_INFO "ProxyChains installed successfully." "$UPDATE_LOG_FILE"
            break
        else
            log $LOG_LEVEL_ERROR "Failed to install ProxyChains. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi

        if [ $attempts -eq $max_attempts ]; then
            log $LOG_LEVEL_ERROR "Failed to install ProxyChains after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
            exit 1
        fi
    done
else
    log $LOG_LEVEL_INFO "ProxyChains is already installed." "$UPDATE_LOG_FILE"
fi

# Check if the proxychains.conf file exists
log $LOG_LEVEL_INFO "Checking if the proxychains.conf file exists..." "$UPDATE_LOG_FILE"
if [ ! -f /etc/proxychains.conf ]; then
    log $LOG_LEVEL_INFO "Creating /etc/proxychains.conf file..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/proxychains.conf
# ProxyChains default configuration
# Dynamic chain
dynamic_chain

# Proxy DNS requests - no leak for DNS data
proxy_dns

[ProxyList]
# add proxy here ...
# defaults set to "tor"
socks4  127.0.0.1 9050
EOF
    log $LOG_LEVEL_INFO "ProxyChains configuration file created." "$UPDATE_LOG_FILE"
else
    log $LOG_LEVEL_INFO "ProxyChains configuration file already exists." "$UPDATE_LOG_FILE"
fi

# Check if required files and directories exist
required_files=(
    "$PROXYCHAINS_CONF"
    "/etc/systemd/system"
    "/usr/local/bin"
)

for file in "${required_files[@]}"; do
    if [ ! -e "$file" ]; then
        log $LOG_LEVEL_ERROR "Error: $file does not exist." "$UPDATE_LOG_FILE"
        exit 1
    fi
done

# Validate the proxy API URLs
validate_url "$PROXY_API_URL1" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL2" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL3" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL4" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL5" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL6" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL7" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL8" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL9" "$UPDATE_LOG_FILE"
validate_url "$PROXY_API_URL10" "$UPDATE_LOG_FILE"

# Configure ProxyChains
log $LOG_LEVEL_INFO "Configuring ProxyChains..." "$UPDATE_LOG_FILE"

# ProxyChains configuration file path
PROXYCHAINS_CONF="/etc/proxychains.conf"

# Check if ProxyChains is already configured for Tor
if grep -q "socks5  127.0.0.1 9050" "$PROXYCHAINS_CONF"; then
    log $LOG_LEVEL_INFO "ProxyChains is already configured for Tor." "$UPDATE_LOG_FILE"
else
    # Update ProxyChains configuration
    sed -i 's/^#dynamic_chain/dynamic_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^strict_chain/#strict_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^#proxy_dns/proxy_dns/' "$PROXYCHAINS_CONF"
    echo "socks5  127.0.0.1 9050" | tee -a "$PROXYCHAINS_CONF"
    log $LOG_LEVEL_INFO "ProxyChains configuration updated." "$UPDATE_LOG_FILE"
fi

# Create the ProxyChains configuration file
log $LOG_LEVEL_INFO "Appending fetched proxy list to ProxyChains configuration..." "$UPDATE_LOG_FILE"

# Append the fetched proxy list to the configuration file
echo "$PROXY_LIST" >> "$PROXYCHAINS_CONF"

log $LOG_LEVEL_INFO "ProxyChains configured successfully." "$UPDATE_LOG_FILE"

# Create a script to fetch and validate proxies
log $LOG_LEVEL_INFO "Creating script to fetch and validate proxies..." "$UPDATE_LOG_FILE"
cat << 'EOF' > /usr/local/bin/update_proxies.sh
#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Variables
PROXY_API_URL1="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"
PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
PROXY_API_URL3="https://spys.me/socks.txt"
PROXY_API_URL4="https://www.proxy-list.download/api/v1/get?type=socks5"
PROXY_API_URL5="https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5"
PROXY_API_URL6="https://www.freeproxy.world/api/proxy?protocol=socks5&limit=100"
PROXY_API_URL7="https://www.free-proxy-list.net/socks5.txt"
PROXY_API_URL8="https://www.proxynova.com/proxy-server-list/"
PROXY_API_URL9="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=elite"
PROXY_API_URL10="https://hidemy.name/en/proxy-list/?type=5&anon=234"
PROXYCHAINS_CONF="/etc/proxychains.conf"
SYSTEMD_UPDATE_PROXIES_SERVICE="/etc/systemd/system/update_proxies.service"
SYSTEMD_UPDATE_PROXIES_TIMER="/etc/systemd/system/update_proxies.timer"

# Function to fetch and validate proxies from a given API URL
fetch_and_validate_proxies() {
    local API_URL=$1
    local VALID_PROXY_COUNT=0
    local PROXY_LIST=$(curl -s $API_URL)

    echo "$PROXY_LIST" | while read -r PROXY; do
        IP=$(echo $PROXY | cut -d':' -f1)
        PORT=$(echo $PROXY | cut -d':' -f2)
        if nc -z $IP $PORT; then
            echo "Valid proxy found: $PROXY"
            echo "socks5  $IP $PORT" | tee -a "$PROXYCHAINS_CONF"
            VALID_PROXY_COUNT=$((VALID_PROXY_COUNT + 1))
            if [ $VALID_PROXY_COUNT -ge 5 ]; then
                break
            fi
        else
            echo "Invalid proxy: $PROXY"
        fi
    done

    echo "Added $VALID_PROXY_COUNT valid proxies from $API_URL."
}

# Function to check if a proxy is anonymous
is_anonymous_proxy() {
    local IP=$1
    local PORT=$2
    local RESPONSE=$(curl -s --proxy socks5://$IP:$PORT https://httpbin.org/ip)
    if echo "$RESPONSE" | grep -q "$IP"; then
        return 1 # Not anonymous
    else
        return 0 # Anonymous
    fi
}

# Function to check if a proxy is fast
is_fast_proxy() {
    local IP=$1
    local PORT=$2
    local RESPONSE_TIME=$(curl -o /dev/null -s -w "%{time_total}\n" --proxy socks5://$IP:$PORT https://httpbin.org/ip)
    if (( $(echo "$RESPONSE_TIME < 1.0" | bc -l) )); then
        return 0 # Fast proxy
    else
        return 1 # Slow proxy
    fi
}

# Fetch and validate proxies from each API
echo "Validating proxies and updating ProxyChains configuration..."
sed -i '/^socks5/d' "$PROXYCHAINS_CONF" # Remove existing SOCKS5 proxies

fetch_and_validate_proxies $PROXY_API_URL1
fetch_and_validate_proxies $PROXY_API_URL2
fetch_and_validate_proxies $PROXY_API_URL3
fetch_and_validate_proxies $PROXY_API_URL4
fetch_and_validate_proxies $PROXY_API_URL5
fetch_and_validate_proxies $PROXY_API_URL6
fetch_and_validate_proxies $PROXY_API_URL7
fetch_and_validate_proxies $PROXY_API_URL8
fetch_and_validate_proxies $PROXY_API_URL9
fetch_and_validate_proxies $PROXY_API_URL10

echo "ProxyChains configuration updated with valid proxies from all APIs."
EOF
chmod +x /usr/local/bin/update_proxies.sh

# Create a systemd service to run the proxy update script on startup
log $LOG_LEVEL_INFO "Creating systemd service to run the proxy update script on startup..." "$UPDATE_LOG_FILE"
cat << EOF > /etc/systemd/system/update_proxies.service
[Unit]
Description=Update Proxy List on Startup
After=network.target

[Service]
ExecStart=/usr/local/bin/update_proxies.sh
Type=oneshot
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
chmod +x /etc/systemd/system/update_proxies.service
systemctl daemon-reload
systemctl enable update_proxies.service
log $LOG_LEVEL_INFO "Systemd service created and enabled." "$UPDATE_LOG_FILE"

# Create a cron job to update proxies every 30 minutes
log $LOG_LEVEL_INFO "Creating cron job to update proxies every 30 minutes..." "$UPDATE_LOG_FILE"
echo "*/30 * * * * root /usr/local/bin/update_proxies.sh" | sudo tee -a /etc/crontab
log $LOG_LEVEL_INFO "Cron job created." "$UPDATE_LOG_FILE"

# Create a systemd timer to run the proxy update script every 30 minutes
log $LOG_LEVEL_INFO "Creating systemd timer to run the proxy update script every 30 minutes..." "$UPDATE_LOG_FILE"
cat << EOF > /etc/systemd/system/update_proxies.timer
[Unit]
Description=Run update_proxies.sh every 30 minutes

[Timer]
OnCalendar=*:0/30
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod +x /etc/systemd/system/update_proxies.timer
systemctl daemon-reload
systemctl enable update_proxies.timer
systemctl start update_proxies.timer
log $LOG_LEVEL_INFO "Systemd timer created and started." "$UPDATE_LOG_FILE"

# Documentation
mkdir -p /usr/local/share/khelp_proxychains
cat << 'EOF' > /usr/local/share/khelp_proxychains/README.md
EOF

# Documentation ProxyChains Configuration
mkdir -p "$KHELP_PROXYCHAINS_DIR"
cat << 'EOF' > "$KHELP_PROXYCHAINS_DIR/README.md"
# ProxyChains Configuration Documentation

## Overview
This section documents the process of ensuring ProxyChains is installed and properly configured. ProxyChains is a tool that allows you to redirect connections through proxy servers.

## Function Explanation
### Checking ProxyChains Installation
1. **Logging**: Logs the start of the process to check if ProxyChains is installed.
2. **Check Installation**: Uses the `command -v proxychains` command to check if ProxyChains is installed.
3. **Installation**: If ProxyChains is not installed, it attempts to install it up to three times using `apt install -y proxychains`.
4. **Logging Success**: Logs a message indicating the successful installation of ProxyChains.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.

### Configuring ProxyChains
1. **Logging**: Logs the start of the process to check if the `proxychains.conf` file exists.
2. **Check Configuration File**: Checks if the `/etc/proxychains.conf` file exists.
3. **Creating Configuration File**: If the configuration file does not exist, it creates the file with the default configuration.
4. **Logging Configuration**: Logs a message indicating the creation or existence of the `proxychains.conf` file.


# Proxy List Setup Documentation

## Overview
This section documents the process of ensuring ProxyChains is configured, fetching a list of proxies, and setting up systemd services and timers to keep the proxy list updated.

## Function Explanation
### Checking Required Files and Directories
1. **Logging**: Logs the start of the process to check if required files and directories exist.
2. **Check Existence**: Checks if the specified files and directories exist.
3. **Logging Failure**: Logs an error message if a required file or directory does not exist and exits with an error code.

### Ensuring ProxyChains Installation
1. **Logging**: Logs the start of the process to check if ProxyChains is installed.
2. **Check Installation**: Uses the `command -v proxychains` command to check if ProxyChains is installed.
3. **Installation**: If ProxyChains is not installed, it attempts to install it up to three times using `apt install -y proxychains`.
4. **Logging Success**: Logs a message indicating the successful installation of ProxyChains.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.

### Configuring ProxyChains
1. **Logging**: Logs the start of the process to configure ProxyChains.
2. **Check Configuration File**: Checks if the `/etc/proxychains.conf` file exists and creates it if it does not.
3. **Check and Update Configuration**: Checks if ProxyChains is already configured for Tor and updates the configuration if it is not.
4. **Appending Proxy List**: Appends the fetched proxy list to the `proxychains.conf` file.
5. **Logging Configuration**: Logs messages indicating the creation or update of the `proxychains.conf` file.

### Creating Proxy Fetching Script
1. **Logging**: Logs the start of the process to create a script for fetching and validating proxies.
2. **Script Creation**: Creates the script `/usr/local/bin/update_proxies.sh` to fetch and validate proxies from multiple API URLs.
3. **Logging Script Creation**: Logs a message indicating the creation of the proxy fetching script.

### Creating Systemd Service
1. **Logging**: Logs the start of the process to create a systemd service.
2. **Service Creation**: Creates the systemd service `/etc/systemd/system/update_proxies.service` to run the proxy update script on startup.
3. **Enabling Service**: Enables the systemd service.
4. **Logging Service Creation**: Logs a message indicating the creation and enabling of the systemd service.

### Creating Cron Job
1. **Logging**: Logs the start of the process to create a cron job.
2. **Cron Job Creation**: Creates a cron job to run the proxy update script every 30 minutes.
3. **Logging Cron Job Creation**: Logs a message indicating the creation of the cron job.

### Creating Systemd Timer
1. **Logging**: Logs the start of the process to create a systemd timer.
2. **Timer Creation**: Creates the systemd timer `/etc/systemd/system/update_proxies.timer` to run the proxy update script every 30 minutes.
3. **Enabling Timer**: Enables and starts the systemd timer.
4. **Logging Timer Creation**: Logs a message indicating the creation and starting of the systemd timer.
EOF

# Configure UFW
configure_ufw() {
    log $LOG_LEVEL_INFO "Configuring UFW firewall..." "$UPDATE_LOG_FILE"
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw logging on
    log $LOG_LEVEL_INFO "UFW firewall configured successfully." "$UPDATE_LOG_FILE"
}

# Create and enable UFW service
create_ufw_service() {
    log $LOG_LEVEL_INFO "Creating and enabling UFW service..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/ufw.sh
#!/bin/bash
systemctl enable ufw
systemctl start ufw
ufw --force enable
# Keep the script running to prevent the service from deactivating
while true; do sleep 60; done
EOF

    chmod +x /usr/local/bin/ufw.sh

    cat << EOF > /etc/systemd/system/ufw.service
[Unit]
Description=UFW service for startups
After=multi-user.target
Wants=multi-user.target

[Service]
Environment="USER_HOME=${USER_HOME}"
ExecStart=/usr/local/bin/ufw.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    chmod +x /etc/systemd/system/ufw.service
    
    systemctl daemon-reload
    systemctl enable ufw.service
    systemctl start ufw.service
    log $LOG_LEVEL_INFO "UFW service created and enabled." "$UPDATE_LOG_FILE"
}

configure_ufw
create_ufw_service

# Documentation UFW Configuration
mkdir -p "$KHELP_UFW_DIR"
cat << 'EOF' > "$KHELP_UFW_DIR/README.md"
# UFW Configuration Documentation

## Overview

This section documents the process of configuring UFW (Uncomplicated Firewall) and setting up a systemd service to ensure it runs on startup.

## Function Explanation

### Configuring UFW

1. **Logging**: Logs the start of the UFW configuration process.
2. **Enable UFW**: Uses `systemctl enable ufw` to enable UFW to start at boot.
3. **Force Enable UFW**: Uses `ufw --force enable` to enable UFW with force, ensuring no user interaction is required.
4. **Set Default Policies**: Sets the default policies to deny incoming traffic and allow outgoing traffic.
5. **Allow SSH**: Configures UFW to allow SSH connections.
6. **Enable Logging**: Enables logging for UFW.
7. **Logging Success**: Logs a message indicating the successful configuration of UFW.

### Creating and Enabling UFW Service

1. **Logging**: Logs the start of the process to create and enable the UFW service.
2. **Create Script**: Creates a script `/usr/local/bin/ufw.sh` to enable and start UFW, and keep the script running to prevent the service from deactivating.
3. **Make Script Executable**: Sets the script as executable.
4. **Create Service File**: Creates a systemd service file `/etc/systemd/system/ufw.service` to run the UFW script on startup.
5. **Make Service File Executable**: Sets the service file as executable.
6. **Reload Systemd**: Reloads the systemd daemon to recognize the new service.
7. **Enable Service**: Enables the UFW service to start at boot.
8. **Start Service**: Starts the UFW service.
9. **Logging Success**: Logs a message indicating the successful creation and enabling of the UFW service.
EOF

# Configure Fail2ban with retry mechanism
configure_fail2ban() {
    log $LOG_LEVEL_INFO "Configuring Fail2ban..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y fail2ban; then
            log $LOG_LEVEL_INFO "Fail2ban installed successfully." "$UPDATE_LOG_FILE"
            break
        else
            log $LOG_LEVEL_ERROR "Failed to install Fail2ban. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    if [ $attempts -eq $max_attempts ]; then
        log $LOG_LEVEL_ERROR "Failed to install Fail2ban after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
        exit 1
    fi

    # Create a Fail2ban configuration
    cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 3600
findtime  = 600
maxretry = 3

[sshd]
enabled = true

[sshd-ddos]
enabled = true
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    if systemctl is-active --quiet fail2ban; then
        log $LOG_LEVEL_INFO "Fail2ban configured and started successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to start Fail2ban." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

configure_fail2ban

# Documentation Fail2ban Configuration
mkdir -p "$KHELP_FAIL2BAN_DIR"
cat << 'EOF' > "$KHELP_FAIL2BAN_DIR/README.md"
# Fail2ban Configuration Documentation

## Overview

This section documents the process of configuring Fail2ban, a tool used to protect servers from brute-force attacks by banning IP addresses that show malicious signs.

## Function Explanation

### Configuring Fail2ban

1. **Logging**: Logs the start of the Fail2ban configuration process with an informational log level.
2. **Retry Mechanism**: Attempts to install Fail2ban up to three times in case of failures.
3. **Installation**: Uses `apt install -y fail2ban` to install Fail2ban.
4. **Logging Success**: Logs a message indicating the successful installation of Fail2ban.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.

### Fail2ban Configuration

1. **Create Configuration File**: Creates the `/etc/fail2ban/jail.local` configuration file with the following settings:
   - `ignoreip`: Specifies IP addresses to ignore.
   - `bantime`: Duration for which the IP is banned.
   - `findtime`: Time window for detecting failures.
   - `maxretry`: Maximum number of retries before banning.
   - `[sshd]` and `[sshd-ddos]`: Enables protection for SSH and SSHD-DDoS.

### Enabling and Starting Fail2ban

1. **Enable Fail2ban**: Uses `systemctl enable fail2ban` to enable Fail2ban to start at boot.
2. **Start Fail2ban**: Uses `systemctl start fail2ban` to start Fail2ban.
3. **Check Status**: Checks if Fail2ban is active using `systemctl is-active --quiet fail2ban`.
4. **Logging Success**: Logs a message indicating the successful configuration and start of Fail2ban.
5. **Logging Failure**: Logs an error message if Fail2ban fails to start and exits with an error code.
EOF

# Ensure the /etc/iptables directory exists
mkdir -p /etc/iptables

# Configure iptables
configure_iptables() {
    log $LOG_LEVEL_INFO "Configuring iptables..." "$UPDATE_LOG_FILE"
    
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    
    if iptables-save > /etc/iptables/rules.v4; then
        log $LOG_LEVEL_INFO "iptables rules configured successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to save iptables rules." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Debugging: After iptables setup
log_iptables_rules() {
    log $LOG_LEVEL_INFO "After iptables setup" "$UPDATE_LOG_FILE"
    iptables -L -v | tee -a /var/log/iptables_script.log
}

# Create and enable iptables service
create_iptables_service() {
    log $LOG_LEVEL_INFO "Creating and enabling iptables service..." "$UPDATE_LOG_FILE"
    
    cat << 'EOF' > /usr/local/bin/iptables.sh
#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
EOF

chmod +x /usr/local/bin/iptables.sh

cat << EOF > /etc/systemd/system/iptables.service
[Unit]
Description=iptables service for startups
After=network.target

[Service]
ExecStart=/usr/local/bin/iptables.sh
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

chmod +x /etc/systemd/system/iptables.service
    
    systemctl daemon-reload
    if systemctl enable iptables.service && systemctl start iptables.service; then
        log $LOG_LEVEL_INFO "iptables service created and enabled." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to create and enable iptables service." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

configure_iptables
log_iptables_rules
create_iptables_service

# Documentation iptables Configuration
mkdir -p "$KHELP_IPTABLES_DIR"
cat << 'EOF' > "$KHELP_IPTABLES_DIR/README.md"
# iptables Configuration Documentation

## Overview

This section documents the process of configuring iptables, a utility for configuring Linux kernel firewall, and setting up a systemd service to ensure the iptables rules are applied on startup.

## Function Explanation

### Ensuring iptables Directory

1. **Directory Creation**: Ensures the `/etc/iptables` directory exists using `mkdir -p /etc/iptables`.

### Configuring iptables

1. **Logging**: Logs the start of the iptables configuration process with an informational log level.
2. **Flush Rules**: Uses `iptables -F` to flush all current rules and `iptables -X` to delete all user-defined chains.
3. **Set Default Policies**: Sets the default policies to drop all incoming and forwarded traffic, and to accept all outgoing traffic.
4. **Allow Loopback and Established Connections**: Configures rules to allow loopback traffic and established or related connections.
5. **Allow SSH and ICMP**: Configures rules to allow SSH connections on port 22 and ICMP (ping) traffic.
6. **Save Rules**: Saves the iptables rules to `/etc/iptables/rules.v4`.
7. **Logging Success**: Logs a message indicating the successful configuration of iptables.
8. **Logging Failure**: Logs an error message if the rules fail to save and exits with an error code.

### Debugging iptables Setup

1. **Logging**: Logs the current iptables rules after setup for debugging purposes.
2. **List Rules**: Uses `iptables -L -v` to list the current rules and appends the output to `/var/log/iptables_script.log`.

### Creating and Enabling iptables Service

1. **Logging**: Logs the start of the process to create and enable the iptables service.
2. **Create Script**: Creates a script `/usr/local/bin/iptables.sh` to restore iptables rules from `/etc/iptables/rules.v4`.
3. **Make Script Executable**: Sets the script as executable.
4. **Create Service File**: Creates a systemd service file `/etc/systemd/system/iptables.service` to run the iptables restoration script on startup.
5. **Make Service File Executable**: Sets the service file as executable.
6. **Reload Systemd**: Reloads the systemd daemon to recognize the new service.
7. **Enable and Start Service**: Enables and starts the iptables service.
8. **Logging Success**: Logs a message indicating the successful creation and enabling of the iptables service.
9. **Logging Failure**: Logs an error message if the service fails to enable or start and exits with an error code.
EOF

# Configure and enable Tor with retry mechanism
configure_tor() {
    log $LOG_LEVEL_INFO "Configuring and enabling Tor..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y tor; then
            log $LOG_LEVEL_INFO "Tor installed successfully." "$UPDATE_LOG_FILE"
            break
        else
            log $LOG_LEVEL_ERROR "Failed to install Tor. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    if [ $attempts -eq $max_attempts ]; then
        log $LOG_LEVEL_ERROR "Failed to install Tor after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
        exit 1
    fi

    # Enable and start the Tor service
    if systemctl enable tor && systemctl start tor; then
        log $LOG_LEVEL_INFO "Tor configured and enabled successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to enable and start Tor service." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

configure_tor

# Documentation Tor Configuration
mkdir -p "$KHELP_TOR_DIR"
cat << 'EOF' > "$KHELP_TOR_DIR/README.md"
# Tor Configuration Documentation

## Overview

This section documents the process of configuring and enabling Tor, a software that enables anonymous communication, with a retry mechanism to handle potential installation issues.

## Function Explanation

### Configuring and Enabling Tor

1. **Logging**: Logs the start of the Tor configuration process with an informational log level.
2. **Retry Mechanism**: Attempts to install Tor up to three times in case of failures.
3. **Installation**: Uses `apt install -y tor` to install Tor.
4. **Logging Success**: Logs a message indicating the successful installation of Tor.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.
6. **Enable and Start Tor Service**: Uses `systemctl enable tor` and `systemctl start tor` to enable and start the Tor service.
7. **Logging Service Success**: Logs a message indicating the successful configuration and enabling of the Tor service.
8. **Logging Service Failure**: Logs an error message if the Tor service fails to enable or start and exits with an error code.
EOF

# Function to set Terminator as the default terminal for GNOME
set_gnome_default_terminal() {
    log $LOG_LEVEL_INFO "Setting Terminator as the default terminal for GNOME..." "$UPDATE_LOG_FILE"
    if gsettings set org.gnome.desktop.default-applications.terminal exec 'terminator' && \
       gsettings set org.gnome.desktop.default-applications.terminal exec-arg '-x'; then
        log $LOG_LEVEL_INFO "Terminator set as default terminal for GNOME." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to set Terminator as default terminal for GNOME." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Function to set Terminator as the default terminal for KDE Plasma
set_kde_default_terminal() {
    log $LOG_LEVEL_INFO "Setting Terminator as the default terminal for KDE Plasma..." "$UPDATE_LOG_FILE"
    if kwriteconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication 'terminator'; then
        log $LOG_LEVEL_INFO "Terminator set as default terminal for KDE Plasma." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to set Terminator as default terminal for KDE Plasma." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Function to set Terminator as the default terminal for XFCE
set_xfce_default_terminal() {
    log $LOG_LEVEL_INFO "Setting Terminator as the default terminal for XFCE..." "$UPDATE_LOG_FILE"
    if xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set 'terminator' && \
       xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set '--login'; then
        log $LOG_LEVEL_INFO "Terminator set as default terminal for XFCE." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to set Terminator as default terminal for XFCE." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

# Function to check the current default terminal and change it to Terminator if needed
check_and_set_default_terminal() {
    case "$XDG_CURRENT_DESKTOP" in
        GNOME)
            current_terminal=$(gsettings get org.gnome.desktop.default-applications.terminal exec)
            if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
                log $LOG_LEVEL_INFO "Current terminal is $current_terminal. Changing to Terminator for GNOME..." "$UPDATE_LOG_FILE"
                set_gnome_default_terminal
            else
                log $LOG_LEVEL_INFO "Current terminal is already set to Terminator for GNOME." "$UPDATE_LOG_FILE"
            fi
            ;;
        KDE)
            current_terminal=$(kreadconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication)
            if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
                log $LOG_LEVEL_INFO "Current terminal is $current_terminal. Changing to Terminator for KDE..." "$UPDATE_LOG_FILE"
                set_kde_default_terminal
            else
                log $LOG_LEVEL_INFO "Current terminal is already set to Terminator for KDE." "$UPDATE_LOG_FILE"
            fi
            ;;
        XFCE)
            current_terminal=$(xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command)
            if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
                log $LOG_LEVEL_INFO "Current terminal is $current_terminal. Changing to Terminator for XFCE..." "$UPDATE_LOG_FILE"
                set_xfce_default_terminal
            else
                log $LOG_LEVEL_INFO "Current terminal is already set to Terminator for XFCE." "$UPDATE_LOG_FILE"
            fi
            ;;
        *)
            log $LOG_LEVEL_ERROR "Unsupported desktop environment: $XDG_CURRENT_DESKTOP" "$UPDATE_LOG_FILE"
            log $LOG_LEVEL_ERROR "Supported environments: GNOME, KDE, XFCE" "$UPDATE_LOG_FILE"
            exit 1
            ;;
    esac
}

# Run the check and set default terminal function
check_and_set_default_terminal

# Documentation Default Terminal Configuration
mkdir -p "$KHELP_DEFAULT_TERMINAL_DIR"
cat << 'EOF' > "$KHELP_DEFAULT_TERMINAL_DIR/README.md"
# Setting Terminator as Default Terminal Documentation

## Overview

This section documents the process of setting Terminator as the default terminal emulator for various desktop environments, including GNOME, KDE Plasma, and XFCE. The script includes functions to configure the default terminal and a function to check the current default terminal and update it if necessary.

## Function Explanation

### Setting Terminator as Default Terminal for GNOME

1. **Logging**: Logs the start of the process to set Terminator as the default terminal for GNOME.
2. **Set Default Terminal**: Uses `gsettings` to set Terminator as the default terminal.
3. **Logging Success**: Logs a message indicating the successful configuration of Terminator as the default terminal.
4. **Logging Failure**: Logs an error message if the configuration fails and exits with an error code.

### Setting Terminator as Default Terminal for KDE Plasma

1. **Logging**: Logs the start of the process to set Terminator as the default terminal for KDE Plasma.
2. **Set Default Terminal**: Uses `kwriteconfig5` to set Terminator as the default terminal.
3. **Logging Success**: Logs a message indicating the successful configuration of Terminator as the default terminal.
4. **Logging Failure**: Logs an error message if the configuration fails and exits with an error code.

### Setting Terminator as Default Terminal for XFCE

1. **Logging**: Logs the start of the process to set Terminator as the default terminal for XFCE.
2. **Set Default Terminal**: Uses `xfconf-query` to set Terminator as the default terminal.
3. **Logging Success**: Logs a message indicating the successful configuration of Terminator as the default terminal.
4. **Logging Failure**: Logs an error message if the configuration fails and exits with an error code.

### Checking and Setting Default Terminal

1. **Logging**: Logs the current default terminal.
2. **Check Current Terminal**: Checks the current default terminal for the detected desktop environment using appropriate commands (`gsettings`, `kreadconfig5`, or `xfconf-query`).
3. **Set Default Terminal**: If the current terminal is not Terminator, it calls the respective function to set Terminator as the default terminal.
4. **Unsupported Desktop Environment**: Logs an error message and exits if the desktop environment is unsupported.
EOF

# Create the startup script
log $LOG_LEVEL_INFO "Creating the startup script..." "$UPDATE_LOG_FILE"
cat << 'EOF' > "$STARTUP_SCRIPT_PATH"
#!/bin/bash

# Function to wait until a specific service is active
wait_for_service() {
    local service_name=$1
    local max_attempts=3
    local attempt=1

    while ! systemctl is-active --quiet "$service_name"; do
        if [ $attempt -gt $max_attempts ]; then
            echo "Service $service_name did not start within the expected time."
            return 1
        fi
        echo "Waiting for $service_name to start... (attempt $attempt)"
        sleep 5
        attempt=$((attempt + 1))
    done
    echo "Service $service_name is active."
}

# Wait for specific services to be active
wait_for_service ufw
wait_for_service tor

echo "Running startup commands to show changes of the post-installer and service."
echo ""

uname -a
ip link show
sudo ufw status
traceroute www.showmyip.com
EOF
chmod +x "$STARTUP_SCRIPT_PATH"

# Create the desktop entry
log $LOG_LEVEL_INFO "Creating the desktop entry..." "$UPDATE_LOG_FILE"
mkdir -p "$USER_HOME/.config/autostart"
cat << EOF > "$DESKTOP_ENTRY_PATH"
[Desktop Entry]
Type=Application
Exec=terminator -e "bash -c '$STARTUP_SCRIPT_PATH; exec bash'"
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name[en_US]=Startup Terminal
Name=Startup Terminal
Comment[en_US]=Run a script in terminal at startup
Comment=Run a script in terminal at startup
EOF
chmod +x "$DESKTOP_ENTRY_PATH"

log $LOG_LEVEL_INFO "Startup verification script and desktop entry created successfully." "$UPDATE_LOG_FILE"

# Documentation Startup Verification
mkdir -p "$KHELP_STARTUP_VERIFICATION_DIR"
cat << 'EOF' > "$KHELP_STARTUP_VERIFICATION_DIR/README.md"
# Startup Script and Desktop Entry Documentation for Verifycation

## Overview

This section documents the process of creating a startup script and a desktop entry to run the script at startup. The script ensures that specific services are active before executing additional commands.

## Function Explanation

### Creating the Startup Script

1. **Logging**: Logs the start of the process to create the startup script with an informational log level.
2. **Script Creation**: Creates a script at the specified `STARTUP_SCRIPT_PATH` with the following functionalities:
   - **Wait for Service**: A function `wait_for_service` waits until a specified service is active, retrying up to three times.
   - **Wait for Specific Services**: Waits for `ufw` and `tor` services to be active.
   - **Run Commands**: Runs commands to show system information and the status of the services.
3. **Make Script Executable**: Sets the script as executable.

### Creating the Desktop Entry

1. **Logging**: Logs the start of the process to create the desktop entry with an informational log level.
2. **Desktop Entry Creation**: Creates a desktop entry at the specified `DESKTOP_ENTRY_PATH` with the following properties:
   - **Type**: Set to `Application`.
   - **Exec**: Runs the startup script in a Terminator terminal.
   - **Autostart**: Enables the desktop entry to run at startup.
   - **Name and Comment**: Provides a name and comment for the desktop entry.
3. **Make Desktop Entry Executable**: Sets the desktop entry as executable.
EOF

# Summary and Reboot
log $LOG_LEVEL_INFO "" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "khelp is done! Everything is looking good!" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "khelp setups a Tor / Proxy Routing by fetching proxies from 10 APIs" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "After reboot it will provide a window with the status of all changes." "$UPDATE_LOG_FILE"

display_logo

log $LOG_LEVEL_INFO "Rebooting the system to apply changes in 1 minute..." "$UPDATE_LOG_FILE"
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log $LOG_LEVEL_INFO "Cancelling the reboot..." "$UPDATE_LOG_FILE"
    shutdown -c
else
    log $LOG_LEVEL_INFO "Reboot will proceed in 1 minute." "$UPDATE_LOG_FILE"
fi
