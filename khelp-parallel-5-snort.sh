#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Define the display_logo function
display_logo() {                                                                                                      
echo " _    _          _       "   
echo "| | _| |__   ___| |_ __  "  
echo "| |/ / '_ \ / _ \ | '_ \ " 
echo "|   <| | | |  __/ | |_) |"
echo "|_|\_\_| |_|\___|_| .__/ "
echo "                  |_|    "
}

# Call the display_logo function
display_logo

# Set USER_HOME based on whether the script is run with sudo or not
if [ -n "$SUDO_USER" ]; then
    export USER_HOME=$(eval echo ~${SUDO_USER})
else
    export USER_HOME=$HOME
fi

# Environment variables for paths and configurations
export UPDATE_LOG_FILE="/var/log/khelp.log"
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
export HOGEN_LOG_FILE=${HOGEN_LOG_FILE:-"/var/log/khelp_hogen.log"}
export HOGEN_SCRIPT_PATH=${HOGEN_SCRIPT_PATH:-"/usr/local/bin/hogen.sh"}
export HOGEN_SERVICE_PATH=${HOGEN_SERVICE_PATH:-"/etc/systemd/system/hogen.service"}
export HOGEN_DOC_DIR=${HOGEN_DOC_DIR:-"/usr/local/share/khelp_hogen"}
export HOGEN_DOC_FILE="$HOGEN_DOC_DIR/README.md"
export MSPOO_LOG_FILE=${MSPOO_LOG_FILE:-"/var/log/khelp_mspoo.log"}
export MSPOO_SCRIPT_PATH=${MSPOO_SCRIPT_PATH:-"/usr/local/bin/mspoo.sh"}
export MSPOO_SERVICE_PATH=${MSPOO_SERVICE_PATH:-"/etc/systemd/system/mspoo.service"}
export MSPOO_DOC_DIR=${MSPOO_DOC_DIR:-"/usr/local/share/khelp_mspoof"}
export MSPOO_DOC_FILE="$MSPOO_DOC_DIR/README.md"
export SNORT_CONF="/etc/snort/snort.conf"
export SNORT_RULES_DIR="/etc/snort/rules"
export SNORT_LOG_DIR="/var/log/snort"
export SNORT_SERVICE="/etc/systemd/system/snort.service"
export SNORT_DOC_DIR=${SNORT_DOC_DIR:-"/usr/local/share/khelp_snort"}
export SNORT_DOC_FILE="$SNORT_DOC_DIR/README.md"

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

# Improved URL validation function
validate_url() {
    local url="$1"
    local log_file="$2"
    
    if [[ ! $url =~ ^https?://.*$ ]]; then
        log $LOG_LEVEL_ERROR "Invalid URL: $url" "$log_file"
        exit 1
    fi
}

# Example usage of the log function for different tasks

# Task 1: Proxy
log $LOG_LEVEL_INFO "Starting Proxy task" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "Proxy task completed successfully" "$UPDATE_LOG_FILE"

# Task 2: Hogen
log $LOG_LEVEL_INFO "Starting Hogen task" "$HOGEN_LOG_FILE"
log $LOG_LEVEL_INFO "Hogen task completed successfully" "$HOGEN_LOG_FILE"

# Task 3: MSPoo
log $LOG_LEVEL_INFO "Starting MSPoo task" "$MSPOO_LOG_FILE"
log $LOG_LEVEL_INFO "MSPoo task completed successfully" "$MSPOO_LOG_FILE"

# Debugging: Print environment variables
log $LOG_LEVEL_INFO "USER_HOME=$USER_HOME" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UPDATE_LOG_FILE=$UPDATE_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_UPDATE_DIR=$KHELP_UPDATE_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_INSTALLER_DIR=$KHELP_INSTALLER_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXYCHAINS_CONF=$PROXYCHAINS_CONF" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL1=$PROXY_API_URL1" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL2=$PROXY_API_URL2" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL3=$PROXY_API_URL3" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL4=$PROXY_API_URL4" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL5=$PROXY_API_URL5" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL6=$PROXY_API_URL6" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL7=$PROXY_API_URL7" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL8=$PROXY_API_URL8" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL9=$PROXY_API_URL9" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL10=$PROXY_API_URL10" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_PROXYCHAINS_DIR=$KHELP_PROXYCHAINS_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UPDATE_PROXIES_SCRIPT=$UPDATE_PROXIES_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_SERVICE=$SYSTEMD_UPDATE_PROXIES_SERVICE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_TIMER=$SYSTEMD_UPDATE_PROXIES_TIMER" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "CRONTAB_FILE=$CRONTAB_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_UFW_DIR=$KHELP_UFW_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UFW_SCRIPT=$UFW_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UFW_SERVICE=$UFW_SERVICE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_FAIL2BAN_DIR=$KHELP_FAIL2BAN_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "FAIL2BAN_CONFIG=$FAIL2BAN_CONFIG" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_RULES_FILE=$IPTABLES_RULES_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_SCRIPT=$IPTABLES_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_SERVICE=$IPTABLES_SERVICE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_IPTABLES_DIR=$KHELP_IPTABLES_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_TOR_DIR=$KHELP_TOR_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_TERMINATOR_DIR=$KHELP_TERMINATOR_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_VERIFY_DIR=$KHELP_VERIFY_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "HOGEN_LOG_FILE=$HOGEN_LOG_FILE" "$HOGEN_LOG_FILE"
log $LOG_LEVEL_INFO "MSPOO_LOG_FILE=$MSPOO_LOG_FILE" "$MSPOO_LOG_FILE"
log $LOG_LEVEL_INFO "SNORT_CONF=$SNORT_CONF" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SNORT_RULES_DIR=$SNORT_RULES_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SNORT_LOG_DIR=$SNORT_LOG_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SNORT_SERVICE=$SNORT_SERVICE" "$UPDATE_LOG_FILE"

# Example usage of the log function
log $LOG_LEVEL_INFO "This is an informational message." "$UPDATE_LOG_FILE"
log $LOG_LEVEL_ERROR "This is an error message." "$UPDATE_LOG_FILE"
log $LOG_LEVEL_WARNING "This is a warning message." "$UPDATE_LOG_FILE"

# Function to detect the local network IP range
detect_ip_range() {
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    IP_PREFIX=$(echo $LOCAL_IP | cut -d. -f1-3)
    ALLOWED_IP_RANGE="$IP_PREFIX.0/24"
}

# Detect local network IP range
detect_ip_range

# Function to determine the primary network interface
get_primary_interface() {
    ip route | grep default | awk '{print $5}'
}

# Update the system
update_system() {
    log $LOG_LEVEL_INFO "Updating and upgrading system" "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt update && apt full-upgrade -y && apt autoremove -y && apt autoclean; then
            log $LOG_LEVEL_INFO "System update and upgrade completed." "$UPDATE_LOG_FILE"
            return 0
        else
            log $LOG_LEVEL_ERROR "System update and upgrade failed. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "System update and upgrade failed after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    exit 1
}

# Example usage of the updated function
update_system

# Determine the primary network interface
PRIMARY_INTERFACE=$(get_primary_interface)

# Export the primary interface
export PRIMARY_INTERFACE

# Main script execution
log $LOG_LEVEL_INFO "Starting khelp setup..." "$UPDATE_LOG_FILE"

# Define functions for independent tasks
install_packages() {
    log $LOG_LEVEL_INFO "Installing tools and packages." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3
    local packages="ufw tor curl jq iptables fail2ban sslh terminator proxychains snort"

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

# Function to install code-oss
install_code_oss() {
    # Add the Microsoft GPG key
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
    sudo install -o root -g root -m 644 packages.microsoft.gpg /usr/share/keyrings/
    rm -f packages.microsoft.gpg

    # Add the code-oss repository
    sudo sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] http://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/code-oss.list'

    # Update the package list
    sudo apt update

    # Install code-oss
    sudo apt install -y code-oss

    echo "code-oss installation completed."
}

# Call the function to install code-oss
install_code_oss

# Create a backup directory with a timestamp
BACKUP_DIR="/backup/configs_$(date +'%Y%m%d%H%M%S')"
mkdir -p "$BACKUP_DIR"

# Function to backup a configuration file
backup_config() {
    local config_file="$1"
    local backup_file="$BACKUP_DIR/$(basename $config_file)"
    if [ -f "$config_file" ]; then
        cp "$config_file" "$backup_file"
        log "INFO" "Backed up $config_file to $backup_file"
    else
        log "WARNING" "Configuration file $config_file not found, skipping backup"
    fi
}

# Backup configurations
log "INFO" "Backing up configuration files..."
backup_config "/etc/proxychains.conf"
backup_config "/etc/ufw/ufw.conf"
backup_config "/etc/iptables/rules.v4"
backup_config "/etc/snort/snort.conf"
backup_config "/etc/fail2ban/jail.local"
backup_config "/etc/sslh/sslh.cfg"

configure_ufw() {
    log $LOG_LEVEL_INFO "Configuring UFW firewall..." "$UPDATE_LOG_FILE"
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow from $ALLOWED_IP_RANGE to any port 22  # Restrict SSH access
    ufw limit ssh/tcp  # Rate limit SSH
    ufw logging on
    log $LOG_LEVEL_INFO "UFW firewall configured successfully." "$UPDATE_LOG_FILE"
}

configure_fail2ban() {
    log $LOG_LEVEL_INFO "Configuring Fail2ban..." "$UPDATE_LOG_FILE"
    apt install -y fail2ban
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
    log $LOG_LEVEL_INFO "Fail2ban configured and started successfully." "$UPDATE_LOG_FILE"
}

configure_iptables() {
    log $LOG_LEVEL_INFO "Configuring iptables..." "$UPDATE_LOG_FILE"
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp -s $ALLOWED_IP_RANGE --dport 22 -j ACCEPT  # Restrict SSH access
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP  # Rate limit SSH
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP  # Drop invalid packets
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -N LOGGING
    iptables -A INPUT -j LOGGING
    iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables: " --log-level 4
    iptables -A LOGGING -j DROP
    iptables-save > /etc/iptables/rules.v4
    log $LOG_LEVEL_INFO "iptables rules configured successfully." "$UPDATE_LOG_FILE"
}

configure_tor() {
    log $LOG_LEVEL_INFO "Configuring and enabling Tor..." "$UPDATE_LOG_FILE"
    apt install -y tor
    systemctl enable tor
    systemctl start tor
    log $LOG_LEVEL_INFO "Tor configured and enabled successfully." "$UPDATE_LOG_FILE"
}

configure_proxychains() {
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
}

configure_snort() {
    log $LOG_LEVEL_INFO "Configuring Snort..." "$UPDATE_LOG_FILE"
    
    # Create necessary directories
    mkdir -p $SNORT_RULES_DIR
    mkdir -p $SNORT_LOG_DIR

    log $LOG_LEVEL_INFO "Creating snort rules..." "$UPDATE_LOG_FILE"
    cat << EOF > $SNORT_RULES_DIR/local.rules
# Custom rules for detecting specific types of traffic and threats
alert tcp \$EXTERNAL_NET any -> \$HOME_NET 22 (msg:"SSH connection attempt"; sid:1000001; rev:1;)
alert tcp \$EXTERNAL_NET any -> \$HOME_NET 80 (msg:"HTTP connection attempt"; sid:1000002; rev:1;)
alert tcp \$HOME_NET 80 -> \$EXTERNAL_NET any (msg:"HTTP response"; sid:1000003; rev:1;)
alert icmp \$EXTERNAL_NET any -> \$HOME_NET any (msg:"ICMP packet"; sid:1000004; rev:1;)
EOF
}

# Execute independent tasks in parallel
install_packages &
install_code_oss &
configure_ufw &
configure_fail2ban &
configure_iptables &
configure_tor &
configure_proxychains &
configure_snort &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All independent tasks completed successfully." "$UPDATE_LOG_FILE"

# Function to create the UFW script
create_ufw_script() {
    log $LOG_LEVEL_INFO "Creating UFW script..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/ufw.sh
#!/bin/bash
systemctl enable ufw
systemctl start ufw
ufw --force enable
# Keep the script running to prevent the service from deactivating
while true; do sleep 60; done
EOF
    chmod +x /usr/local/bin/ufw.sh
    log $LOG_LEVEL_INFO "UFW script created successfully." "$UPDATE_LOG_FILE"
}

# Function to create the iptables script
create_iptables_script() {
    log $LOG_LEVEL_INFO "Creating iptables script..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/iptables.sh
#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
EOF
    chmod +x /usr/local/bin/iptables.sh
    log $LOG_LEVEL_INFO "iptables script created successfully." "$UPDATE_LOG_FILE"
}

# Function to create the hogen script
create_hogen_script() {
    log $LOG_LEVEL_INFO "Creating hostname generator script..." "$HOGEN_LOG_FILE"
    cat << 'EOF' > "$HOGEN_SCRIPT_PATH"
#!/bin/bash

# Lock file location
LOCKFILE="/var/run/hogen.lock"

# Function to log messages
log() {
    local message="$1"
    local log_file="/var/log/hogen.log"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')

    # Ensure the log file exists
    touch $log_file

    # Append the log message with a timestamp
    echo "$timestamp $message" >> $log_file
}

# Function to fetch a random name from the Random User Generator API
fetch_random_name() {
    local api_url="https://randomuser.me/api/"
    local response=$(curl -s $api_url)
    
    if [ -z "$response" ]; then
        log "Failed to fetch data from the API."
        exit 1
    fi

    local first_name=$(echo $response | jq -r '.results[0].name.first')
    local last_name=$(echo $response | jq -r '.results[0].name.last')
    
    if [ -z "$first_name" ] || [ -z "$last_name" ]; then
        log "Failed to extract names from the API response."
        exit 1
    fi

    # Capitalize the first letter of the first name and last name
    first_name=$(echo $first_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    last_name=$(echo $last_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    local name="${first_name}${last_name}"
    
    echo $name
}

# Check if another instance of the script is running
if [ -e $LOCKFILE ]; then
    log "Another instance of the script is already running. Exiting."
    exit 1
fi

# Create the lock file
touch $LOCKFILE

# Fetch and set the new hostname
newhn=$(fetch_random_name)
if [ $? -ne 0 ]; then
    log "Failed to fetch random name."
    rm -f $LOCKFILE
    exit 1
fi

log "Fetched random name: $newhn"

if hostnamectl set-hostname "$newhn"; then
    log "Hostname set to $newhn"
else
    log "Failed to set hostname to $newhn"
    rm -f $LOCKFILE
    exit 1
fi

# Ensure /etc/hosts has the correct entries
update_hosts_file() {
    local entry="$1"
    if ! grep -q "$entry" /etc/hosts; then
        echo "$entry" >> /etc/hosts
        if [ $? -eq 0 ]; then
            log "Added $entry to /etc/hosts"
        else
            log "Failed to add $entry to /etc/hosts"
            return 1
        fi
    fi
}

update_hosts_file "127.0.0.1    localhost"
update_hosts_file "127.0.0.1    $newhn"

# Ensure the current hostname is also mapped correctly
current_hostname=$(hostname)
update_hosts_file "127.0.0.1    $current_hostname"

log "Hostname set to $newhn and /etc/hosts updated"

# Remove the lock file
rm -f $LOCKFILE
EOF
    chmod +x "$HOGEN_SCRIPT_PATH"
    log $LOG_LEVEL_INFO "Hostname generator script created successfully." "$HOGEN_LOG_FILE"
}

# Function to create the MAC spoofing script
create_mspoo_script() {
    log $LOG_LEVEL_INFO "Creating MAC spoofing script..." "$MSPOO_LOG_FILE"
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
    chmod +x "$MSPOO_SCRIPT_PATH"
    log $LOG_LEVEL_INFO "MAC spoofing script created successfully." "$MSPOO_LOG_FILE"
}

# Create the startup script
create_startup_script() {
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
sudo ufw status verbose
traceroute www.showmyip.com
EOF
    chmod +x "$STARTUP_SCRIPT_PATH"
    log $LOG_LEVEL_INFO "Startup script created successfully." "$UPDATE_LOG_FILE"
}

# Create the desktop entry
create_desktop_entry() {
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
    log $LOG_LEVEL_INFO "Desktop entry created successfully." "$UPDATE_LOG_FILE"
}

# Create a sample Snort configuration file
create_snort_script() {
    log $LOG_LEVEL_INFO "Creating snort script..." "$UPDATE_LOG_FILE"
    cat << EOF > "$SNORT_CONF"
# Define network variables
var HOME_NET $ALLOWED_IP_RANGE
var EXTERNAL_NET any

# Preprocessor configurations
preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy windows, detect_anomalies, require_3whs 180, overlap_limit 10, small_segments 3 bytes 150, timeout 180
preprocessor stream5_udp: timeout 180
preprocessor stream5_icmp: timeout 180

preprocessor http_inspect: global iis_unicode_map unicode.map 1252
preprocessor http_inspect_server: server default profile all ports { 80 8080 8180 } oversize_dir_length 500

preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10

preprocessor stream5_ssh: max_sessions 256

preprocessor dcerpc2: memcap 102400, events [co]

preprocessor dns: ports { 53 } enable_rdata_overflow no enable_rdata_txt_overflow no enable_rdata_type_overflow no

preprocessor ssl: noinspect_encrypted

# Include rule sets
include \$RULE_PATH/local.rules
include \$RULE_PATH/community.rules

# Output modules
output alert_fast: stdout
output log_tcpdump: $SNORT_LOG_DIR/snort.log

# Path to rule files
var RULE_PATH $SNORT_RULES_DIR

# Path to dynamic preprocessor libraries
dynamicpreprocessor directory /usr/local/lib/snort_dynamicpreprocessor/
dynamicengine /usr/local/lib/snort_dynamicengine/libsf_engine.so
dynamicdetection directory /usr/local/lib/snort_dynamicrules/

# Customize and add your rules
include \$RULE_PATH/snort.rules
EOF
}

# Execute script creation tasks in parallel
create_ufw_script &
create_iptables_script &
create_hogen_script &
create_mspoo_script &
create_startup_script &
create_desktop_entry &
create_snort_script &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All script creation tasks completed successfully." "$UPDATE_LOG_FILE"

# Main script execution
log $LOG_LEVEL_INFO "Starting khelp service setup..." "$UPDATE_LOG_FILE"

# Function to create the UFW systemd service
create_ufw_service() {
    log $LOG_LEVEL_INFO "Creating and enabling UFW service..." "$UPDATE_LOG_FILE"
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

# Function to create the iptables systemd service
create_iptables_service() {
    log $LOG_LEVEL_INFO "Creating and enabling iptables service..." "$UPDATE_LOG_FILE"
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
    systemctl enable iptables.service
    systemctl start iptables.service
    log $LOG_LEVEL_INFO "iptables service created and enabled." "$UPDATE_LOG_FILE"
}

# Function to create the hostname generator systemd service
create_hogen_service() {
    log $LOG_LEVEL_INFO "Creating and enabling hostname generator service..." "$HOGEN_LOG_FILE"
    cat << EOF > "$HOGEN_SERVICE_PATH"
[Unit]
Description=HOGEN Hostname Generator
Before=display-manager.service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hogen.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    chmod +x "$HOGEN_SERVICE_PATH"
    systemctl daemon-reload
    systemctl enable hogen.service
    systemctl start hogen.service
    log $LOG_LEVEL_INFO "Hostname generator service created and enabled successfully." "$HOGEN_LOG_FILE"
}

# Function to create the MAC spoofing systemd service
create_mspoo_service() {
    log $LOG_LEVEL_INFO "Creating and enabling MAC spoofing service..." "$MSPOO_LOG_FILE"
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
    systemctl start mspoo.service
    log $LOG_LEVEL_INFO "MAC spoofing service created and enabled successfully." "$MSPOO_LOG_FILE"
}

# Function to create the ProxyChains update systemd service
create_update_proxies_service() {
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
    systemctl start update_proxies.service
    log $LOG_LEVEL_INFO "Systemd service created and enabled." "$UPDATE_LOG_FILE"
}

# Function to create the ProxyChains update systemd timer
create_update_proxies_timer() {
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
}

# Create a systemd service file for Snort
create_snort_service(){
    cat << EOF > $SNORT_SERVICE
[Unit]
Description=Snort Network Intrusion Detection System
After=network.target

[Service]
ExecStart=/usr/sbin/snort -c $SNORT_CONF -i $PRIMARY_INTERFACE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start the Snort service
    systemctl daemon-reload
    systemctl enable snort
    systemctl start snort
    log $LOG_LEVEL_INFO "Snort configured and started successfully." "$UPDATE_LOG_FILE"
}

# Execute systemd service creation tasks in parallel
create_ufw_service &
create_iptables_service &
create_hogen_service &
create_mspoo_service &
create_update_proxies_service &
create_update_proxies_timer &
create_snort_service &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All systemd service creation tasks completed successfully." "$UPDATE_LOG_FILE"

# Main script execution
log $LOG_LEVEL_INFO "Starting khelp documentation setup..." "$UPDATE_LOG_FILE"

# Function to create README.md for Logging Function
create_logging_readme() {
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
}

# Function to create README.md for Update Service
create_update_readme() {
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
}

# Function to create README.md for Install Packages
create_installer_readme() {
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
}

# Function to create README.md for Proxychains Configuration
create_proxychains_readme() {
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
}

# Function to create README.md for UFW Configuration
create_ufw_readme() {
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
}

# Function to create README.md for Fail2Ban Configuration
create_fail2ban_readme() {
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
}

# Function to create README.md for Iptables Configuration
create_iptables_readme() {
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
}

# Function to create README.md for Tor Configuration
create_tor_readme() {
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
}

# Function to create README.md for Default Terminal Configuration
create_default_terminal_readme() {
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
}

# Function to create README.md for Startup Verification
create_startup_verification_readme() {
  mkdir -p "$KHELP_STARTUP_VERIFICATION_DIR"
  cat << 'EOF' > "$KHELP_STARTUP_VERIFICATION_DIR/README.md"
# Startup Script and Desktop Entry Documentation for Verification

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
}

# Function to create README.md for MSPOO
create_mspoo_readme() {
  mkdir -p "$MSPOO_DOC_DIR"
  cat << 'EOF' > "$MSPOO_DOC_FILE"
# MAC Spoofer Script 
MSPOO

## Description
This script changes the MAC address of all network interfaces (except loopback) to a randomly generated address. It includes advanced logging features, error handling, and ensures that network interfaces are correctly managed.

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
}

# Function to create README.md for HOGEN
create_hogen_readme() {
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
}

# Function to create README.md for Snort
create_snort_readme() {
  mkdir -p "$SNORT_DOC_DIR"
  cat << EOF > "$SNORT_DOC_FILE"
# Snort Configuration Documentation

## Overview
Snort is an open-source Intrusion Detection and Prevention System (IDPS) developed by Cisco. It is used to monitor network traffic in real-time, 
analyzing packets for signs of malicious activity, policy violations, or other threats. Snort can operate in three main modes:

1. **Sniffer Mode**: Captures and displays network packets in real-time.
2. **Packet Logger Mode**: Logs packets to disk for later analysis.
3. **Network Intrusion Detection System (NIDS) Mode**: Analyzes network traffic against a set of rules to detect suspicious activity.

## Conclusion
This documentation provides an overview of the Snort configuration steps and the associated environment variables. 
By following these steps, you can ensure that Snort is properly integrated into your network security setup, providing real-time intrusion detection alongside UFW, 
iptables, and Fail2ban.
EOF
}

# Run both functions in parallel
create_default_terminal_readme &
create_startup_verification_readme &
create_logging_readme &
create_update_readme &
create_installer_readme &
create_proxychains_readme &
create_ufw_readme &
create_fail2ban_readme &
create_iptables_readme &
create_tor_readme &
create_default_terminal_readme &
create_startup_verification_readme &
create_mspoo_readme &
create_hogen_readme &
create_snort_readme &

# Wait for all background processes to finish
wait

log $LOG_LEVEL_INFO "All README.md files have been created." "$UPDATE_LOG_FILE"

# Call the display_logo function
display_logo

# Reboot the system to apply changes
log $LOG_LEVEL_INFO "Rebooting the system to apply changes in 1 minute..." "$UPDATE_LOG_FILE"
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log $LOG_LEVEL_INFO "Cancelling the reboot..." "$UPDATE_LOG_FILE"
    shutdown -c
else
    log $LOG_LEVEL_INFO "Reboot will proceed in 1 minute." "$UPDATE_LOG_FILE"
fi