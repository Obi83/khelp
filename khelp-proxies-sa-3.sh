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
    local proxy_log_file="/var/log/khelp_proxy.log"

    # Rotate log file if it exceeds 1MB
    if [ -f "$proxy_log_file" ] && [ $(stat -c%s "$proxy_log_file") -gt 1048576 ]; then
        mv "$proxy_log_file" "$proxy_log_file.$(date +'%Y%m%d%H%M%S')"
    fi

    echo "$(date +'%Y-%m-%d %H:%M:%S') [$level] - $message" | tee -a "$proxy_log_file"
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
mkdir -p /usr/local/share/khelp_update
cat << 'EOF' > /usr/local/share/khelp_update/README.md
# System Update Script

## Description
This script updates and upgrades the system with a retry mechanism in case of failures.

## Functions
- log(level, message): Logs messages with a specified log level.
- update_system: Updates and upgrades the system with a retry mechanism.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

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
    local packages="ufw tor curl jq iptables fail2ban sslh terminator"

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
mkdir -p /usr/local/share/khelp_installer
cat << 'EOF' > /usr/local/share/khelp_installer/README.md
# Package Installer Script

## Description
This script installs a set of useful helper packages with a retry mechanism in case of failures.

## Functions
- log(level, message): Logs messages with a specified log level.
- install_packages: Installs a set of packages with a retry mechanism.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

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

# Ensure ProxyChains is installed
log "INFO" "Checking if ProxyChains is installed..."
if ! command -v proxychains &> /dev/null; then
    log "INFO" "ProxyChains is not installed. Installing ProxyChains..."
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y proxychains; then
            log "INFO" "ProxyChains installed successfully."
            break
        else
            log "ERROR" "Failed to install ProxyChains. Retrying in $((attempts * 5)) seconds..."
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi

        if [ $attempts -eq $max_attempts ]; then
            log "ERROR" "Failed to install ProxyChains after $max_attempts attempts. Please check your network connection and try again."
            exit 1
        fi
    done
else
    log "INFO" "ProxyChains is already installed."
fi

# Check if the proxychains.conf file exists
log "INFO" "Checking if the proxychains.conf file exists..."
if [ ! -f /etc/proxychains.conf ]; then
    log "INFO" "Creating /etc/proxychains.conf file..."
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
    log "INFO" "ProxyChains configuration file created."
else
    log "INFO" "ProxyChains configuration file already exists."
fi

# Environment variables for paths and configurations
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
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export USER_HOME=$(eval echo ~${SUDO_USER})
export STARTUP_SCRIPT_PATH="$USER_HOME/startup_script.sh"
export DESKTOP_ENTRY_PATH="$USER_HOME/.config/autostart/startup_terminal.desktop"
export proxy_log_file="/var/log/khelp_proxy.log"

# Improved URL validation function
validate_url() {
    if [[ ! $1 =~ ^https?://.*$ ]]; then
        log "ERROR" "Invalid URL: $1"
        exit 1
    fi
}

# Debugging: Print environment variables
log "INFO" "Environment Variables:"
log "INFO" "PROXY_API_URL1=$PROXY_API_URL1"
log "INFO" "PROXY_API_URL2=$PROXY_API_URL2"
log "INFO" "PROXY_API_URL3=$PROXY_API_URL3"
log "INFO" "PROXY_API_URL4=$PROXY_API_URL4"
log "INFO" "PROXY_API_URL5=$PROXY_API_URL5"
log "INFO" "PROXY_API_URL6=$PROXY_API_URL6"
log "INFO" "PROXY_API_URL7=$PROXY_API_URL7"
log "INFO" "PROXY_API_URL8=$PROXY_API_URL8"
log "INFO" "PROXY_API_URL9=$PROXY_API_URL9"
log "INFO" "PROXY_API_URL10=$PROXY_API_URL10"
log "INFO" "PROXYCHAINS_CONF=$PROXYCHAINS_CONF"
log "INFO" "USER_HOME=$USER_HOME"
log "INFO" "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH"
log "INFO" "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH"
log "INFO" "proxy_log_file=$proxy_log_file"

# Check if required files and directories exist
required_files=(
    "$PROXYCHAINS_CONF"
    "/etc/systemd/system"
    "/usr/local/bin"
)

for file in "${required_files[@]}"; do
    if [ ! -e "$file" ]; then
        log "ERROR" "Error: $file does not exist."
        exit 1
    fi
done

# Validate the proxy API URLs
validate_url "$PROXY_API_URL1"
validate_url "$PROXY_API_URL2"
validate_url "$PROXY_API_URL3"
validate_url "$PROXY_API_URL4"
validate_url "$PROXY_API_URL5"
validate_url "$PROXY_API_URL6"
validate_url "$PROXY_API_URL7"
validate_url "$PROXY_API_URL8"
validate_url "$PROXY_API_URL9"
validate_url "$PROXY_API_URL10"

# Configure ProxyChains
log "INFO" "Configuring ProxyChains..."

# ProxyChains configuration file path
PROXYCHAINS_CONF="/etc/proxychains.conf"

# Check if ProxyChains is already configured for Tor
if grep -q "socks5  127.0.0.1 9050" "$PROXYCHAINS_CONF"; then
    log "INFO" "ProxyChains is already configured for Tor."
else
    # Update ProxyChains configuration
    sed -i 's/^#dynamic_chain/dynamic_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^strict_chain/#strict_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^#proxy_dns/proxy_dns/' "$PROXYCHAINS_CONF"
    echo "socks5  127.0.0.1 9050" | tee -a "$PROXYCHAINS_CONF"
    log "INFO" "ProxyChains configuration updated."
fi

# Create the ProxyChains configuration file
log "INFO" "Appending fetched proxy list to ProxyChains configuration..."

# Append the fetched proxy list to the configuration file
echo "$PROXY_LIST" >> "$PROXYCHAINS_CONF"

log "INFO" "ProxyChains configured successfully."

# Create a script to fetch and validate proxies
log "INFO" "Creating script to fetch and validate proxies..."
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
log "INFO" "Creating systemd service to run the proxy update script on startup..."
cat << EOF > /etc/systemd/system/update_proxies.service
[Unit]
Description=Update Proxy List on Startup
After=mspoo.service network.target

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
log "INFO" "Systemd service created and enabled."

# Create a cron job to update proxies every 30 minutes
log "INFO" "Creating cron job to update proxies every 30 minutes..."
echo "*/30 * * * * root /usr/local/bin/update_proxies.sh" | sudo tee -a /etc/crontab
log "INFO" "Cron job created."

# Create a systemd timer to run the proxy update script every 30 minutes
log "INFO" "Creating systemd timer to run the proxy update script every 30 minutes..."
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
log "INFO" "Systemd timer created and started."

# Documentation
mkdir -p /usr/local/share/khelp_proxychains
cat << 'EOF' > /usr/local/share/khelp_proxychains/README.md
# ProxyChains Configuration Script

## Description
This script configures ProxyChains and sets up a systemd service and timer to fetch and validate proxies periodically.

## Functions
- log(level, message): Logs messages with a specified log level.
- configure_tor: Installs and configures Tor with a retry mechanism.
- configure_proxychains: Configures ProxyChains for Tor and updates the configuration with fetched proxies.
- fetch_and_validate_proxies: Fetches and validates proxies from a given API URL.
- is_anonymous_proxy: Checks if a proxy is anonymous.
- is_fast_proxy: Checks if a proxy is fast.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `apt` package manager must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of ProxyChains configuration and proxy fetching.
- The script sets up a systemd service and timer to fetch and validate proxies every 30 minutes.
EOF

# Configure UFW
configure_ufw() {
    log "INFO" "Configuring UFW firewall..."
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw logging on
    log "INFO" "UFW firewall configured successfully."
}

# Create and enable UFW service
create_ufw_service() {
    log "INFO" "Creating and enabling UFW service..."
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
    log "INFO" "UFW service created and enabled."
}

configure_ufw
create_ufw_service

# Documentation for UFW
mkdir -p /usr/local/share/khelp_ufw
cat << 'EOF' > /usr/local/share/khelp_ufw/README.md
# UFW Configuration Script

## Description
This script configures the UFW firewall and sets up a systemd service to ensure it starts on boot and remains active.

## Functions
- log(level, message): Logs messages with a specified log level.
- configure_ufw: Configures the UFW firewall with standard settings.
- create_ufw_service: Creates and enables a systemd service to ensure UFW starts on boot and remains active.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `ufw` package must be installed.
- The `systemctl` command must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of UFW configuration and service creation.
EOF

# Configure Fail2ban with retry mechanism
configure_fail2ban() {
    log "INFO" "Configuring Fail2ban..."
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y fail2ban; then
            log "INFO" "Fail2ban installed successfully."
            break
        else
            log "ERROR" "Failed to install Fail2ban. Retrying in $((attempts * 5)) seconds..."
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    if [ $attempts -eq $max_attempts ]; then
        log "ERROR" "Failed to install Fail2ban after $max_attempts attempts. Please check your network connection and try again."
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
        log "INFO" "Fail2ban configured and started successfully."
    else
        log "ERROR" "Failed to start Fail2ban."
        exit 1
    fi
}

configure_fail2ban

# Documentation for Fail2ban
mkdir -p /usr/local/share/khelp_fail2ban
cat << 'EOF' > /usr/local/share/khelp_fail2ban/README.md
# Fail2ban Configuration Script

## Description
This script installs and configures Fail2ban with a retry mechanism in case of failures.

## Functions
- log(level, message): Logs messages with a specified log level.
- configure_fail2ban: Installs and configures Fail2ban with a retry mechanism.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `apt` package manager must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of Fail2ban installation and configuration.
EOF

# Ensure the /etc/iptables directory exists
mkdir -p /etc/iptables

# Configure iptables
configure_iptables() {
    log "INFO" "Configuring iptables..."
    
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
        log "INFO" "iptables rules configured successfully."
    else
        log "ERROR" "Failed to save iptables rules."
        exit 1
    fi
}

# Debugging: After iptables setup
log_iptables_rules() {
    log "INFO" "After iptables setup"
    iptables -L -v | tee -a /var/log/iptables_script.log
}

# Create and enable iptables service
create_iptables_service() {
    log "INFO" "Creating and enabling iptables service..."
    
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
        log "INFO" "iptables service created and enabled."
    else
        log "ERROR" "Failed to create and enable iptables service."
        exit 1
    fi
}

configure_iptables
log_iptables_rules
create_iptables_service

# Documentation for iptables
mkdir -p /usr/local/share/khelp_iptables
cat << 'EOF' > /usr/local/share/khelp_iptables/README.md
# iptables Configuration Script

## Description
This script configures iptables rules and sets up a systemd service to ensure the rules are applied on startup.

## Functions
- log(level, message): Logs messages with a specified log level.
- configure_iptables: Configures iptables rules.
- log_iptables_rules: Logs the current iptables rules.
- create_iptables_service: Creates and enables a systemd service to ensure iptables rules are applied on startup.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `iptables` package must be installed.
- The `systemctl` command must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of iptables configuration and service creation.
EOF

# Configure and enable Tor with retry mechanism
configure_tor() {
    log "INFO" "Configuring and enabling Tor..."
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        if apt install -y tor; then
            log "INFO" "Tor installed successfully."
            break
        else
            log "ERROR" "Failed to install Tor. Retrying in $((attempts * 5)) seconds..."
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
        fi
    done

    if [ $attempts -eq $max_attempts ]; then
        log "ERROR" "Failed to install Tor after $max_attempts attempts. Please check your network connection and try again."
        exit 1
    fi

    # Enable and start the Tor service
    if systemctl enable tor && systemctl start tor; then
        log "INFO" "Tor configured and enabled successfully."
    else
        log "ERROR" "Failed to enable and start Tor service."
        exit 1
    fi
}

configure_tor

# Documentation
mkdir -p /usr/local/share/khelp_tor
cat << 'EOF' > /usr/local/share/khelp_tor/README.md
# Tor Configuration Script

## Description
This script installs and configures Tor with a retry mechanism in case of failures.

## Functions
- log(level, message): Logs messages with a specified log level.
- configure_tor: Installs and configures Tor with a retry mechanism.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The `apt` package manager must be available.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of Tor installation and configuration.
EOF

# Function to set Terminator as the default terminal for GNOME
set_gnome_default_terminal() {
    log "INFO" "Setting Terminator as the default terminal for GNOME..."
    if gsettings set org.gnome.desktop.default-applications.terminal exec 'terminator' && \
       gsettings set org.gnome.desktop.default-applications.terminal exec-arg '-x'; then
        log "INFO" "Terminator set as default terminal for GNOME."
    else
        log "ERROR" "Failed to set Terminator as default terminal for GNOME."
        exit 1
    fi
}

# Function to set Terminator as the default terminal for KDE Plasma
set_kde_default_terminal() {
    log "INFO" "Setting Terminator as the default terminal for KDE Plasma..."
    if kwriteconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication 'terminator'; then
        log "INFO" "Terminator set as default terminal for KDE Plasma."
    else
        log "ERROR" "Failed to set Terminator as default terminal for KDE Plasma."
        exit 1
    fi
}

# Function to set Terminator as the default terminal for XFCE
set_xfce_default_terminal() {
    log "INFO" "Setting Terminator as the default terminal for XFCE..."
    if xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set 'terminator' && \
       xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set '--login'; then
        log "INFO" "Terminator set as default terminal for XFCE."
    else
        log "ERROR" "Failed to set Terminator as default terminal for XFCE."
        exit 1
    fi
}

# Function to check the current default terminal and change it to Terminator if needed
check_and_set_default_terminal() {
    case "$XDG_CURRENT_DESKTOP" in
        GNOME)
            current_terminal=$(gsettings get org.gnome.desktop.default-applications.terminal exec)
            if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
                log "INFO" "Current terminal is $current_terminal. Changing to Terminator for GNOME..."
                set_gnome_default_terminal
            else
                log "INFO" "Current terminal is already set to Terminator for GNOME."
            fi
            ;;
        KDE)
            current_terminal=$(kreadconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication)
            if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
                log "INFO" "Current terminal is $current_terminal. Changing to Terminator for KDE..."
                set_kde_default_terminal
            else
                log "INFO" "Current terminal is already set to Terminator for KDE."
            fi
            ;;
        XFCE)
            current_terminal=$(xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command)
            if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
                log "INFO" "Current terminal is $current_terminal. Changing to Terminator for XFCE..."
                set_xfce_default_terminal
            else
                log "INFO" "Current terminal is already set to Terminator for XFCE."
            fi
            ;;
        *)
            log "ERROR" "Unsupported desktop environment: $XDG_CURRENT_DESKTOP"
            log "ERROR" "Supported environments: GNOME, KDE, XFCE"
            exit 1
            ;;
    esac
}

# Run the check and set default terminal function
check_and_set_default_terminal

# Documentation
mkdir -p /usr/local/share/khelp_terminator
cat << 'EOF' > /usr/local/share/khelp_terminator/README.md
# Terminator Configuration Script

## Description
This script sets Terminator as the default terminal for GNOME, KDE Plasma, and XFCE desktop environments.

## Functions
-  log(level, message): Logs messages with a specified log level.
-  set_gnome_default_terminal: Sets Terminator as the default terminal for GNOME.
-  set_kde_default_terminal: Sets Terminator as the default terminal for KDE Plasma.
-  set_xfce_default_terminal: Sets Terminator as the default terminal for XFCE.
-  check_and_set_default_terminal: Checks the current default terminal and changes it to Terminator if needed.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

## Requirements
- The gsettings command must be available for GNOME.
- The kwriteconfig5 command must be available for KDE Plasma.
- The xfconf-query command must be available for XFCE.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of setting Terminator as the default terminal.

### Summary of Improvements:
1. **Comprehensive Error Handling and Logging:**
   - Added a logging function to log info and error messages.
   - Added error handling in the functions to set Terminator as the default terminal.

2. **Advanced Validation:**
   - Ensured that the current default terminal is checked before changing it to Terminator.
   - Validated the desktop environment before attempting to change the default terminal.

3. **Detailed Documentation:**
   - Created a README.md file with detailed documentation of the script.

By incorporating these improvements, the script is now more robust, with enhanced error handling, logging, and validation, and it includes detailed documentation for users.
EOF

# Create the startup script
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

log "INFO" "Startup verification script and desktop entry created successfully."

# Documentation
mkdir -p /usr/local/share/khelp_verify
cat << 'EOF' > /usr/local/share/khelp_verify/README.md
# Startup Verification Script

## Description
This script creates a startup verification script and a desktop entry to run the script at startup in a terminal window.

## Functions
- log(level, message): Logs messages with a specified log level.
- wait_for_service(service_name): Waits for a specific service to be active.

## Log File
Logs are saved to /var/log/khelp_proxy.log. The log file is rotated if it exceeds 1MB.

## Script Details
- The startup script is created at the path specified by the STARTUP_SCRIPT_PATH variable.
- The desktop entry is created at the path specified by the DESKTOP_ENTRY_PATH variable.
- The script waits for specific services (UFW and Tor) to be active before running startup commands.
- The desktop entry runs the script in a Terminator terminal window at startup.

## Requirements
- The systemctl command must be available.
- The terminator terminal emulator must be installed.

## Notes
- The script supports error handling and logs errors and info messages.
- The script validates the success of creating the startup script and desktop entry.
EOF

# Summary and Reboot
log "INFO" ""
log "INFO" "khelp is done! Everything is looking good!"
log "INFO" ""
log "INFO" "khelp setups a Tor / Proxy Routing by fetching proxies from 10 APIs"
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
fi
