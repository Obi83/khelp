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

# Example usage in the script
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

# Configure UFW
log "INFO" "Configuring UFW firewall..."
configure_ufw() {
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw logging on
    log "INFO" "UFW firewall configured successfully."
}
configure_ufw

# Create and enable UFW service
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

# Configure Fail2ban with retry mechanism
log "INFO" "Configuring Fail2ban..."
configure_fail2ban() {
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

        if [ $attempts -eq $max_attempts ]; then
            log "ERROR" "Failed to install Fail2ban after $max_attempts attempts. Please check your network connection and try again."
            exit 1
        fi
    done

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
    log "INFO" "Fail2ban configured successfully."
}
configure_fail2ban

# Configure iptables
log "INFO" "Configuring iptables..."
configure_iptables() {
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
    log "INFO" "iptables rules configured successfully."
}
configure_iptables

# Debugging: After iptables setup
log "INFO" "After iptables setup"
iptables -L -v

# Create and enable iptables service
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
systemctl enable iptables.service
systemctl start iptables.service
log "INFO" "iptables service created and enabled."

# Configure and enable Tor with retry mechanism
log "INFO" "Configuring and enabling Tor..."
configure_tor() {
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

        if [ $attempts -eq $max_attempts ]; then
            log "ERROR" "Failed to install Tor after $max_attempts attempts. Please check your network connection and try again."
            exit 1
        fi
    done

    # Enable and start the Tor service
    systemctl enable tor
    systemctl start tor
    log "INFO" "Tor configured and enabled successfully."
}
configure_tor

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
cat /etc/proxychains/proxychains.conf >> "$PROXYCHAINS_CONF"

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

# Function to spoof MAC address for a given interface
spoof_mac() {
    local interface=$1
    local new_mac=$(generate_random_mac)
    echo "Spoofing MAC address for interface $interface with new MAC: $new_mac"
    if ! ip link set dev $interface down; then
        echo "Failed to bring down the network interface $interface."
        exit 1
    fi
    if ! ip link set dev $interface address $new_mac; then
        echo "Failed to change the MAC address for $interface."
        exit 1
    fi
    if ! ip link set dev $interface up; then
        echo "Failed to bring up the network interface $interface."
        exit 1
    fi
    ip link show $interface | grep ether
}

# Get all network interfaces except loopback
interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo)

# Spoof MAC address for each interface
for interface in $interfaces; do
    spoof_mac $interface
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

# Make the service unit file executable
chmod +x /etc/systemd/system/mspoo.service

# Reload systemd daemon and enable the MAC spoofing service
systemctl daemon-reload
systemctl enable mspoo.service
systemctl start mspoo.service
log "INFO" "MAC spoofing service created and enabled successfully."

# Log the completion of MAC spoofing service creation and enabling
log "INFO" "MAC spoofing service created and enabled."

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

# Create and enable hostname generator service
log "INFO" "Creating and enabling hostname generator service..."

# Create the hostname generator script
cat << 'EOF' > /usr/local/bin/hogen.sh
#!/bin/bash

# Function to fetch a random name from the Random User Generator API
fetch_random_name() {
    local api_url="https://randomuser.me/api/"
    local response=$(curl -s $api_url)
    local first_name=$(echo $response | jq -r '.results[0].name.first')
    local last_name=$(echo $response | jq -r '.results[0].name.last')
    
    # Capitalize the first letter of the first name and last name
    first_name=$(echo $first_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    last_name=$(echo $last_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    local name="${first_name}${last_name}"
    echo $name
}

newhn=$(fetch_random_name)
hostnamectl set-hostname "$newhn"

# Ensure /etc/hosts has the correct entries
grep -q "127.0.0.1    localhost" /etc/hosts || echo "127.0.0.1    localhost" >> /etc/hosts
grep -q "127.0.0.1    $newhn" /etc/hosts || echo "127.0.0.1    $newhn" >> /etc/hosts

# Ensure the current hostname is also mapped correctly
current_hostname=$(hostname)
grep -q "127.0.0.1    $current_hostname" /etc/hosts || echo "127.0.0.1    $current_hostname" >> /etc/hosts

echo "Hostname set to $newhn and /etc/hosts updated"
EOF

# Make the script executable
chmod +x /usr/local/bin/hogen.sh

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

# Make the service unit file executable
chmod +x /etc/systemd/system/hogen.service

# Reload systemd daemon and enable the hostname generator service
systemctl daemon-reload
systemctl enable hogen.service
systemctl start hogen.service
log "INFO" "Hostname generator service created and enabled successfully."

# Function to set Terminator as the default terminal for GNOME
set_gnome_default_terminal() {
    log "INFO" "Setting Terminator as the default terminal for GNOME..."
    gsettings set org.gnome.desktop.default-applications.terminal exec 'terminator'
    gsettings set org.gnome.desktop.default-applications.terminal exec-arg '-x'
}

# Function to set Terminator as the default terminal for KDE Plasma
set_kde_default_terminal() {
    log "INFO" "Setting Terminator as the default terminal for KDE Plasma..."
    kwriteconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication 'terminator'
}

# Function to set Terminator as the default terminal for XFCE
set_xfce_default_terminal() {
    log "INFO" "Setting Terminator as the default terminal for XFCE..."
    xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set 'terminator'
    xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set '--login'
}

# Function to check the current default terminal and change it to Terminator if needed
check_and_set_default_terminal() {
    if [ "$XDG_CURRENT_DESKTOP" = "GNOME" ]; then
        current_terminal=$(gsettings get org.gnome.desktop.default-applications.terminal exec)
        if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
            log "INFO" "Current terminal is $current_terminal. Changing to Terminator for GNOME..."
            set_gnome_default_terminal
        fi
    elif [ "$XDG_CURRENT_DESKTOP" = "KDE" ]; then
        current_terminal=$(kreadconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication)
        if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
            log "INFO" "Current terminal is $current_terminal. Changing to Terminator for KDE..."
            set_kde_default_terminal
        fi
    elif [ "$XDG_CURRENT_DESKTOP" = "XFCE" ]; then
        current_terminal=$(xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command)
        if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
            log "INFO" "Current terminal is $current_terminal. Changing to Terminator for XFCE..."
            set_xfce_default_terminal
        fi
    else
        log "ERROR" "Unsupported desktop environment: $XDG_CURRENT_DESKTOP"
        log "ERROR" "Supported environments: GNOME, KDE, XFCE"
        exit 1
    fi
}

# Run the check and set default terminal function
check_and_set_default_terminal

# Create startup verification script and desktop entry
log "INFO" "Creating startup verification script and desktop entry..."
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
        sleep 2
        attempt=$((attempt + 1))
    done
}

# Wait for specific services to be active
wait_for_service ufw
wait_for_service mspoo

echo "Running startup commands to show changes of khelp post-installer and service."
echo ""

uname -a
ip link show
sudo ufw status
traceroute www.showmyip.com
EOF
chmod +x "$STARTUP_SCRIPT_PATH"

mkdir -p "$USER_HOME/.config/autostart"
cat << 'EOF' > "$DESKTOP_ENTRY_PATH"
[Desktop Entry]
Type=Application
Exec=terminator -e "bash -c '$HOME/startup_script.sh; exec bash'"
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name[en_US]=Startup Terminal
Name=Startup Terminal
Comment[en_US]=Run a script in terminal at startup
Comment=Run a script in terminal at startup
EOF
chmod +x "$DESKTOP_ENTRY_PATH"

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
fi