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

# Ensure the script is run as root for initial setup
if [ "$EUID" -ne 0 ]; then
    log "Please run this script as root."
    exit 1
fi

# Logging function
log() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" | tee -a /var/log/proxy_script.log
}

# Preconfigure sslh to install as standalone
log "Preconfiguring sslh to install as standalone..."
echo "sslh sslh/inetd_or_standalone select standalone" | debconf-set-selections

# Update & full-upgrade system
log "Updating and upgrading system"
if ! apt update && apt full-upgrade -y && apt autoremove -y && apt autoclean; then
    log "System update and upgrade failed."
    exit 1
fi
log "System update and upgrade completed."

# Install helper packages
log "Installing tools and packages."
if ! sudo apt install -y ufw tor curl jq iptables fail2ban sslh kali-linux-large kali-tools-windows-resources terminator bpytop htop shellcheck seclists inxi fastfetch guake impacket-scripts bloodhound powershell-empire; then
    log "Package installation failed."
    exit 1
fi
log "Installed all useful helper tools."

# Ensure ProxyChains is installed
if ! command -v proxychains &> /dev/null; then
    log "ProxyChains is not installed. Installing ProxyChains..."
    if ! sudo apt install -y proxychains; then
        log "ProxyChains installation failed."
        exit 1
    fi
fi

# Check if the proxychains.conf file exists
if [ ! -f /etc/proxychains.conf ]; then
    log "Creating /etc/proxychains.conf file..."
    cat << 'EOF' > /etc/proxychains.conf
# ProxyChains default configuration
# Dynamic chain
dynamic_chain

# Proxy DNS requests - no leak for DNS data
proxy_dns

[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks5  127.0.0.1 9050
EOF
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
export LOG_FILE="/var/log/mspoo.log"
export MAC_BACKUP_FILE="/var/log/original_macs.log"

# Improved URL validation function
validate_url() {
    if [[ ! $1 =~ ^https?://.*$ ]]; then
        log "Invalid URL: $1"
        exit 1
    fi
}

# Debugging: Print environment variables
log "Environment Variables:"
log "PROXY_API_URL1=$PROXY_API_URL1"
log "PROXY_API_URL2=$PROXY_API_URL2"
log "PROXY_API_URL3=$PROXY_API_URL3"
log "PROXY_API_URL4=$PROXY_API_URL4"
log "PROXY_API_URL5=$PROXY_API_URL5"
log "PROXY_API_URL6=$PROXY_API_URL6"
log "PROXY_API_URL7=$PROXY_API_URL7"
log "PROXY_API_URL8=$PROXY_API_URL8"
log "PROXY_API_URL9=$PROXY_API_URL9"
log "PROXY_API_URL10=$PROXY_API_URL10"
log "PROXYCHAINS_CONF=$PROXYCHAINS_CONF"
log "USER_HOME=$USER_HOME"
log "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH"
log "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH"
log "LOG_FILE=$LOG_FILE"
log "MAC_BACKUP_FILE=$MAC_BACKUP_FILE"

# Check if required files and directories exist
required_files=(
    "$PROXYCHAINS_CONF"
    "/etc/systemd/system"
    "/usr/local/bin"
)

for file in "${required_files[@]}"; do
    if [ ! -e "$file" ]; then
        log "Error: $file does not exist."
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
log "Configuring UFW firewall..."
configure_ufw() {
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw logging on
    log "UFW firewall configured successfully."
}
configure_ufw

# Create and enable UFW service
log "Creating and enabling UFW service..."
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
log "UFW service created and enabled."

# Configure Fail2ban
log "Configuring Fail2ban..."
configure_fail2ban() {
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
    log "Fail2ban configured successfully."
}
configure_fail2ban

# Configure iptables
log "Configuring iptables..."
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
    log "iptables rules configured successfully."
}
configure_iptables

# Debugging: After iptables setup
log "After iptables setup"
iptables -L -v

# Create and enable iptables service
log "Creating and enabling iptables service..."
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
log "iptables service created and enabled."

# Start and enable Tor service
log "Starting and enabling Tor service..."
systemctl start tor
systemctl enable tor

# Configure ProxyChains
log "Configuring ProxyChains..."
if grep -q "socks5  127.0.0.1 9050" "$PROXYCHAINS_CONF"; then
    log "ProxyChains is already configured for Tor."
else
    sed -i 's/^#dynamic_chain/dynamic_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^strict_chain/#strict_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^#proxy_dns/proxy_dns/' "$PROXYCHAINS_CONF"
    echo "socks5  127.0.0.1 9050" | tee -a "$PROXYCHAINS_CONF"
    log "ProxyChains configuration updated."
fi

# Create a script to fetch and validate proxies
log "Creating script to fetch and validate proxies..."
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
LOG_FILE="/var/log/proxy_update.log"

# Function to log messages
log() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
    # Send email notification if there is an error
    if [[ "$message" == *"Error"* ]]; then
        echo "$message" | mail -s "ProxyChains Script Error" user@example.com
    fi
}

# Enhanced function to fetch and validate proxies from a given API URL
fetch_and_validate_proxies() {
    local API_URL=$1
    local VALID_PROXY_COUNT=0
    local PROXY_LIST=$(curl -s $API_URL)

    echo "$PROXY_LIST" | while read -r PROXY; do
        IP=$(echo $PROXY | cut -d':' -f1)
        PORT=$(echo $PROXY | cut -d':' -f2)
        if nc -z $IP $PORT && is_anonymous_proxy $IP $PORT && is_fast_proxy $IP $PORT; then
            log "Valid proxy found: $PROXY"
            echo "socks5  $IP $PORT" | tee -a "$PROXYCHAINS_CONF"
            VALID_PROXY_COUNT=$((VALID_PROXY_COUNT + 1))
            if [ $VALID_PROXY_COUNT -ge 5 ]; then
                break
            fi
        else
            log "Invalid or non-anonymous proxy: $PROXY"
        fi
    done

    log "Added $VALID_PROXY_COUNT valid proxies from $API_URL."
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
log "Validating proxies and updating ProxyChains configuration..."
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

log "ProxyChains configuration updated with valid SOCKS5 proxies from all APIs."
EOF
chmod +x /usr/local/bin/update_proxies.sh

# Create a cron job to update proxies every hour
echo "0 * * * * root /usr/local/bin/update_proxies.sh" | sudo tee -a /etc/crontab

# Create a systemd service to run the proxy update script on startup
log "Creating systemd service to run the proxy update script on startup..."
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

# Create a cron job to update proxies every 30 minutes
echo "*/30 * * * * root /usr/local/bin/update_proxies.sh" | sudo tee -a /etc/crontab

# Create a systemd timer to run the proxy update script every 30 minutes
log "Creating systemd timer to run the proxy update script every 30 minutes..."
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

# Create and enable MAC spoofing service
log "Creating and enabling MAC spoofing service..."
cat << 'EOF' > /usr/local/bin/mspoo.sh
#!/bin/bash

# Logging function
log() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

# Ensure the script is run as root for initial setup
if [ "$EUID" -ne 0 ]; then
    log "Please run this script as root."
    exit 1
fi

# Check if the required commands are available
if ! command -v ip &> /dev/null; then
    log "'ip' command not found. Please install it and try again."
    exit 1
fi

# Function to generate a random MAC address
generate_random_mac() {
    echo -n "02"  # Locally administered MAC
    for i in {1..5}; do
        printf ":%02x" $((RANDOM % 256))
    done
    echo
}

# Function to spoof the MAC address
spoof_mac() {
    local interface=$1
    local new_mac=$(generate_random_mac)
    log "Spoofing MAC address for interface $interface with new MAC: $new_mac"

    # Save the original MAC address
    local original_mac=$(ip link show $interface | awk '/ether/ {print $2}')
    log "Original MAC address for $interface: $original_mac"
    echo "$interface $original_mac" >> "$MAC_BACKUP_FILE"

    if ! ip link set dev $interface down; then
        log "Failed to bring down the network interface $interface."
        exit 1
    fi
    if ! ip link set dev $interface address $new_mac; then
        log "Failed to change the MAC address for $interface."
        exit 1
    fi
    if ! ip link set dev $interface up; then
        log "Failed to bring up the network interface $interface."
        exit 1
    fi
    ip link show $interface | grep ether
}

# Function to restore the original MAC address
restore_mac() {
    local interface=$1
    local original_mac=$(grep "^$interface " "$MAC_BACKUP_FILE" | awk '{print $2}')
    if [ -z "$original_mac" ]; then
        log "Original MAC address for interface $interface not found."
        exit 1
    fi

    log "Restoring original MAC address for interface $interface: $original_mac"
    if ! ip link set dev $interface down; then
        log "Failed to bring down the network interface $interface."
        exit 1
    fi
    if ! ip link set dev $interface address $original_mac; then
        log "Failed to restore the MAC address for $interface."
        exit 1
    fi
    if ! ip link set dev $interface up; then
        log "Failed to bring up the network interface $interface."
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

# Restore original MAC addresses
for interface in $interfaces; do
    restore_mac $interface
done
EOF
chmod +x /usr/local/bin/mspoo.sh

cat << EOF > /etc/systemd/system/mspoo.service
[Unit]
Description=MSPOO MACSpoofing Service
After=network-online.target
Wants=network-online.target

[Service]
Environment="USER_HOME=${USER_HOME}"
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

# Function to set Terminator as the default terminal for GNOME
set_gnome_default_terminal() {
    log "Setting Terminator as the default terminal for GNOME..."
    gsettings set org.gnome.desktop.default-applications.terminal exec 'terminator'
    gsettings set org.gnome.desktop.default-applications.terminal exec-arg '-x'
}

# Function to set Terminator as the default terminal for KDE Plasma
set_kde_default_terminal() {
    log "Setting Terminator as the default terminal for KDE Plasma..."
    kwriteconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication 'terminator'
}

# Function to set Terminator as the default terminal for XFCE
set_xfce_default_terminal() {
    log "Setting Terminator as the default terminal for XFCE..."
    xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set 'terminator'
    xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command --type string --set '--login'
}

# Function to check the current default terminal and change it to Terminator if needed
check_and_set_default_terminal() {
    if [ "$XDG_CURRENT_DESKTOP" = "GNOME" ]; then
        current_terminal=$(gsettings get org.gnome.desktop.default-applications.terminal exec)
        if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
            set_gnome_default_terminal
        fi
    elif [ "$XDG_CURRENT_DESKTOP" = "KDE" ]; then
        current_terminal=$(kreadconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication)
        if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
            set_kde_default_terminal
        fi
    elif [ "$XDG_CURRENT_DESKTOP" = "XFCE" ]; then
        current_terminal=$(xfconf-query --channel xfce4-session --property /sessions/Failsafe/Client0_Command)
        if [[ "$current_terminal" == *"gnome-terminal"* || "$current_terminal" == *"qterminal"* || "$current_terminal" == *"konsole"* || "$current_terminal" == *"xfce4-terminal"* ]]; then
            set_xfce_default_terminal
        fi
    else
        log "Unsupported desktop environment: $XDG_CURRENT_DESKTOP"
        log "Supported environments: GNOME, KDE, XFCE"
        exit 1
    fi
}

# Run the check and set default terminal function
check_and_set_default_terminal

# Create startup verification script and desktop entry
log "Creating startup verification script and desktop entry..."
cat << 'EOF' > "$STARTUP_SCRIPT_PATH"
#!/bin/bash

# Function to log messages
log() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" | tee -a "$HOSTNAME_CHANGER_LOG_FILE"
}

# Function to wait until a specific service is active
wait_for_service() {
    local service_name=$1
    local max_attempts=3
    local attempt=1

    while ! systemctl is-active --quiet "$service_name"; do
        if [ $attempt -gt $max_attempts ]; then
            log "Service $service_name did not start within the expected time."
            return 1
        fi
        log "Waiting for $service_name to start... (attempt $attempt)"
        sleep 2
        attempt=$((attempt + 1))
    done
}

# Wait for specific services to be active
wait_for_service ufw
wait_for_service mspoo

log "Running startup commands to show changes of khelp post-installer and service."
log ""

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
log ""
log "khelp is done! Everything is looking good!"
log ""
log "khelp setups a Tor / Proxy Routing by fetching proxies from 10 API's"
log "Its also setups HOGEN and MSPOO Service."
log "After reboot it will provide a window with the status of all changes."

display_logo
log "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log "Cancelling the reboot..."
    shutdown -c
else
    log "Reboot will proceed in 1 minute."
fi