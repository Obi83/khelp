#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Ensure ProxyChains is installed
if ! command -v proxychains &> /dev/null; then
    echo "ProxyChains is not installed. Installing ProxyChains..."
    dnf update -y && dnf install -y proxychains
fi

# Check if the proxychains.conf file exists
if [ ! -f /etc/proxychains.conf ]; then
    echo "Creating /etc/proxychains.conf file..."
    cat << 'EOF' > /etc/proxychains.conf
# ProxyChains default configuration
# Dynamic chain
dynamic_chain

# Proxy DNS requests - no leak for DNS data
proxy_dns

[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 9050
EOF
fi

# Environment variables for paths and configurations
export PROXY_API_URL1="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"
export PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
export PROXY_API_URL3="https://spys.me/socks.txt"
export PROXY_API_URL4="https://www.proxy-list.download/api/v1/get?type=socks5"
export PROXY_API_URL5="https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5"
export PROXY_API_URL6="https://www.freeproxy.world/api/proxy?protocol=socks5&limit=100"
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export USER_HOME=$(eval echo ~${SUDO_USER})
export STARTUP_SCRIPT_PATH="$USER_HOME/startup_script.sh"
export DESKTOP_ENTRY_PATH="$USER_HOME/.config/autostart/startup_terminal.desktop"

# Logging function
log() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" | tee -a /var/log/proxy_script.log
}

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
log "PROXYCHAINS_CONF=$PROXYCHAINS_CONF"
log "USER_HOME=$USER_HOME"
log "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH"
log "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH"

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

# Preconfigure sslh to install as standalone
log "Preconfiguring sslh to install as standalone..."
echo "sslh sslh/inetd_or_standalone select standalone" | sudo debconf-set-selections

# Update & full-upgrade system
log "Updating and upgrading system"
dnf update -y && dnf upgrade -y && dnf autoremove -y && dnf clean all
log "System update and upgrade completed."

# Install helper packages
log "Installing tools and packages."
dnf install -y ufw tor curl iptables-services fail2ban sslh jq
log "Installed all useful helper tools."

# Validate the proxy API URLs
validate_url "$PROXY_API_URL1"
validate_url "$PROXY_API_URL2"
validate_url "$PROXY_API_URL3"
validate_url "$PROXY_API_URL4"
validate_url "$PROXY_API_URL5"
validate_url "$PROXY_API_URL6"

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
    iptables-save > /etc/sysconfig/iptables
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
iptables-restore < /etc/sysconfig/iptables
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
PROXYCHAINS_CONF="/etc/proxychains.conf"

# Function to validate proxy
validate_proxy() {
    proxy=$1
    response=$(curl -s --proxy "$proxy" --max-time 5 https://www.google.com -o /dev/null -w "%{http_code}")
    if [ "$response" -eq 200 ]; then
        echo "$proxy"
    fi
}

# Function to fetch working proxies
fetch_working_proxies() {
    api_list_urls=(
        "$PROXY_API_URL1"
        "$PROXY_API_URL2"
        "$PROXY_API_URL3"
        "$PROXY_API_URL4"
        "$PROXY_API_URL5"
        "$PROXY_API_URL6"
    )
    num_proxies=5
    working_proxies=()

    for api_url in "${api_list_urls[@]}"; do
        proxies=$(curl -s "$api_url" | jq -r '.[]') # Assuming the API returns a JSON list of proxies
        for proxy in $proxies; do
            valid_proxy=$(validate_proxy "$proxy")
            if [ -n "$valid_proxy" ]; then
                working_proxies+=("$valid_proxy")
            fi
            if [ "${#working_proxies[@]}" -ge "$num_proxies" ]; then
                break 2
            fi
        done
    done

    # Print working proxies
    printf "%s\n" "${working_proxies[@]}"
}

# Ensure jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq is not installed. Installing jq..."
    dnf update -y && dnf install -y jq
fi

# Fetch and validate proxies
fetch_working_proxies > /tmp/working_proxies.txt

# Update ProxyChains configuration
log "Updating ProxyChains configuration..."
sed -i '/^socks5/d' "$PROXYCHAINS_CONF" # Remove existing SOCKS5 proxies
while IFS= read -r proxy; do
    echo "socks5  $proxy" | tee -a "$PROXYCHAINS_CONF"
done < /tmp/working_proxies.txt
log "ProxyChains configuration updated with valid proxies from all APIs."
EOF
chmod +x /usr/local/bin/update_proxies.sh

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

# Summary and Reboot
log "System is fresh and clean!"
log "khelp configured standard ufw, iptables, fail2ban and sshl"
log "Network setup with tor and proxchains is complete."
log "Script will fetch proxy lists from 6 APIs."

log "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

log "Reboot will proceed in 1 minute."