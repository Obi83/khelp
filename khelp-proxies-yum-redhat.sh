#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Ensure ProxyChains is installed
if ! command -v proxychains &> /dev/null; then
    echo "ProxyChains is not installed. Installing ProxyChains..."
    yum update -y && yum install -y proxychains
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
yum update -y && yum upgrade -y && yum autoremove -y && yum clean all
log "System update and upgrade completed."

# Install helper packages
log "Installing tools and packages."
yum install -y ufw tor curl iptables-services fail2ban sslh jq
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
WantedBy=multi