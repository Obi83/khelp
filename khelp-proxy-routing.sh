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

# Preconfigure sslh to install as standalone
echo "Preconfiguring sslh to install as standalone..."
echo "sslh sslh/inetd_or_standalone select standalone" | sudo debconf-set-selections

# Update & full-upgrade system
echo "Updating and upgrading system"
apt update && apt full-upgrade -y && apt autoremove -y && apt autoclean
echo ""

# Install helper packages
echo "Installing tools and packages."
apt install -y ufw tor curl proxychains iptables fail2ban sslh
echo "Installed all useful helper tools."

# Improved URL validation function
validate_url() {
    if [[ ! $1 =~ ^https?://.*$ ]]; then
        echo "Invalid URL: $1"
        exit 1
    fi
}

# Debugging: Print URLs before validation
echo "Validating URLs:"
echo "PROXY_API_URL1: $PROXY_API_URL1"
echo "PROXY_API_URL2: $PROXY_API_URL2"
echo "PROXY_API_URL3: $PROXY_API_URL3"

# Environment variables for paths and configurations
export PROXY_API_URL1="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"
export PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
export PROXY_API_URL3="https://spys.me/socks.txt"
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export USER_HOME=$(eval echo ~${SUDO_USER})
export STARTUP_SCRIPT_PATH="$USER_HOME/startup_script.sh"
export DESKTOP_ENTRY_PATH="$USER_HOME/.config/autostart/startup_terminal.desktop"

# Validate the proxy API URLs
validate_url "$PROXY_API_URL1"
validate_url "$PROXY_API_URL2"
validate_url "$PROXY_API_URL3"

# Debugging: Print environment variables after validation
echo "PROXY_API_URL1=$PROXY_API_URL1"
echo "PROXY_API_URL2=$PROXY_API_URL2"
echo "PROXY_API_URL3=$PROXY_API_URL3"
echo "PROXYCHAINS_CONF=$PROXYCHAINS_CONF"
echo "USER_HOME=$USER_HOME"
echo "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH"
echo "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH"

# Configure UFW
echo "Configuring UFW firewall..."
configure_ufw() {
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw logging on
    echo "UFW firewall configured successfully."
}
configure_ufw

# Create and enable UFW service
echo "Creating and enabling UFW service..."
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

# Configure Fail2ban
echo "Configuring Fail2ban..."
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
    echo "Fail2ban configured successfully."
}
configure_fail2ban

# Configure iptables
echo "Configuring iptables..."
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
    echo "iptables rules configured successfully."
}
configure_iptables

# Debugging: After iptables setup
echo "After iptables setup"
iptables -L -v

# Create and enable iptables service
echo "Creating and enabling iptables service..."
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

# Start and enable Tor service
echo "Starting and enabling Tor service..."
systemctl start tor
systemctl enable tor

# Configure ProxyChains
echo "Configuring ProxyChains..."
if grep -q "socks5  127.0.0.1 9050" "$PROXYCHAINS_CONF"; then
    echo "ProxyChains is already configured for Tor."
else
    sed -i 's/^#dynamic_chain/dynamic_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^strict_chain/#strict_chain/' "$PROXYCHAINS_CONF"
    sed -i 's/^#proxy_dns/proxy_dns/' "$PROXYCHAINS_CONF"
    echo "socks5  127.0.0.1 9050" | tee -a "$PROXYCHAINS_CONF"
    echo "ProxyChains configuration updated."
fi

# Create a script to fetch and validate proxies
echo "Creating script to fetch and validate proxies..."
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

# Fetch and validate proxies from each API
echo "Validating proxies and updating ProxyChains configuration..."
sed -i '/^socks5/d' "$PROXYCHAINS_CONF" # Remove existing SOCKS5 proxies

fetch_and_validate_proxies $PROXY_API_URL1
fetch_and_validate_proxies $PROXY_API_URL2
fetch_and_validate_proxies $PROXY_API_URL3

echo "ProxyChains configuration updated with valid proxies from all APIs."
EOF
chmod +x /usr/local/bin/update_proxies.sh

# Create a systemd service to run the proxy update script on startup
echo "Creating systemd service to run the proxy update script on startup..."
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
echo "systeme is fresh and clean!"
echo "khelp configured standard ufw, iptables, fail2ban and sshl"
echo ""
echo "network setup with tor and proxchains is complete."
echo "script will fetch proxy lists from 3 apis."
echo ""

display_logo
echo "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    echo "Cancelling the reboot..."
    shutdown -c
else
    echo "Reboot will proceed in 1 minute."
fi