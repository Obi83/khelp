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
echo "PROXY_API_URL4: $PROXY_API_URL4"
echo "PROXY_API_URL5: $PROXY_API_URL5"
echo "PROXY_API_URL6: $PROXY_API_URL6"

# Environment variables for paths and configurations
export PROXY_API_URL1="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"
export PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
export PROXY_API_URL3="https://spys.me/socks.txt"
export PROXY_API_URL4="https://www.sslproxies.org/"
export PROXY_API_URL5="https://www.us-proxy.org/"
export PROXY_API_URL6="https://free-proxy.cz/en/"
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export USER_HOME=$(eval echo ~${SUDO_USER})
export STARTUP_SCRIPT_PATH="$USER_HOME/startup_script.sh"
export DESKTOP_ENTRY_PATH="$USER_HOME/.config/autostart/startup_terminal.desktop"

# Validate the proxy API URLs
validate_url "$PROXY_API_URL1"
validate_url "$PROXY_API_URL2"
validate_url "$PROXY_API_URL3"
validate_url "$PROXY_API_URL4"
validate_url "$PROXY_API_URL5"
validate_url "$PROXY_API_URL6"

# Debugging: Print environment variables after validation
echo "PROXY_API_URL1=$PROXY_API_URL1"
echo "PROXY_API_URL2=$PROXY_API_URL2"
echo "PROXY_API_URL3=$PROXY_API_URL3"
echo "PROXY_API_URL4=$PROXY_API_URL4"
echo "PROXY_API_URL5=$PROXY_API_URL5"
echo "PROXY_API_URL6=$PROXY_API_URL6"
echo "PROXYCHAINS_CONF=$PROXYCHAINS_CONF"
echo "USER_HOME=$USER_HOME"
echo "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH"
echo "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH"

# Update & full-upgrade system
echo "Updating and upgrading system"
apt update && apt full-upgrade -y && apt autoremove -y && apt autoclean
echo ""

# Install helper packages
echo "Installing tools and packages."
apt install -y kali-linux-large kali-tools-windows-resources terminator bpytop htop shellcheck seclists inxi ufw tor curl proxychains iptables fastfetch guake impacket-scripts bloodhound powershell-empire fail2ban sslh
echo "Installed all useful helper tools."

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
PROXY_API_URL4="https://www.sslproxies.org/"
PROXY_API_URL5="https://www.us-proxy.org/"
PROXY_API_URL6="https://free-proxy.cz/en/"
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
fetch_and_validate_proxies $PROXY_API_URL4
fetch_and_validate_proxies $PROXY_API_URL5
fetch_and_validate_proxies $PROXY_API_URL6

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

# Create and enable hostname generator service
echo "Creating and enabling hostname generator service..."
cat << 'EOF' > /usr/local/bin/hogen.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi
syllables=("la" "na" "se" "xa" "zu" "fo" "ra" "gi" "ja" "bo" "pi" "ke" "se" "ro" "mo" "me" "li" "jo" "lo" "mi" "pa" "ku" "te" "pa" "fo" "vo" "lu" "vo" "wo" "ta" "si" "pe" "ne" "mu" "so" "ma" "na" "ri" "la" "ga" "ja" "fi" "ba" "gu" "ka" "lo" "la" "po" "me" "sa" "va" "xe" "zu" "du" "ke" "ji" "xe" "ne" "nu" "be" "ni" "to" "ru" "su" "no" "la" "me" "na" "ra" "za" "xi" "po" "mi" "ha" "ne" "tu" "lo" "ka" "ta" "ni" "me" "jo" "ta" "re" "mi" "to" "na" "ya" "wa" "nu" "na" "ka" "ra" "pa" "ji" "nu" "fe" "lo" "ja" "ma" "jo" "su" "bo" "me" "re" "ke" "ti" "xu" "bo" "le" "pa" "da" "ku" "ki" "la" "so" "ve" "ba" "me" "zo" "ro" "lo" "je" "si" "mi" "pe" "na" "ga" "vo" "mu" "pa" "la" "sa" "me" "pi" "ho" "la" "mo" "te" "ma" "le" "bi" "jo" "re" "nu" "wi" "pa" "je" "mo" "ne" "la" "ma" "ra" "ru" "wi" "bu" "na" "lo" "ne" "me" "xi" "ko" "fi" "lu" "ji" "do" "ri" "we" "po" "pe" "wa" "ku" "ka" "hi" "yo" "ri" "ji" "ju" "ra" "po" "mo" "lo" "ma" "ko" "le" "ti" "me" "li" "to" "du" "la" "ne" "ka" "ga" "je" "be" "ri" "lo" "mi" "ti" "tu" "ku" "ri" "gi" "sa" "se" "la" "jo" "me" "sa" "pa" "ka" "to" "ta" "ru" "su" "la" "ne" "zi" "go" "po" "wa" "pu" "ka" "vo" "sa" "do" "me" "ki" "su" "me" "jo" "ro" "le" "pa" "me" "no" "ji" "le" "ho" "me" "su" "na" "la" "pa" "we" "le" "ne" "mi" "ku" "mo" "no" "ka" "mo" "me" "wo" "no" "ja" "ki" "ru" "lo" "po" "me" "te" "ri" "ha" "ra" "mi" "ma" "ba" "to" "me" "ja" "le" "mo" "mu" "la" "pa" "te" "la" "ro" "wa" "ze" "bi" "ke" "na" "le" "me" "mo" "ru" "ne" "la" "po" "me" "le" "bu" "lo" "sa" "xi" "me" "la" "ga" "so" "ru" "me" "pa" "sa" "wa" "me" "lo" "ka" "no" "we" "po" "zi" "ha" "re" "da" "me" "ne" "jo" "po" "ja" "ra" "la" "za" "ga" "le" "me" "ka" "no" "me" "la" "je" "me" "la" "na" "po" "so" "ro" "la" "mi" "na" "me" "ka" "le" "jo" "ne" "xi" "me" "le" "la" "nu" "so" "lo" "je" "ra" "me" "pa" "sa" "me" "la" "me" "ne" "la" "me" "pa" "me" "pa" "le" "we" "pa" "lo" "sa" "le" "lo")
name=""
while [ ${#name} -lt 8 ]; do
    name="${name}${syllables[RANDOM % ${#syllables[@]}]}"
done
name=${name:0:8}
name="$(tr '[:lower:]' '[:upper:]' <<< ${name:0:1})${name:1:1}$(tr '[:lower:]' '[:upper:]' <<< ${name:2:1})${name:3}"
newhn=$name
hostnamectl set-hostname $newhn
echo "127.0.0.1    localhost" > /etc/hosts
echo "127.0.0.1    $newhn" >> /etc/hosts
exit
EOF
chmod +x /usr/local/bin/hogen.sh

cat << EOF > /etc/systemd/system/hogen.service
[Unit]
Description=HOGEN Hostname Generator
After=network-online.target
Wants=network-online.target

[Service]
Environment="USER_HOME=${USER_HOME}"
ExecStart=/usr/local/bin/hogen.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
chmod +x /etc/systemd/system/hogen.service
systemctl daemon-reload
systemctl enable hogen.service

# Create and enable MAC spoofing service
echo "Creating and enabling MAC spoofing service..."
cat << 'EOF' > /usr/local/bin/mspoo.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi
if ! command -v ip &> /dev/null; then
    echo "'ip' command not found. Please install it and try again."
    exit 1
fi

generate_random_mac() {
    echo -n "02"
    for i in {1..5}; do
        printf ":%02x" $((RANDOM % 256))
    done
    echo
}

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
    echo "Setting Terminator as the default terminal for GNOME..."
    gsettings set org.gnome.desktop.default-applications.terminal exec 'terminator'
    gsettings set org.gnome.desktop.default-applications.terminal exec-arg '-x'
}

# Function to set Terminator as the default terminal for KDE Plasma
set_kde_default_terminal() {
    echo "Setting Terminator as the default terminal for KDE Plasma..."
    kwriteconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication 'terminator'
}

# Function to set Terminator as the default terminal for XFCE
set_xfce_default_terminal() {
    echo "Setting Terminator as the default terminal for XFCE..."
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
        echo "Unsupported desktop environment: $XDG_CURRENT_DESKTOP"
        echo "Supported environments: GNOME, KDE, XFCE"
        exit 1
    fi
}

# Run the check and set default terminal function
check_and_set_default_terminal

# Create startup verification script and desktop entry
echo "Creating startup verification script and desktop entry..."
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
echo ""
ip link show
ufw status
traceroute www.showmyip.com
traceroute www.stromanmelden.online
EOF
chmod +x "$STARTUP_SCRIPT_PATH"

cat << EOF > /etc/systemd/system/startup_script.service
[Unit]
Description=Startup Script Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/startup_script.sh
Type=oneshot

[Install]
WantedBy=default.target
EOF
chmod +x /etc/systemd/system/startup_script.service

systemctl daemon-reload
systemctl enable startup_script.service

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
echo ""
echo "khelp setups a service to verify config on startups"
echo ""
echo "systeme is fresh and clean! tools and packages are installed!"
echo "hogen spoofing service has been installed and enabled."
echo "mspoo spoofing service has been installed and enabled."
echo "also configured standard ufw setup and enables the service."
echo ""
echo "network pentesting setup with tor and proxchains is complete."
echo "script will fetch proxy lists from 3 apis and merge the lists"
echo "the system will now reboot to apply changes and show proxy setup status."
echo ""
echo "configuration is done. script will reboot and show all changes."
echo ""

display_logo
echo "let the script reboot to show all changes after startup."
echo "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    echo "Cancelling the reboot..."
    shutdown -c
else
    echo "Reboot will proceed in 1 minute."
fi