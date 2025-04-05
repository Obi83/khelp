#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Define the display_logo function
display_logo() {                                                                                                      
echo "  _    _          _             ____                _____          "
echo " | | _| |__   ___| |_ __       |  _ \ _ __ _____  _|  ___|____  __ "
echo " | |/ / '_ \ / _ \ | '_ \      | |_) | '__/ _ \ \/ / |_ / _ \ \/ / "
echo " |   <| | | |  __/ | |_) |  #  |  __/| | | (_) >  <|  _| (_) >  <  "
echo " |_|\_\_| |_|\___|_| .__/      |_|   |_|  \___/_/\_\_|  \___/_/\_\ "
echo "                   |_|                                             " 
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
#Log Files
export UPDATE_LOG_FILE="/var/log/khelp.log"
export PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"
export PROXY_TIMER_LOG_FILE="/var/log/timer_proxies.log"
export IPTABLES_LOG_FILE="/var/log/khelp_iptables.log"

# SSL DOMAIN
export SSL_DOMAIN="example.com"

# Directories
export KHELP_UPDATE_DIR="/usr/local/share/khelp_update"
export KHELP_INSTALLER_DIR="/usr/local/share/khelp_installer"
export KHELP_PROXYCHAINS_DIR="/usr/local/share/khelp_proxychains"
export KHELP_UFW_DIR="/usr/local/share/khelp_ufw"
export KHELP_FAIL2BAN_DIR="/usr/local/share/khelp_fail2ban"
export KHELP_IPTABLES_DIR="/usr/local/share/khelp_iptables"
export KHELP_TOR_DIR="/usr/local/share/khelp_tor"
export KHELP_LOGGING_DIR="/usr/local/share/khelp_logging"

# Configuration files
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export FAIL2BAN_CONFIG="/etc/fail2ban/jail.local"
export IPTABLES_RULES_FILE="/etc/iptables/rules.v4"
export CRONTAB_FILE="/etc/crontab"
export PROXY_LIST_FILE="/etc/proxychains/fetched_proxies.txt"

# Script paths
export UPDATE_PROXIES_SCRIPT="/usr/local/bin/update_proxies.sh"
export UFW_SCRIPT="/usr/local/bin/ufw.sh"
export IPTABLES_SCRIPT="/usr/local/bin/iptables.sh"

# Service paths
export SYSTEMD_UPDATE_PROXIES_SERVICE="/etc/systemd/system/update_proxies.service"
export SYSTEMD_UPDATE_PROXIES_TIMER="/etc/systemd/system/update_proxies.timer"
export UFW_SERVICE_PATH="/etc/systemd/system/ufw.service"
export IPTABLES_SERVICE_PATH="/etc/systemd/system/iptables.service"

# Proxy API URLs
export PROXY_API_URL1="https://spys.me/socks.txt"
export PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
export PROXY_API_URL3="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"


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

    # Rotate log file if it exceeds 1MB and compress old logs
    if [ -f "$log_file" ] && [ $(stat -c%s "$log_file") -gt 1048576 ]; then
        mv "$log_file" "$log_file.$(date +'%Y%m%d%H%M%S').gz"
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

# Log Files
log $LOG_LEVEL_INFO "UPDATE_LOG_FILE=$UPDATE_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_UPDATE_LOG_FILE=$PROXY_UPDATE_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_LOG_FILE=$IPTABLES_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_LIST_FILE=$PROXY_LIST_FILE" "$UPDATE_LOG_FILE"

# SSL Domain Log
log $LOG_LEVEL_INFO "SSL_DOMAIN=$SSL_DOMAIN" "$UPDATE_LOG_FILE"

# Directories
log $LOG_LEVEL_INFO "KHELP_UPDATE_DIR=$KHELP_UPDATE_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_INSTALLER_DIR=$KHELP_INSTALLER_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_PROXYCHAINS_DIR=$KHELP_PROXYCHAINS_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_UFW_DIR=$KHELP_UFW_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_FAIL2BAN_DIR=$KHELP_FAIL2BAN_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_IPTABLES_DIR=$KHELP_IPTABLES_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_TOR_DIR=$KHELP_TOR_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_LOGGING_DIR=$KHELP_LOGGING_DIR" "$UPDATE_LOG_FILE"

# Configuration files
log $LOG_LEVEL_INFO "PROXYCHAINS_CONF=$PROXYCHAINS_CONF" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "FAIL2BAN_CONFIG=$FAIL2BAN_CONFIG" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_RULES_FILE=$IPTABLES_RULES_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "CRONTAB_FILE=$CRONTAB_FILE" "$UPDATE_LOG_FILE"

# Script paths
log $LOG_LEVEL_INFO "UPDATE_PROXIES_SCRIPT=$UPDATE_PROXIES_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UFW_SCRIPT=$UFW_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_SCRIPT=$IPTABLES_SCRIPT" "$UPDATE_LOG_FILE"

# Service paths
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_SERVICE=$SYSTEMD_UPDATE_PROXIES_SERVICE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_TIMER=$SYSTEMD_UPDATE_PROXIES_TIMER" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UFW_SERVICE_PATH=$UFW_SERVICE_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_SERVICE_PATH=$IPTABLES_SERVICE_PATH" "$UPDATE_LOG_FILE"

# Log proxy API URLs
log $LOG_LEVEL_INFO "PROXY_API_URL1=$PROXY_API_URL1" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL2=$PROXY_API_URL2" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_API_URL3=$PROXY_API_URL3" "$UPDATE_LOG_FILE"

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

# Function to check the local network after setting up Tor routing
check_local_network() {
    log $LOG_LEVEL_INFO "Checking local network after setting up Tor routing..." "$UPDATE_LOG_FILE"

    # Detect local network IP range
    detect_ip_range

    # Perform nmap scan on the detected IP range
    nmap -sP "$ALLOWED_IP_RANGE" > /var/log/nmap_scan.log

    log $LOG_LEVEL_INFO "Local network check completed. Results saved to /var/log/nmap_scan.log" "$UPDATE_LOG_FILE"
}

# Main script execution
log $LOG_LEVEL_INFO "Starting khelp setup..." "$UPDATE_LOG_FILE"

# Functions to install individual packages
install_curl() {
    log $LOG_LEVEL_INFO "Installing curl..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y curl
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "Curl installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install curl. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install curl after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_tor() {
    log $LOG_LEVEL_INFO "Installing tor..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y tor
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "Tor installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install tor. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install tor after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_ufw() {
    log $LOG_LEVEL_INFO "Installing ufw..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y ufw
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "UFW installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install UFW. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install UFW after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_jq() {
    log $LOG_LEVEL_INFO "Installing jq..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y jq
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "jq installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install jq. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install jq after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_iptables() {
    log $LOG_LEVEL_INFO "Installing iptables..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y iptables
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "iptables installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install iptables. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install iptables after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_fail2ban() {
    log $LOG_LEVEL_INFO "Installing fail2ban..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y fail2ban
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "fail2ban installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install fail2ban. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install fail2ban after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_sslh() {
    log $LOG_LEVEL_INFO "Installing sslh..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y sslh
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "sslh installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install sslh. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install sslh after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_proxychains() {
    log $LOG_LEVEL_INFO "Installing proxychains..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y proxychains
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "proxychains installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install proxychains. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install proxychains after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_openssl() {
    log $LOG_LEVEL_INFO "Installing openssl..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y openssl
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "openssl installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install openssl. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install openssl after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_logwatch() {
    log $LOG_LEVEL_INFO "Installing logwatch..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y logwatch
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "logwatch installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install logwatch. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install logwatch after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_rsyslog() {
    log $LOG_LEVEL_INFO "Installing rsyslog..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y rsyslog
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "rsyslog installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install rsyslog. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install openssl after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

# Main script execution
log $LOG_LEVEL_INFO "Starting khelp setup..." "$UPDATE_LOG_FILE"

# Execute independent package installation tasks in parallel
install_curl &
install_tor &
install_ufw &
install_jq &
install_iptables &
install_fail2ban &
install_sslh &
install_proxychains &
install_openssl &
install_logwatch &
install_rsyslog &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All package installations completed successfully." "$UPDATE_LOG_FILE"

# Create a backup directory with a timestamp
BACKUP_DIR="/backup/configs_$(date +'%Y%m%d%H%M%S')"
mkdir -p "$BACKUP_DIR"

# Function to backup a configuration file
backup_config() {
    local config_file="$1"
    local backup_file="$BACKUP_DIR/$(basename $config_file)"
    if [ -f "$config_file" ]; then
        cp "$config_file" "$backup_file"
        log $LOG_LEVEL_INFO "Backed up $config_file to $backup_file" "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_WARNING "Configuration file $config_file not found, skipping backup" "$UPDATE_LOG_FILE"
    fi
}

# Backup configurations
log $LOG_LEVEL_INFO "Backing up configuration files..." "$UPDATE_LOG_FILE"
backup_config "/etc/proxychains.conf"
backup_config "/etc/ufw/ufw.conf"
backup_config "/etc/tor/torrc"
backup_config "/etc/resolv.conf"

# Function to update or create config files
configure_ufw() {
    log $LOG_LEVEL_INFO "Configuring UFW firewall..." "$UPDATE_LOG_FILE"
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default deny outgoing
    ufw allow from $ALLOWED_IP_RANGE to any port 22
    ufw allow out 9050/tcp
    ufw allow out 9001/tcp
    ufw allow out 443/tcp  # Erlaubt ausgehende HTTPS-Verbindungen
    ufw limit ssh/tcp
    ufw logging on
    log $LOG_LEVEL_INFO "UFW firewall configured successfully." "$UPDATE_LOG_FILE"
}

configure_fail2ban() {
    log $LOG_LEVEL_INFO "Configuring Fail2ban..." "$UPDATE_LOG_FILE"
    apt install -y fail2ban
    cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 86400  # 1 Tag
findtime  = 600
maxretry = 3

# SSH Jail
[sshd]
enabled = true

# SSHD DDOS Jail
[sshd-ddos]
enabled = true

# Apache Auth Jail
[apache-auth]
enabled  = true
port     = http,https
logpath  = /var/log/apache2/*error.log
maxretry = 3

# Recidive Jail
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
bantime = 604800  # 1 Woche
findtime = 86400  # 1 Tag
maxretry = 5

# Custom Filter Beispiel für Tor
[tor]
enabled = true
filter = tor
action = iptables[name=Tor, port="9050,9001", protocol=tcp]
logpath = /var/log/tor/log
maxretry = 3
bantime = 3600

# Custom Filter Beispiel für SOCKS5
[socks5]
enabled = true
filter = socks5
action = iptables[name=SOCKS5, port="1080", protocol=tcp]
logpath = /var/log/socks5.log
maxretry = 3
bantime = 3600
EOF

    log $LOG_LEVEL_INFO "Creating/Updating sshd-ddos filter..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/fail2ban/filter.d/sshd-ddos.conf
# Fail2Ban filter for sshd-ddos
[Definition]

_daemon = sshd

failregex = ^%(__prefix_line)sReceived disconnect from <HOST>: 11:  \[preauth\]$
            ^%(__prefix_line)sReceived disconnect from <HOST>: 11: Bye Bye \[preauth\]$
            ^%(__prefix_line)sReceived disconnect from <HOST>: 3:  \[preauth\]$
            ^%(__prefix_line)sReceived disconnect from <HOST>: 3: Bye Bye \[preauth\]$

ignoreregex =
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    log $LOG_LEVEL_INFO "Fail2ban configured and started successfully." "$UPDATE_LOG_FILE"
}

configure_iptables() {
    log $LOG_LEVEL_INFO "Configuring iptables..." "$IPTABLES_LOG_FILE"
    iptables -F
    log $LOG_LEVEL_INFO "Flushed all iptables rules." "$IPTABLES_LOG_FILE"
    iptables -X
    log $LOG_LEVEL_INFO "Deleted all user-defined iptables chains." "$IPTABLES_LOG_FILE"
    iptables -P INPUT DROP
    log $LOG_LEVEL_INFO "Set default policy for INPUT chain to DROP." "$IPTABLES_LOG_FILE"
    iptables -P FORWARD DROP
    log $LOG_LEVEL_INFO "Set default policy for FORWARD chain to DROP." "$IPTABLES_LOG_FILE"
    iptables -P OUTPUT DROP  # Ändern, um sicherzustellen, dass nur erlaubte Verbindungen ausgehen
    log $LOG_LEVEL_INFO "Set default policy for OUTPUT chain to DROP." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -i lo -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed loopback traffic on INPUT chain." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed established and related connections on INPUT chain." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p tcp -s $ALLOWED_IP_RANGE --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9050 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9001 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # Erlaubt eingehende HTTPS-Verbindungen
    iptables -A OUTPUT -p tcp --dport 9050 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 9001 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # Erlaubt ausgehende HTTPS-Verbindungen
    log $LOG_LEVEL_INFO "Set Allow Tor to ACCEPT." "$IPTABLES_LOG_FILE"
    log $LOG_LEVEL_INFO "Allowed SSH access from $ALLOWED_IP_RANGE on port 22." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
    log $LOG_LEVEL_INFO "Rate-limited new SSH connections." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    log $LOG_LEVEL_INFO "Dropped invalid packets on INPUT chain." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 10 -j ACCEPT
    log $LOG_LEVEL_INFO "Rate-limited for ICMP." "$IPTABLES_LOG_FILE"
    iptables -N LOGGING
    iptables -A INPUT -j LOGGING
    iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables: " --log-level 4
    iptables -A LOGGING -j DROP
    log $LOG_LEVEL_INFO "Configured logging for iptables." "$IPTABLES_LOG_FILE"
    # Entfernen oder nicht hinzufügen:
    # ip6tables -A INPUT -p icmpv6 -j ACCEPT

    log $LOG_LEVEL_INFO "Configured logging for iptables." "$IPTABLES_LOG_FILE"
    
    # Ensure the rules file exists and has default content if not
    if [ ! -f /etc/iptables/rules.v4 ]; then
        log $LOG_LEVEL_INFO "Creating default iptables rules file..." "$IPTABLES_LOG_FILE"
        mkdir -p /etc/iptables
        cat << EOF > /etc/iptables/rules.v4
# Default iptables rules
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]  # Ändern, um sicherzustellen, dass nur erlaubte Verbindungen ausgehen
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 9050 -j ACCEPT
-A INPUT -p tcp --dport 9001 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT  # Erlaubt eingehende HTTPS-Verbindungen
-A OUTPUT -p tcp --dport 9050 -j ACCEPT
-A OUTPUT -p tcp --dport 9001 -j ACCEPT
-A OUTPUT -p tcp --dport 443 -j ACCEPT  # Erlaubt ausgehende HTTPS-Verbindungen
-A INPUT -p icmp -m limit --limit 1/s --limit-burst 10 -j ACCEPT
COMMIT
EOF
        log $LOG_LEVEL_INFO "Created default iptables rules file." "$IPTABLES_LOG_FILE"
    fi
    
    iptables-save > /etc/iptables/rules.v4
    log $LOG_LEVEL_INFO "iptables rules configured successfully." "$IPTABLES_LOG_FILE"
}

configure_tor() {
    log $LOG_LEVEL_INFO "Configuring and enabling Tor..." "$UPDATE_LOG_FILE"
    systemctl enable tor
    systemctl start tor
    log $LOG_LEVEL_INFO "Tor configured and enabled successfully." "$UPDATE_LOG_FILE"

    # Write or overwrite the torrc file with the desired configuration
    log $LOG_LEVEL_INFO "Writing torrc file..." "$UPDATE_LOG_FILE"
    mkdir -p /etc/tor
    cat << EOF > /etc/tor/torrc
# Tor configuration file

# Enable SocksPort for Tor proxy routing
# SocksPort 9050
SocksPort 127.0.0.1:9050

# Log all messages of level 'notice' or higher to syslog
Log notice syslog

# Run Tor as a daemon
RunAsDaemon 1

# Define the directory for keeping all the keys/etc.
DataDirectory /var/lib/tor

# Enable ControlPort with CookieAuthentication
ControlPort 9051
CookieAuthentication 1

# Automap hosts on resolve
AutomapHostsOnResolve 1
VirtualAddrNetwork 10.192.0.0/10

# Hidden service configuration (uncomment and configure as needed)
# HiddenServiceDir /var/lib/tor/hidden_service/
# HiddenServicePort 80 127.0.0.1:80

# Relay configuration (uncomment and configure as needed)
# ORPort 9001
# Address your_relay_address

# Uncomment and set your contact information (optional)
# ContactInfo Your Name <your_email@example.com>

# Uncomment to mirror directory information (optional)
# DirPort 9030
# DirPortFrontPage /etc/tor/tor-exit-notice.html

# Exit policy configuration
ExitPolicy reject *:*  # Example: Reject all exit traffic
# ExitPolicy accept *:80,accept *:443,reject *:*  # Example: Allow only web traffic

# Optional Bridge configuration

# Uncomment the following lines to enable Bridge mode
# BridgeRelay 1
# PublishServerDescriptor 0
# BridgeRelay 1
# ORPort 9001
# ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# ExtORPort auto
# ContactInfo <Your_Name> <your_email@example.com>

# Multi-Hop Configuration
# Ensure at least 5 Entry Guards and 7 Directory Guards
NumEntryGuards 6
NumDirectoryGuards 10
EOF
    chmod 600 /etc/tor/torrc
    chown root:root /etc/tor/torrc
    log $LOG_LEVEL_INFO "Created torrc file." "$UPDATE_LOG_FILE"
    log $LOG_LEVEL_INFO "torrc configured successfully." "$UPDATE_LOG_FILE"
}

configure_proxychains() {
    log $LOG_LEVEL_INFO "Checking if ProxyChains is installed..." "$UPDATE_LOG_FILE"
    if ! command -v proxychains &> /dev/null; then
        log $LOG_LEVEL_ERROR "ProxyChains is not installed. Please install ProxyChains before running this script." "$UPDATE_LOG_FILE"
        exit 1
    else
        log $LOG_LEVEL_INFO "ProxyChains is already installed." "$UPDATE_LOG_FILE"
    fi

    # Check if the proxychains.conf file exists
    log $LOG_LEVEL_INFO "Checking if the proxychains.conf file exists..." "$UPDATE_LOG_FILE"
    if [ ! -f /etc/proxychains.conf ]; then
        log $LOG_LEVEL_INFO "Creating /etc/proxychains.conf file..." "$UPDATE_LOG_FILE"
        cat << 'EOF' > /etc/proxychains.conf
# ProxyChains default configuration file
# Strict chain
strict_chain

# Proxy DNS requests - no leak for DNS data
proxy_dns

# Timeouts
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Remote DNS Subnet
remote_dns_subnet 224

[ProxyList]
# Include proxies from fetched_proxies.txt
include /etc/proxychains/fetched_proxies.txt
# defaults set to "tor"
socks5  127.0.0.1 9050
EOF
        log $LOG_LEVEL_INFO "ProxyChains configuration file created." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "ProxyChains configuration file already exists." "$UPDATE_LOG_FILE"
    fi

    # Validate the proxy API URLs
    validate_url "$PROXY_API_URL1" "$UPDATE_LOG_FILE"

    log $LOG_LEVEL_INFO "ProxyChains configured successfully." "$UPDATE_LOG_FILE"
}

configure_resolv_conf() {
    log $LOG_LEVEL_INFO "Configuring resolv.conf to prevent DNS leaks..." "$UPDATE_LOG_FILE"
    
    # Backup existing resolv.conf
    cp /etc/resolv.conf /etc/resolv.conf.backup
    
    # Set DNS servers
    cat <<EOF > /etc/resolv.conf
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

    log $LOG_LEVEL_INFO "resolv.conf configured successfully." "$UPDATE_LOG_FILE"
}

configure_openssl() {
    log $LOG_LEVEL_INFO "Configuring openssl..." "$UPDATE_LOG_FILE"
    
    local ssl_dir="/etc/ssl"
    mkdir -p "$ssl_dir/private"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$ssl_dir/private/nginx-selfsigned.key" -out "$ssl_dir/certs/nginx-selfsigned.crt" -subj "/CN=your_domain.com"
    
    if [ $? -eq 0 ]; then
        log $LOG_LEVEL_INFO "openssl configured successfully." "$UPDATE_LOG_FILE"
        return 0
    else
        log $LOG_LEVEL_ERROR "Failed to configure openssl." "$UPDATE_LOG_FILE"
        return 1
    fi
}

setup_monitoring() {
    log $LOG_LEVEL_INFO "Setting up monitoring tools..." "$UPDATE_LOG_FILE"

    echo -e "#!/bin/bash\n/usr/sbin/logwatch --output mail --mailto your-email@example.com --detail high" > /etc/cron.daily/00logwatch
    chmod +x /etc/cron.daily/00logwatch

    systemctl restart fail2ban  # Ensure fail2ban is running with the existing configuration

    log $LOG_LEVEL_INFO "Monitoring tools configured successfully." "$UPDATE_LOG_FILE"
    return 0
}

setup_syslog() {
    log $LOG_LEVEL_INFO "Setting up syslog..." "$UPDATE_LOG_FILE"
    
    echo -e "*.info;mail.none;authpriv.none;cron.none /var/log/messages\nauthpriv.* /var/log/secure\nmail.* -/var/log/maillog\ncron.* /var/log/cron" >> /etc/rsyslog.conf
    systemctl restart rsyslog

    log $LOG_LEVEL_INFO "Syslog configured successfully." "$UPDATE_LOG_FILE"
    return 0
}

# Execute independent tasks in parallel
configure_ufw &
configure_fail2ban &
configure_iptables &
configure_tor &
configure_proxychains &
configure_resolv_conf &
configure_openssl &
setup_monitoring &
setup_syslog &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All independent tasks completed successfully." "$UPDATE_LOG_FILE"

# Function to create all scripts
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

create_iptables_script() {
    log $LOG_LEVEL_INFO "Creating iptables script..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/iptables.sh
#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
EOF
    chmod +x /usr/local/bin/iptables.sh
    log $LOG_LEVEL_INFO "iptables script created successfully." "$UPDATE_LOG_FILE"
}

create_update_proxies_script() {
    log $LOG_LEVEL_INFO "Creating update_proxies script..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/update_proxies.sh
#!/bin/bash

LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_ERROR=3
UPDATE_LOG_FILE="/var/log/khelp.log"
PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"
PROXY_LIST_FILE="/etc/proxychains/fetched_proxies.txt"
PROXY_API_URL1="https://spys.me/socks.txt"
PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
PROXY_API_URL3="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"

log() {
    local level=$1
    local message=$2
    local logfile=$3
    echo "$(date +"%Y-%m-%d %H:%M:%S") [LEVEL $level] $message" >> "$logfile"
}

fetch_proxies() {
  local proxy_list_file="$PROXY_LIST_FILE"
  local max_proxies=100
  local attempts=0
  local max_attempts=3

  mkdir -p "$(dirname "$proxy_list_file")"

  original_ip=$(curl -s https://api.ipify.org)
  
  fetch_and_validate_proxies() {
    local api_url=$1
    log $LOG_LEVEL_INFO "Fetching new proxy list from $api_url..." "$PROXY_UPDATE_LOG_FILE"
    local response=$(curl -s $api_url)
    if [ -n "$response" ]; then
        local valid_proxies=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
        if [ -n "$valid_proxies" ]; then
            while IFS= read -r proxy; do
                proxy_ip=$(curl -x "socks5://$proxy" -s https://api.ipify.org)
                if [ "$original_ip" != "$proxy_ip" ]; then
                    if ! grep -q "^$proxy$" "$proxy_list_file"; then
                        echo "$proxy" >> "$proxy_list_file"
                    fi
                fi
            done <<< "$valid_proxies"
            log $LOG_LEVEL_INFO "Fetched and validated $(grep -c '' "$proxy_list_file") valid proxies from $api_url." "$PROXY_UPDATE_LOG_FILE"
        else
            log $LOG_LEVEL_ERROR "No valid proxies found in the response from $api_url." "$PROXY_UPDATE_LOG_FILE"
        fi
    else
        log $LOG_LEVEL_ERROR "Failed to fetch proxies from $api_url or the response is empty." "$PROXY_UPDATE_LOG_FILE"
    fi
  }

  # Abrufen und Validieren von Proxies von beiden APIs
  fetch_and_validate_proxies "$PROXY_API_URL1"
  fetch_and_validate_proxies "$PROXY_API_URL2"
}

# Fetch and update proxy list
fetch_proxies

log $LOG_LEVEL_INFO "update_proxies script executed successfully." "$UPDATE_LOG_FILE"
EOF
    chmod +x /usr/local/bin/update_proxies.sh
    log $LOG_LEVEL_INFO "update_proxies script created successfully." "$UPDATE_LOG_FILE"
}

# Execute script creation tasks in parallel
create_ufw_script &
create_iptables_script &
create_update_proxies_script &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All script creation tasks completed successfully." "$UPDATE_LOG_FILE"

# Function to create systemd service
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
    chmod 644 /etc/systemd/system/ufw.service
    systemctl daemon-reload
    systemctl enable ufw.service
    systemctl start ufw.service
    log $LOG_LEVEL_INFO "UFW service created and enabled." "$UPDATE_LOG_FILE"
}

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
    chmod 644 /etc/systemd/system/iptables.service
    systemctl daemon-reload
    systemctl enable iptables.service
    systemctl start iptables.service
    log $LOG_LEVEL_INFO "iptables service created and enabled." "$UPDATE_LOG_FILE"
}

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
    chmod 644 /etc/systemd/system/update_proxies.service
    systemctl daemon-reload
    systemctl enable update_proxies.service
    systemctl start update_proxies.service
    log $LOG_LEVEL_INFO "Systemd service created and enabled." "$UPDATE_LOG_FILE"
}

create_update_proxies_timer() {
    log $LOG_LEVEL_INFO "Creating systemd timer to run the proxy update script every 30 minutes..." "$PROXY_TIMER_LOG_FILE"
    cat << EOF > /etc/systemd/system/update_proxies.timer
[Unit]
Description=Run update_proxies.sh every 30 minutes

[Timer]
OnCalendar=*:0/30
Persistent=true

[Install]
WantedBy=timers.target
EOF
    chmod 644 /etc/systemd/system/update_proxies.timer
    systemctl daemon-reload
    systemctl enable update_proxies.timer
    systemctl start update_proxies.timer
    log $LOG_LEVEL_INFO "Systemd timer created and started." "$PROXY_TIMER_LOG_FILE"
}

# Execute systemd service creation tasks in parallel
create_ufw_service &
create_iptables_service &
create_update_proxies_service &
create_update_proxies_timer &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All systemd service creation tasks completed successfully." "$UPDATE_LOG_FILE"

# Call the display_logo function
display_logo

# Verifying systemd services
log $LOG_LEVEL_INFO "Verifying systemd services..." "$UPDATE_LOG_FILE"
systemctl status update_proxies | tee -a "$UPDATE_LOG_FILE"
systemctl status iptables | tee -a "$UPDATE_LOG_FILE"
systemctl status ufw | tee -a "$UPDATE_LOG_FILE"
systemctl status fail2ban | tee -a "$UPDATE_LOG_FILE"
systemctl status rsyslog | tee -a "$UPDATE_LOG_FILE"

# Scan local network
log $LOG_LEVEL_INFO "Scanning local network..." "$UPDATE_LOG_FILE"
check_local_network

log $LOG_LEVEL_INFO "Verification completed." "$UPDATE_LOG_FILE"
