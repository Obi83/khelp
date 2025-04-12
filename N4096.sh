#!/bin/bash
 
set -euo pipefail
umask 077
trap 'cleanup_function' EXIT

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Define the display_logo function
display_logo() {                                                                                                      
echo "  _    _          _              _  _        _____               ______         " 
echo " | |  | |        | |           _| || |_     |  __ \             |  ____|        " 
echo " | | _| |__   ___| |_ __      |_  __  _|    | |__) | __ _____  _| |__ _____  __ "
echo " | |/ / '_ \ / _ \ | '_ \      _| || |_     |  ___/ '__/ _ \ \/ /  __/ _ \ \/ / "
echo " |   <| | | |  __/ | |_) |    |_  __  _|    | |   | | | (_) >  <| | | (_) >  <  "
echo " |_|\_\_| |_|\___|_| .__/       |_||_|      |_|   |_|  \___/_/\_\_|  \___/_/\_\ "
echo "                   | |                                                          "
echo "                   |_|                                                          "
}

# Call the display_logo function
display_logo

# Set USER_HOME based on whether the script is run with sudo or not
if [ -n "$SUDO_USER" ]; then
    export USER_HOME=$(eval echo ~${SUDO_USER})
else
    export USER_HOME=$HOME
fi

# Example usage of mktemp for temporary files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Function to perform cleanup
cleanup_function() {
    # Cleanup commands
    echo "Cleaning up..."
    rm -rf "$TEMP_DIR"
}

# Environment variables for paths and configurations
# Log Files
export UPDATE_LOG_FILE="/var/log/khelp.log"
export PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"
export PROXY_TIMER_LOG_FILE="/var/log/timer_proxies.log"
export IPTABLES_LOG_FILE="/var/log/khelp_iptables.log"

# Directories
export KHELP_UPDATE_DIR="/usr/local/share/khelp_update"
export KHELP_INSTALLER_DIR="/usr/local/share/khelp_installer"
export KHELP_PROXYCHAINS_DIR="/usr/local/share/khelp_proxychains"
export KHELP_UFW_DIR="/usr/local/share/khelp_ufw"
export KHELP_FAIL2BAN_DIR="/usr/local/share/khelp_fail2ban"
export KHELP_IPTABLES_DIR="/usr/local/share/khelp_iptables"
export KHELP_TOR_DIR="/usr/local/share/khelp_tor"
export KHELP_LOGGING_DIR="/usr/local/share/khelp_logging"

# Proxy/Proxychains Variables
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export PROXY_LIST_FILE="/etc/proxychains/fetched_proxies.txt"
export UPDATE_PROXIES_SCRIPT="/usr/local/bin/update_proxies.sh"
export PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"
export PROXY_TIMER_LOG_FILE="/var/log/timer_proxies.log"
export SYSTEMD_UPDATE_PROXIES_SERVICE="/etc/systemd/system/update_proxies.service"
export SYSTEMD_UPDATE_PROXIES_TIMER="/etc/systemd/system/update_proxies.timer"

# Fail2Ban Variables
export FAIL2BAN_CONFIG="/etc/fail2ban/jail.local"
export KHELP_FAIL2BAN_DIR="/usr/local/share/khelp_fail2ban"

# SSL Variables
export SSL_DIR="/etc/ssl"
export SSL_PRIVATE_DIR="$SSL_DIR/private"
export SSL_CERTS_DIR="$SSL_DIR/certs"
export SSL_KEY="$SSL_PRIVATE_DIR/nginx-selfsigned.key"
export SSL_CERT="$SSL_CERTS_DIR/nginx-selfsigned.crt"
export SSL_DHPARAM="$SSL_CERTS_DIR/dhparam.pem"
export NGX_SSL_CONF="/etc/nginx/snippets/self-signed.conf"
export DOMAIN="example.com"  # Replace with your actual domain

# Nginx Directories
export time_local="$(date +'%Y-%m-%d %H:%M:%S')"
export NGX_CONF_DIR="/etc/nginx"
export NGX_SITES_AVAILABLE="$NGX_CONF_DIR/sites-available"
export NGX_CONF="/etc/nginx/sites-available/tor_proxy"  # Kleinbuchstaben
export NGX_SITES_ENABLED="$NGX_CONF_DIR/sites-enabled"

# IPTables Variables
export IPTABLES_RULES_FILE="/etc/iptables/rules.v4"
export IPTABLES_SCRIPT="/usr/local/bin/iptables.sh"
export IPTABLES_LOG_FILE="/var/log/khelp_iptables.log"
export IPTABLES_SERVICE_PATH="/etc/systemd/system/iptables.service"

# UFW Variables
export UFW_SCRIPT="/usr/local/bin/ufw.sh"
export UFW_SERVICE_PATH="/etc/systemd/system/ufw.service"
export KHELP_UFW_DIR="/usr/local/share/khelp_ufw"

# Crontab Configuration
export CRONTAB_FILE="/etc/crontab"

# Proxy API URLs
export PROXY_API_URL1="https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt"

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
        gzip "$log_file"
        mv "$log_file.gz" "$log_file.$(date +'%Y%m%d%H%M%S').gz"
        touch "$log_file"
        chmod 600 "$log_file"
    fi

    # Ensure log file permissions
    if [ ! -f "$log_file" ]; then
        touch "$log_file"
        chmod 600 "$log_file"
    fi

    # Include metadata in the log entry
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S.%3N')
    local script_name=$(basename "$0")
    local user=$(whoami)
    local hostname=$(hostname)
    local pid=$$
    local ppid=$(ps -o ppid= -p $$)

    # Format and write the log entry
    echo "$timestamp [$log_level_name] [$script_name] [$user@$hostname] [PID $pid, PPID $ppid] - $message" | tee -a "$log_file"
}

validate_url() {
    local url="$1"
    local log_file="$2"

    # Check if URL starts with http or https
    if [[ ! $url =~ ^https?:// ]]; then
        log $LOG_LEVEL_ERROR "Invalid URL: $url. URL must start with http:// or https://" "$log_file"
        return 1
    fi

    # Check if URL is well-formed
    if ! [[ $url =~ ^https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:[0-9]{1,5})?(/.*)?$ ]]; then
        log $LOG_LEVEL_ERROR "Invalid URL: $url. URL is not well-formed." "$log_file"
        return 1
    fi

    log $LOG_LEVEL_INFO "Valid URL: $url" "$log_file"
    return 0
}

# Log Files
log $LOG_LEVEL_INFO "UPDATE_LOG_FILE=$UPDATE_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_UPDATE_LOG_FILE=$PROXY_UPDATE_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_LOG_FILE=$IPTABLES_LOG_FILE" "$UPDATE_LOG_FILE"

# Directories
log $LOG_LEVEL_INFO "KHELP_UPDATE_DIR=$KHELP_UPDATE_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_INSTALLER_DIR=$KHELP_INSTALLER_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_PROXYCHAINS_DIR=$KHELP_PROXYCHAINS_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_UFW_DIR=$KHELP_UFW_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_FAIL2BAN_DIR=$KHELP_FAIL2BAN_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_IPTABLES_DIR=$KHELP_IPTABLES_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_TOR_DIR=$KHELP_TOR_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_LOGGING_DIR=$KHELP_LOGGING_DIR" "$UPDATE_LOG_FILE"

# SSL Logs
log $LOG_LEVEL_INFO "SSL_DIR=$SSL_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SSL_PRIVATE_DIR=$SSL_PRIVATE_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SSL_CERTS_DIR=$SSL_CERTS_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SSL_KEY=$SSL_KEY" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SSL_CERT=$SSL_CERT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SSL_DHPARAM=$SSL_DHPARAM" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "NGX_SSL_CONF=$NGX_SSL_CONF" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "DOMAIN=$DOMAIN" "$UPDATE_LOG_FILE"

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

# Set permissions for main log files
chmod 644 /var/log/khelp.log
chown root:adm /var/log/khelp.log

# Set permissions for NGINX log files
chmod 644 /var/log/nginx/error.log
chmod 644 /var/log/nginx/access.log
chown www-data:adm /var/log/nginx/error.log
chown www-data:adm /var/log/nginx/access.log

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
    local interface
    interface=$(ip route | grep default | awk '{print $5}')

    # Prüfe, ob eine primäre Schnittstelle gefunden wurde
    if [ -z "$interface" ]; then
        log $LOG_LEVEL_WARNING "PRIMARY_INTERFACE is not set. Attempting to use fallback interfaces." "$UPDATE_LOG_FILE"

        # Erster Fallback: Versuche eth0
        if ip link show eth0 > /dev/null 2>&1; then
            PRIMARY_INTERFACE="eth0"
            log $LOG_LEVEL_INFO "Fallback to eth0 as PRIMARY_INTERFACE." "$UPDATE_LOG_FILE"
        # Zweiter Fallback: Versuche wlan0
        elif ip link show wlan0 > /dev/null 2>&1; then
            PRIMARY_INTERFACE="wlan0"
            log $LOG_LEVEL_INFO "Fallback to wlan0 as PRIMARY_INTERFACE." "$UPDATE_LOG_FILE"
        else
            log $LOG_LEVEL_ERROR "No valid network interface found. Please check your network settings." "$UPDATE_LOG_FILE"
            exit 1
        fi
    else
        PRIMARY_INTERFACE="$interface"
        log $LOG_LEVEL_INFO "Detected primary interface: $PRIMARY_INTERFACE" "$UPDATE_LOG_FILE"
    fi
}

# Determine the primary network interface
PRIMARY_INTERFACE=$(get_primary_interface)
if [ $? -ne 0 ] || [ -z "$PRIMARY_INTERFACE" ]; then
    log $LOG_LEVEL_ERROR "Failed to determine the primary network interface." "$UPDATE_LOG_FILE"
    exit 1
fi
log $LOG_LEVEL_INFO "Primary network interface determined: $PRIMARY_INTERFACE" "$UPDATE_LOG_FILE"

# Export the primary interface
export PRIMARY_INTERFACE

# Function to check the local network after setting up Tor routing
check_local_network() {
    log $LOG_LEVEL_INFO "Checking local network after setting up Tor routing..." "$UPDATE_LOG_FILE"

    # Detect local network IP range
    detect_ip_range

    # Perform nmap scan on the detected IP range using TCP SYN scan instead of ICMP ping
    nmap -sS "$ALLOWED_IP_RANGE" > /var/log/nmap_scan.log

    log $LOG_LEVEL_INFO "Local network check completed. Results saved to /var/log/nmap_scan.log" "$UPDATE_LOG_FILE"
}

# Main script execution
log $LOG_LEVEL_INFO "Starting khelp # proxfox setup..." "$UPDATE_LOG_FILE"

# Functions to install individual packages
install_packages() {
    log $LOG_LEVEL_INFO "Installing packages..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y curl tor ufw jq iptables fail2ban sslh proxychains openssl logwatch rsyslog nginx coreutils certbot python3-certbot-nginx
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "packages installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install packages. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install packages after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

# Execute independent package installation tasks in parallel
install_packages

log $LOG_LEVEL_INFO "All package installations completed successfully." "$UPDATE_LOG_FILE"

# Create a backup directory with a timestamp
BACKUP_DIR="/backup/configs_$(date +'%Y%m%d%H%M%S')"
mkdir -p "$BACKUP_DIR"

# Function to backup a configuration file
backup_config() {
    local config_file="$1"
    local backup_file="$BACKUP_DIR/$(basename $config_file)"
    
    # Ensure the backup directory exists
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
    fi

    if [ -f "$config_file" ]; then
        cp "$config_file" "$backup_file"
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "Backed up $config_file to $backup_file" "$UPDATE_LOG_FILE"
        else
            log $LOG_LEVEL_ERROR "Failed to backup $config_file" "$UPDATE_LOG_FILE"
        fi
    else
        log $LOG_LEVEL_WARNING "Configuration file $config_file not found, skipping backup" "$UPDATE_LOG_FILE"
    fi
}

# Backup configurations
log $LOG_LEVEL_INFO "Backing up configuration files..." "$UPDATE_LOG_FILE"
backup_config "/etc/proxychains.conf"
backup_config "/etc/ufw/ufw.conf"
backup_config "/etc/tor/torrc"
backup_config "/etc/nginx/nginx.conf"
backup_config "/etc/rsyslog.conf"
backup_config "/etc/nginx/sites-available/default"

# Configure Fail2Ban Service
configure_fail2ban() {
    log $LOG_LEVEL_INFO "Configuring Fail2ban..." "$UPDATE_LOG_FILE"
    apt install -y fail2ban

    cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 3600
findtime  = 600
maxretry = 3

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
bantime  = 604800  # 1 Woche
findtime = 86400   # 1 Tag
maxretry = 5

[sshd]
enabled = true
bantime = 86400  # 1 Tag

[sshd-ddos]
enabled = true

[apache-auth]
enabled  = true
port     = http,https
logpath  = /var/log/apache2/*error.log
maxretry = 3
bantime  = 7200  # 2 Stunden

[nginx-http-auth]
enabled = true
port    = http,https
filter  = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime  = 7200  # 2 Stunden

#destemail = your-email@example.com
#sender = fail2ban@example.com
#action = %(action_mwl)s
EOF

    log $LOG_LEVEL_INFO "Creating/Updating sshd-ddos filter..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/fail2ban/filter.d/sshd-ddos.conf
# Fail2Ban filter for sshd-ddos
[Definition]

_daemon = sshd

failregex = ^Received disconnect from <HOST>: 11:  \[preauth\]$
            ^Received disconnect from <HOST>: 11: Bye Bye \[preauth\]$
            ^Received disconnect from <HOST>: 3:  \[preauth\]$
            ^Received disconnect from <HOST>: 3: Bye Bye \[preauth\]$

ignoreregex =
EOF

    # Set permissions for fail2ban configuration files
    chmod 644 /etc/fail2ban/jail.local
    chmod 644 /etc/fail2ban/filter.d/sshd-ddos.conf
    chown root:root /etc/fail2ban/jail.local
    chown root:root /etc/fail2ban/filter.d/sshd-ddos.conf
    
    systemctl enable fail2ban
    systemctl start fail2ban
    log $LOG_LEVEL_INFO "Fail2ban configured and started successfully." "$UPDATE_LOG_FILE"
}

configure_fail2ban

configure_ufw() {
    log $LOG_LEVEL_INFO "Configuring UFW firewall..." "$UPDATE_LOG_FILE"
    
    # Check if UFW is installed
    if ! command -v ufw &> /dev/null; then
        log $LOG_LEVEL_ERROR "UFW is not installed. Please install UFW before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Enable IPv6 support in UFW
    if [ -f /etc/default/ufw ]; then
        sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
        log $LOG_LEVEL_INFO "Enabled IPv6 support in UFW configuration." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "UFW configuration file /etc/default/ufw not found. Cannot enable IPv6." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Reload UFW to apply configuration changes
    ufw reload

    # Configure UFW rules
    ufw --force enable

    # Standardrichtlinien setzen
    ufw default deny incoming
    ufw default deny outgoing

    # Eingehende Verbindungen erlauben
    ufw allow in 9050/tcp  # SOCKS5 
    ufw allow in 443/tcp   # HTTPS
         
    # Ausgehende Verbindungen erlauben
    ufw allow out 443/tcp  # HTTPS
    ufw allow out 9050/tcp  # SOCKS5

    # Block all IPv6 traffic (optional redundancy for additional coverage)
    if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = "0" ]; then
        ufw deny proto ipv6 from any to any comment "Block all IPv6 traffic"
        log $LOG_LEVEL_INFO "Blocked all incoming and outgoing IPv6 traffic." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_WARNING "IPv6 is disabled on the system. Skipping IPv6 configuration in UFW." "$UPDATE_LOG_FILE"
    fi

    # Logging
    ufw logging full

    # Enable UFW service
    systemctl enable ufw
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to enable UFW service." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Start UFW service
    systemctl start ufw
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to start UFW service." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Verify UFW status
    ufw status verbose
    if [ $? -eq 0 ]; then
        log $LOG_LEVEL_INFO "UFW firewall configured successfully." "$UPDATE_LOG_FILE"
        return 0
    else
        log $LOG_LEVEL_ERROR "Failed to configure UFW firewall." "$UPDATE_LOG_FILE"
        return 1
    fi
}

configure_iptables() {
    log $LOG_LEVEL_INFO "Configuring iptables..." "$IPTABLES_LOG_FILE"
    
    # Check if iptables is installed
    if ! command -v iptables &> /dev/null; then
        log $LOG_LEVEL_ERROR "iptables is not installed. Please install iptables before running this script." "$IPTABLES_LOG_FILE"
        return 1
    fi

    # Flush all existing rules
    iptables -F
    iptables -X
    ip6tables -F
    ip6tables -X
    log $LOG_LEVEL_INFO "Flushed all iptables and ip6tables rules." "$IPTABLES_LOG_FILE"

    # Set default policies for IPv4
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    log $LOG_LEVEL_INFO "Set default policies for iptables (IPv4)." "$IPTABLES_LOG_FILE"

    # Set default policies for IPv6
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
    log $LOG_LEVEL_INFO "Set default policies for ip6tables (IPv6)." "$IPTABLES_LOG_FILE"

    # Allow loopback traffic and established connections for IPv4
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed loopback and established connections for iptables (IPv4)." "$IPTABLES_LOG_FILE"

    # Allow loopback traffic and established connections for IPv6
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed loopback and established connections for ip6tables (IPv6)." "$IPTABLES_LOG_FILE"

    # DNS setting
    iptables -A OUTPUT -p udp --dport 53 -j REJECT
    iptables -A OUTPUT -p tcp --dport 53 -j REJECT

    # Define important ports
    local important_ports=(80 443 9040 9050)

    # Configure IPv4 rules
    for port in "${important_ports[@]}"; do
        if [[ "$port" -eq 443 || "$port" -eq 9050 ]]; then
            # Allow outgoing HTTPS and SOCKS5 only
            iptables -A OUTPUT -p tcp --dport "$port" -j ACCEPT
            log $LOG_LEVEL_INFO "Allowed outgoing traffic on port $port (IPv4)." "$IPTABLES_LOG_FILE"
        else
            # Drop all other outgoing traffic explicitly
            iptables -A OUTPUT -p tcp --dport "$port" -j DROP
            log $LOG_LEVEL_INFO "Blocked outgoing traffic on port $port (IPv4)." "$IPTABLES_LOG_FILE"
        fi
        # Block all incoming traffic on these ports
        iptables -A INPUT -p tcp --dport "$port" -j DROP
        log $LOG_LEVEL_INFO "Blocked incoming traffic on port $port (IPv4)." "$IPTABLES_LOG_FILE"
    done

    # Configure IPv6 rules
    for port in "${important_ports[@]}"; do
        # Block all incoming and outgoing traffic for IPv6
        ip6tables -A INPUT -p tcp --dport "$port" -j DROP
        ip6tables -A OUTPUT -p tcp --dport "$port" -j DROP
        log $LOG_LEVEL_INFO "Blocked traffic on port $port (IPv6)." "$IPTABLES_LOG_FILE"
    done

    # Rate-limit for all defined ports (IPv4)
    for port in "${important_ports[@]}"; do
        iptables -A INPUT -p tcp --dport "$port" -m limit --limit 10/second --limit-burst 20 -j ACCEPT
        log $LOG_LEVEL_INFO "Applied rate-limit for port $port (IPv4)." "$IPTABLES_LOG_FILE"
    done

    # Rate-limit SSH (Port 22)
    iptables -A OUTPUT -p tcp --dport 22 -j DROP
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
    log $LOG_LEVEL_INFO "Applied rate-limit for SSH (Port 22)." "$IPTABLES_LOG_FILE"

    # Rate-limit ICMP (Ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second --limit-burst 5 -j ACCEPT
    log $LOG_LEVEL_INFO "Applied rate-limit for ICMP (Ping)." "$IPTABLES_LOG_FILE"
    
    # Drop invalid packets for IPv4 and IPv6
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP
    log $LOG_LEVEL_INFO "Dropped invalid packets for iptables and ip6tables." "$IPTABLES_LOG_FILE"

    # Create a logging chain for IPv4
    iptables -N LOGGING
    iptables -A INPUT -j LOGGING
    iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables: " --log-level 4
    iptables -A LOGGING -j DROP
    log $LOG_LEVEL_INFO "Configured logging for iptables (IPv4)." "$IPTABLES_LOG_FILE"

    # Save the iptables rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    log $LOG_LEVEL_INFO "Saved iptables and ip6tables rules." "$IPTABLES_LOG_FILE"
}

configure_tor() {
    log $LOG_LEVEL_INFO "Configuring and enabling Tor..." "$UPDATE_LOG_FILE"
    
    # Check if Tor is installed
    if ! command -v tor &> /dev/null; then
        log $LOG_LEVEL_ERROR "Tor is not installed. Please install Tor before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Enable and start Tor service
    systemctl enable tor
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to enable Tor service." "$UPDATE_LOG_FILE"
        return 1
    fi

    systemctl start tor
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to start Tor service." "$UPDATE_LOG_FILE"
        return 1
    fi

    log $LOG_LEVEL_INFO "Tor configured and enabled successfully." "$UPDATE_LOG_FILE"

    # Write or overwrite the torrc file with the desired configuration
    log $LOG_LEVEL_INFO "Writing torrc file..." "$UPDATE_LOG_FILE"
    mkdir -p /etc/tor
    cat << EOF > /etc/tor/torrc
# Tor configuration file

# Enable SocksPort for Tor proxy routing
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
# Bridge <bridge_address>
# Bridge <bridge_address>
# Bridge <bridge_address>

# Specify the number of Entry Guards (optional)
NumEntryGuards 6
# Specify the number of Directory Guards
NumDirectoryGuards 10

# BridgeRelay 1
# PublishServerDescriptor 0
# BridgeRelay 1
# ORPort 9001
# ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# ExtORPort auto
# ContactInfo <Your_Name> <your_email@example.com>
EOF
    chmod 600 /etc/tor/torrc
    chown root:root /etc/tor/torrc
    log $LOG_LEVEL_INFO "Created torrc file." "$UPDATE_LOG_FILE"
    log $LOG_LEVEL_INFO "torrc configured successfully." "$UPDATE_LOG_FILE"
    return 0
}

configure_proxychains() {
    log $LOG_LEVEL_INFO "Checking if ProxyChains is installed..." "$UPDATE_LOG_FILE"
    
    # Check if ProxyChains is installed
    if ! command -v proxychains &> /dev/null; then
        log $LOG_LEVEL_ERROR "ProxyChains is not installed. Please install ProxyChains before running this script." "$UPDATE_LOG_FILE"
        return 1
    else
        log $LOG_LEVEL_INFO "ProxyChains is already installed." "$UPDATE_LOG_FILE"
    fi

    # Ensure the directory for fetched proxies exists
    if [ ! -d /etc/proxychains ]; then
        mkdir -p /etc/proxychains
        chmod 755 /etc/proxychains
    fi

    # Ensure the validated_proxies.txt file exists and set permissions
    touch /etc/proxychains/validated_proxies.txt
    chmod 644 /etc/proxychains/validated_proxies.txt
    chown root:root /etc/proxychains/validated_proxies.txt

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
# Include proxies from validated_proxies.txt
include /etc/proxychains/validated_proxies.txt
# defaults set to "tor"
socks5  127.0.0.1 9050
EOF
        chmod 600 /etc/proxychains.conf
        chown root:root /etc/proxychains.conf
        log $LOG_LEVEL_INFO "ProxyChains configuration file created." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "ProxyChains configuration file already exists." "$UPDATE_LOG_FILE"
    fi

    # Validate the proxy API URLs
    validate_url "$PROXY_API_URL1" "$UPDATE_LOG_FILE"
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Invalid Proxy API URL: $PROXY_API_URL1" "$UPDATE_LOG_FILE"
        return 1
    fi

    local dns=$1
    if proxychains dig @$dns google.com &> /dev/null; then
        log $LOG_LEVEL_INFO "DNS server $dns is reachable through SOCKS5 proxy." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "DNS server $dns is not reachable through SOCKS5 proxy." "$UPDATE_LOG_FILE"
        return 1
    fi

    log $LOG_LEVEL_INFO "ProxyChains configured successfully." "$UPDATE_LOG_FILE"
    return 0

}

configure_openssl() {
    log $LOG_LEVEL_INFO "Configuring OpenSSL..." "$UPDATE_LOG_FILE"
    
    # Check if OpenSSL is installed
    if ! command -v openssl &> /dev/null; then
        log $LOG_LEVEL_ERROR "OpenSSL is not installed. Please install OpenSSL before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Create necessary directories
    mkdir -p "$SSL_PRIVATE_DIR"
    mkdir -p "$SSL_CERTS_DIR"

    # Verify directories were created
    if [ ! -d "$SSL_PRIVATE_DIR" ] || [ ! -d "$SSL_CERTS_DIR" ]; then
        log $LOG_LEVEL_ERROR "Failed to create required directories for SSL certificates." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Generate OpenSSL configuration file
    local openssl_config="$SSL_DIR/openssl.cnf"
    log $LOG_LEVEL_INFO "Generating OpenSSL configuration file at $openssl_config..." "$UPDATE_LOG_FILE"
    cat <<EOF > "$openssl_config"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $DOMAIN

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = www.$DOMAIN
EOF

    # Generate a self-signed certificate
    log $LOG_LEVEL_INFO "Generating SSL certificate for domain: $DOMAIN..." "$UPDATE_LOG_FILE"
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -config "$openssl_config" -extensions v3_req -sha256

    # Check if the operation was successful
    if [ $? -eq 0 ]; then
        log $LOG_LEVEL_INFO "OpenSSL configured successfully for domain: $DOMAIN." "$UPDATE_LOG_FILE"
        return 0
    else
        log $LOG_LEVEL_ERROR "Failed to configure OpenSSL." "$UPDATE_LOG_FILE"
        return 1
    fi
}

setup_monitoring() {
    log $LOG_LEVEL_INFO "Setting up monitoring tools..." "$UPDATE_LOG_FILE"
    
    # Check if Logwatch is installed
    if ! command -v logwatch &> /dev/null; then
        log $LOG_LEVEL_ERROR "Logwatch is not installed. Please install Logwatch before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Configure Logwatch to run daily and send email reports
    log $LOG_LEVEL_INFO "Configuring Logwatch to run daily..." "$UPDATE_LOG_FILE"
    echo -e "#!/bin/bash\n/usr/sbin/logwatch --output mail --mailto your-email@example.com --detail high" > /etc/cron.daily/00logwatch
    chmod +x /etc/cron.daily/00logwatch
    log $LOG_LEVEL_INFO "Logwatch daily configuration created." "$UPDATE_LOG_FILE"

    # Ensure Fail2ban is running with the existing configuration
    log $LOG_LEVEL_INFO "Restarting Fail2ban to ensure it is running with the existing configuration..." "$UPDATE_LOG_FILE"
    systemctl restart fail2ban
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to restart Fail2ban." "$UPDATE_LOG_FILE"
        return 1
    fi

    log $LOG_LEVEL_INFO "Monitoring tools configured successfully." "$UPDATE_LOG_FILE"
    return 0
}

setup_syslog() {
    log $LOG_LEVEL_INFO "Setting up syslog..." "$UPDATE_LOG_FILE"
    
    # Check if rsyslog is installed
    if ! command -v rsyslogd &> /dev/null; then
        log $LOG_LEVEL_ERROR "rsyslog is not installed. Please install rsyslog before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Backup existing rsyslog.conf
    if [ ! -f /etc/rsyslog.conf.backup ]; then
        cp /etc/rsyslog.conf /etc/rsyslog.conf.backup
        log $LOG_LEVEL_INFO "Backup of rsyslog.conf created." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "Backup of rsyslog.conf already exists." "$UPDATE_LOG_FILE"
    fi

    # Append syslog configuration
    cat <<EOF >> /etc/rsyslog.conf
# Custom syslog configuration
*.info;mail.none;authpriv.none;cron.none /var/log/messages
authpriv.* /var/log/secure
mail.* -/var/log/maillog
cron.* /var/log/cron
EOF

    # Restart rsyslog service
    systemctl restart rsyslog
    if [ $? -eq 0 ]; then
        log $LOG_LEVEL_INFO "Syslog configured successfully." "$UPDATE_LOG_FILE"
        return 0
    else
        log $LOG_LEVEL_ERROR "Failed to restart rsyslog." "$UPDATE_LOG_FILE"
        return 1
    fi
}

touch /var/log/nmap_scan.log
chmod 644 /var/log/nmap_scan.log
chown root:adm /var/log/nmap_scan.log
touch /var/log/khelp_iptables.log
chmod 644 /var/log/khelp_iptables.log
chown root:adm /var/log/khelp_iptables.log
touch "$PROXY_TIMER_LOG_FILE"
chmod 644 "$PROXY_TIMER_LOG_FILE"
chown root:root "$PROXY_TIMER_LOG_FILE"

configure_ufw &
configure_iptables &
configure_tor &
configure_proxychains &
configure_openssl &
setup_monitoring &
setup_syslog &

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
# Restore IPv4 rules
if [ -f /etc/iptables/rules.v4 ]; then
    iptables-restore < /etc/iptables/rules.v4
else
    echo "/etc/iptables/rules.v4 not found. Exiting."
    exit 1
fi

# Restore IPv6 rules
if [ -f /etc/iptables/rules.v6 ]; then
    ip6tables-restore < /etc/iptables/rules.v6
else
    echo "/etc/iptables/rules.v6 not found. Skipping IPv6 rules."
fi
EOF
    chmod +x /usr/local/bin/iptables.sh
    log $LOG_LEVEL_INFO "iptables script created successfully." "$UPDATE_LOG_FILE"
}

create_update_proxies_script() {
    log $LOG_LEVEL_INFO "Creating update_proxies script..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/update_proxies.sh
#!/bin/bash

# Path to input and output files
input_file="/etc/proxychains/fetched_proxies.txt"
output_file="/etc/proxychains/validated_proxies.txt"

LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_ERROR=3
UPDATE_LOG_FILE="/var/log/khelp.log"
PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"
PROXY_LIST_FILE="/etc/proxychains/fetched_proxies.txt"
PROXY_API_URL1="https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt"

log() {
    local level=$1
    local message=$2
    local logfile=$3
    echo "$(date +"%Y-%M-%d %H:%M:%S") [LEVEL $level] $message" >> "$logfile"
}

fetch_proxies() {
    log $LOG_LEVEL_INFO "Starting fetch_proxies function..." "$UPDATE_LOG_FILE"
    local proxy_api_urls=(
        "https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt"
    )
    local proxy_list_file="/etc/proxychains/fetched_proxies.txt"
    local max_proxies=100
    local attempts=0
    local max_attempts=3
    local all_proxies=""
    local fetched_proxies_set=()
    
    mkdir -p "$(dirname "$proxy_list_file")"
    
    # Load existing proxies into a set to avoid duplicates
    if [ -f "$proxy_list_file" ]; then
        while IFS= read -r proxy; do
            fetched_proxies_set+=("$proxy")
        done < "$proxy_list_file"
    fi
    
    while [ $attempts -lt $max_attempts ]; do
        for proxy_api_url in "${proxy_api_urls[@]}"; do
            log $LOG_LEVEL_INFO "Fetching new proxy list from $proxy_api_url (attempt $((attempts + 1)))..." "$UPDATE_LOG_FILE"
            
            # Use curl with certificate validation
            local response=$(curl --fail --silent --show-error --location --cacert /etc/ssl/certs/ca-certificates.crt $proxy_api_url)
            if [ $? -ne 0 ]; then
                log $LOG_LEVEL_ERROR "Failed to fetch proxies from $proxy_api_url. Curl error code: $?" "$UPDATE_LOG_FILE"
                continue
            fi
            
            if [ -n "$response" ]; then
                local valid_proxies=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -n $max_proxies)
                if [ -n "$valid_proxies" ]; then
                    while IFS= read -r proxy; do
                        if [[ ! " ${fetched_proxies_set[*]} " =~ " ${proxy} " ]]; then
                            fetched_proxies_set+=("$proxy")
                            all_proxies+="$proxy\n"
                        fi
                    done <<< "$valid_proxies"
                else
                    log $LOG_LEVEL_ERROR "No valid proxies found in the response from $proxy_api_url." "$UPDATE_LOG_FILE"
                fi
            else
                log $LOG_LEVEL_ERROR "Failed to fetch proxies from $proxy_api_url or the response is empty." "$UPDATE_LOG_FILE"
            fi
        done
        
        if [ -n "$all_proxies" ]; then
            echo -e "$all_proxies" > "$proxy_list_file"
            log $LOG_LEVEL_INFO "Fetched $(echo -e "$all_proxies" | wc -l) valid proxies." "$UPDATE_LOG_FILE"
            return 0
        fi
        
        attempts=$((attempts + 1))
        sleep 5
    done
    
    log $LOG_LEVEL_CRITICAL "Failed to fetch valid proxies after $max_attempts attempts. Exiting script." "$UPDATE_LOG_FILE"
    exit 1
}

read_proxies_from_file() {
    log $LOG_LEVEL_INFO "Starting read_proxies_from_file function..." "$UPDATE_LOG_FILE"
    local file_path="$1"
    if [ -f "$file_path" ]; then
        cat "$file_path"
    else
        log $LOG_LEVEL_ERROR "File $file_path does not exist." "$UPDATE_LOG_FILE"
    fi
}

filter_proxies() {
    log $LOG_LEVEL_INFO "Starting filter_proxies function..." "$UPDATE_LOG_FILE"
    local proxy_list="$1"
    local anonymity_level="$2"
    local filtered_proxies=""
    echo "$proxy_list" | while IFS= read -r proxy; do
        parts=($proxy)
        if [ "${#parts[@]}" -lt 2 ]; then
            continue
        fi

        ip_port="${parts[0]}"
        IFS='-' read -r -a attributes <<< "${parts[1]}"

        if [ "${#attributes[@]}" -ne 3 ]; then
            continue
        fi

        code="${attributes[0]}"
        anonymity="${attributes[1]}"
        ssl="${attributes[2]:0:1}"

        if [ "$anonymity" == "$anonymity_level" ]; then
            filtered_proxies+="$proxy\n"
        fi
    done
    echo -e "$filtered_proxies"
}

write_to_file() {
    log $LOG_LEVEL_INFO "Starting write_to_file function..." "$UPDATE_LOG_FILE"
    local proxy_list="$1"
    local file_path="$2"
    echo "$proxy_list" > "$file_path"
    log $LOG_LEVEL_INFO "Written filtered proxies to $file_path" "$UPDATE_LOG_FILE"
}

write_new_list() {
    log $LOG_LEVEL_INFO "Starting write_new_list function..." "$UPDATE_LOG_FILE"
    local anonymity_level="H"
    proxies=$(read_proxies_from_file "$input_file")
    filtered_proxies=$(filter_proxies "$proxies" "$anonymity_level")
    write_to_file "$filtered_proxies" "$output_file"
    chmod 644 "$input_file"
    chmod 644 "$output_file"
    log $LOG_LEVEL_INFO "Set permissions for $output_file to 644" "$UPDATE_LOG_FILE"
}

get_proxy_ip() {
    local proxy=$1
    curl -s --max-time 10 -x socks5://$proxy https://api.ipify.org
}

main() {
    log $LOG_LEVEL_INFO "Starting update_proxies script..." "$UPDATE_LOG_FILE"

    fetch_proxies
    write_new_list

    log $LOG_LEVEL_INFO "update_proxies script executed successfully." "$UPDATE_LOG_FILE"
}

main
EOF
    chmod +x /usr/local/bin/update_proxies.sh
    log $LOG_LEVEL_INFO "update_proxies script created successfully." "$UPDATE_LOG_FILE"
}

create_ufw_script &
create_iptables_script &
create_update_proxies_script &

wait

log $LOG_LEVEL_INFO "All script creation tasks completed successfully." "$UPDATE_LOG_FILE"

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
Type=simple
RemainAfterExit=no
Restart=always
RestartSec=5

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

create_ufw_service &
create_iptables_service &
create_update_proxies_service &
create_update_proxies_timer &

wait

log $LOG_LEVEL_INFO "All systemd service creation tasks completed successfully." "$UPDATE_LOG_FILE"

display_logo

configure_nginx_ssl() {
    log $LOG_LEVEL_INFO "Configuring Nginx SSL with strict HTTPS enforcement and SOCKS5 proxy..." "$UPDATE_LOG_FILE"
    
    # Check if Nginx is installed
    if ! command -v nginx &> /dev/null; then
        log $LOG_LEVEL_ERROR "Nginx is not installed. Please install Nginx before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Check if OpenSSL is installed
    if ! command -v openssl &> /dev/null; then
        log $LOG_LEVEL_ERROR "OpenSSL is not installed. Please install OpenSSL before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Create required directories
    mkdir -p /etc/nginx/snippets
    mkdir -p /var/www/html

    # Generate a self-signed certificate if it doesn't exist
    if [ ! -f /etc/ssl/private/nginx-selfsigned.key ] || [ ! -f /etc/ssl/certs/nginx-selfsigned.crt ]; then
        log $LOG_LEVEL_INFO "Generating self-signed SSL certificate..." "$UPDATE_LOG_FILE"
        openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -keyout /etc/ssl/private/nginx-selfsigned.key \
            -out /etc/ssl/certs/nginx-selfsigned.crt \
            -subj "/CN=localhost"
        
        if [ $? -ne 0 ]; then
            log $LOG_LEVEL_ERROR "Failed to generate self-signed SSL certificate." "$UPDATE_LOG_FILE"
            return 1
        fi
        log $LOG_LEVEL_INFO "Self-signed SSL certificate generated successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "Self-signed SSL certificate already exists, skipping generation." "$UPDATE_LOG_FILE"
    fi

    # Generate DH parameters if they don't exist
    if [ ! -f /etc/ssl/certs/dhparam.pem ]; then
        log $LOG_LEVEL_INFO "Generating DH parameters, this might take a while..." "$UPDATE_LOG_FILE"
        start_time=$(date +%s)
        openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
        end_time=$(date +%s)
        elapsed_time=$((end_time - start_time))
        log $LOG_LEVEL_INFO "DH parameters generated in $elapsed_time seconds." "$UPDATE_LOG_FILE"

        if [ $? -ne 0 ]; then
            log $LOG_LEVEL_ERROR "Failed to generate DH parameters." "$UPDATE_LOG_FILE"
            return 1
        fi
    else
        log $LOG_LEVEL_INFO "DH parameters already exist, skipping generation." "$UPDATE_LOG_FILE"
    fi

    # Configure global Nginx settings
    local nginx_global_conf="/etc/nginx/nginx.conf"
    if [ ! -f "$nginx_global_conf.bak" ]; then
        cp "$nginx_global_conf" "$nginx_global_conf.bak"
        log $LOG_LEVEL_INFO "Backup of nginx.conf created at $nginx_global_conf.bak" "$UPDATE_LOG_FILE"
    fi

    # Ensure the limit_req_zone directive exists in the global http block
    if ! grep -q "limit_req_zone" "$nginx_global_conf"; then
        sed -i '/^http {/a \    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;' "$nginx_global_conf"
        log $LOG_LEVEL_INFO "Added rate limiting directive to Nginx global http block." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "Rate limiting directive already exists in Nginx configuration, skipping." "$UPDATE_LOG_FILE"
    fi

    # Ensure the log_format directive exists in the global http block
    if ! grep -q "log_format proxy_logs" "$nginx_global_conf"; then
        sed -i '/^http {/a \    log_format proxy_logs '\''[\$time_local] \$remote_addr: \$remote_port -> \$server_addr: \$server_port '\''\n                       '\''"\$request" \$status \$body_bytes_sent '\''\n                       '\''"\$http_referer" "\$http_user_agent" SSL: \$ssl_cipher \$ssl_protocol'\'';' "$nginx_global_conf"
        log $LOG_LEVEL_INFO "Added log_format directive to Nginx global http block." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "Log_format directive already exists in Nginx configuration, skipping." "$UPDATE_LOG_FILE"
    fi

    # Configure Nginx SSL snippet
    local NGX_SSL_CONF="/etc/nginx/snippets/self-signed.conf"
    cat << 'EOF' > "$NGX_SSL_CONF"
ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_dhparam /etc/ssl/certs/dhparam.pem;

# OCSP-Stapling
# ssl_stapling on;
# ssl_stapling_verify on;
# resolver 8.8.8.8 1.1.1.1 valid=300s;
# resolver_timeout 5s;

# Add security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
EOF

    # Create Nginx configuration for strict HTTPS and SOCKS5 proxy
    local NGX_CONF="/etc/nginx/sites-available/tor_proxy"
    cat << EOF > "$NGX_CONF"
server {
    listen 80;
    server_name localhost;

    # Redirect all HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost;

    include /etc/nginx/snippets/self-signed.conf;

    # Sicherheitsheader
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        root /var/www/html;
        index index.html index.htm;

        # Rate Limiting
        limit_req zone=one burst=20;

        # Directory Listing deaktivieren
        autoindex off;

        # Forward traffic to SOCKS5 proxy
        proxy_pass http://127.0.0.1:9050;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$host;

        # Proxy Timeout und Pufferung
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
        proxy_buffering on;
        proxy_buffers 8 16k;
        proxy_buffer_size 4k;
    }

    # Logging
    access_log /var/log/nginx/https_proxy_access.log proxy_logs;
    error_log /var/log/nginx/https_proxy_error.log;

    # Maximale Upload-Größe
    client_max_body_size 1M;

    # HTTP-Methoden einschränken
    if (\$request_method !~ ^(GET|POST|HEAD)$ ) {
        return 444;
    }

    # Server Tokens deaktivieren
    server_tokens off;
}
EOF

    # Enable the site by creating a symbolic link
    local NGX_SITES_ENABLED="/etc/nginx/sites-enabled/tor_proxy"
    if [ ! -f "$NGX_SITES_ENABLED" ]; then
        ln -s "$NGX_CONF" "$NGX_SITES_ENABLED"
        log $LOG_LEVEL_INFO "Linked $NGX_CONF to $NGX_SITES_ENABLED." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "Nginx site configuration already enabled, skipping." "$UPDATE_LOG_FILE"
    fi

    # Test Nginx configuration
    if ! nginx -t; then
        log $LOG_LEVEL_ERROR "Nginx configuration test failed. Please check your configuration." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Start Nginx to apply changes
    if systemctl start nginx; then
        log $LOG_LEVEL_INFO "Nginx started successfully with updated configuration." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to start Nginx. Check the service status." "$UPDATE_LOG_FILE"
        return 1
    fi

    log $LOG_LEVEL_INFO "Nginx SSL with strict HTTPS and SOCKS5 proxy configured successfully." "$UPDATE_LOG_FILE"
    return 0
}

configure_nginx_ssl

# Function to log the status of systemd services
log_service_status() {
    local service_name=$1
    log $LOG_LEVEL_INFO "Checking status of $service_name..." "$UPDATE_LOG_FILE"
    systemctl status "$service_name" | tee -a "$UPDATE_LOG_FILE"

    # Check if the service is active
    if systemctl is-active --quiet "$service_name"; then
        log $LOG_LEVEL_INFO "Service $service_name is active and running." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Service $service_name is not active or failed!" "$UPDATE_LOG_FILE"
    fi
}

# Verifying systemd services
log $LOG_LEVEL_INFO "Verifying systemd services..." "$UPDATE_LOG_FILE"

# List of services to validate
services=("update_proxies" "iptables" "ufw" "fail2ban" "rsyslog" "update_proxies.timer")

# Loop through the services array and validate each service
for service in "${services[@]}"; do
    log_service_status "$service"
done

# Scan local network
log $LOG_LEVEL_INFO "Scanning local network..." "$UPDATE_LOG_FILE"
check_local_network

output=$(proxychains curl -s https://check.torproject.org)
if echo "$output" | grep -q "Congratulations"; then
    echo "Tor is working correctly."
else
    echo "Tor validation failed."
fi

display_logo

log $LOG_LEVEL_INFO "Verification completed." "$UPDATE_LOG_FILE"
