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
echo " ____                _____          "
echo "|  _ \ _ __ _____  _|  ___|____  __ "
echo "| |_) | '__/ _ \ \/ / |_ / _ \ \/ / "
echo "|  __/| | | (_) >  <|  _| (_) >  <  "
echo "|_|   |_|  \___/_/\_\_|  \___/_/\_\ "
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
#Log Files
export UPDATE_LOG_FILE="/var/log/khelp.log"
export PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"
export PROXY_TIMER_LOG_FILE="/var/log/timer_proxies.log"
export IPTABLES_LOG_FILE="/var/log/khelp_iptables.log"
export LOG_PATH="/var/log/snort"

# Directories
export KHELP_UPDATE_DIR="/usr/local/share/khelp_update"
export KHELP_INSTALLER_DIR="/usr/local/share/khelp_installer"
export KHELP_PROXYCHAINS_DIR="/usr/local/share/khelp_proxychains"
export KHELP_UFW_DIR="/usr/local/share/khelp_ufw"
export KHELP_FAIL2BAN_DIR="/usr/local/share/khelp_fail2ban"
export KHELP_IPTABLES_DIR="/usr/local/share/khelp_iptables"
export KHELP_TOR_DIR="/usr/local/share/khelp_tor"
export KHELP_LOGGING_DIR="/usr/local/share/khelp_logging"
export SNORT_DIR="/etc/snort"

# SSL Variables
export SSL_DIR="/etc/ssl"
export SSL_PRIVATE_DIR="$SSL_DIR/private"
export SSL_CERTS_DIR="$SSL_DIR/certs"
export SSL_KEY="$SSL_PRIVATE_DIR/nginx-selfsigned.key"
export SSL_CERT="$SSL_CERTS_DIR/nginx-selfsigned.crt"
export SSL_DHPARAM="$SSL_CERTS_DIR/dhparam.pem"
export NGX_SSL_CONF="/etc/nginx/snippets/self-signed.conf"
export DOMAIN="your_domain.com"

# Configuration files
export PROXYCHAINS_CONF="/etc/proxychains.conf"
export FAIL2BAN_CONFIG="/etc/fail2ban/jail.local"
export IPTABLES_RULES_FILE="/etc/iptables/rules.v4"
export CRONTAB_FILE="/etc/crontab"
export PROXY_LIST_FILE="/etc/proxychains/fetched_proxies.txt"
export SNORT_CONF="/etc/snort/snort.conf"
export HOME_NET="192.168.1.0/24"

# Script paths
export UPDATE_PROXIES_SCRIPT="/usr/local/bin/update_proxies.sh"
export UFW_SCRIPT="/usr/local/bin/ufw.sh"
export IPTABLES_SCRIPT="/usr/local/bin/iptables.sh"
export RULE_PATH="/etc/snort/rules"

# Service paths
export SYSTEMD_UPDATE_PROXIES_SERVICE="/etc/systemd/system/update_proxies.service"
export SYSTEMD_UPDATE_PROXIES_TIMER="/etc/systemd/system/update_proxies.timer"
export UFW_SERVICE_PATH="/etc/systemd/system/ufw.service"
export IPTABLES_SERVICE_PATH="/etc/systemd/system/iptables.service"

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
log $LOG_LEVEL_INFO "SNORT_CONF=$SNORT_CONF" "$UPDATE_LOG_FILE"

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

# Set permissions for log files
chmod 644 /var/log/khelp.log
chmod 644 /var/log/nginx/error.log
chown root:adm /var/log/khelp.log
chown root:adm /var/log/nginx/error.log

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

    log $LOG_LEVEL_ERROR "Failed to install rsyslog after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_nginx() {
    log $LOG_LEVEL_INFO "Installing nginx..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y nginx
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "nginx installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install nginx. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install nginx after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_coreutils_shuf() {
    log $LOG_LEVEL_INFO "Installing coreutils (shuf)..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y coreutils
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "coreutils (shuf) installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install coreutils (shuf). Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install coreutils (shuf) after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_snort() {
    log $LOG_LEVEL_INFO "Installing Snort..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y snort
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "Snort installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install Snort. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install Snort after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
    return 1
}

install_ip() {
    log $LOG_LEVEL_INFO "Installing ip..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y ip
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "ip installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install ip. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install ip after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
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
install_nginx &
install_coreutils_shuf &
install_snort &
install_ip &

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
backup_config "/etc/resolv.conf"
backup_config "/etc/nginx/nginx.conf"

# Configuration of Snort Service
configure_snort() {
    if [ -z "$HOME_NET" ]; then
        log $LOG_LEVEL_ERROR "HOME_NET is not set. Please set the HOME_NET variable before configuring Snort." "$UPDATE_LOG_FILE"
        exit 1
    fi

    log $LOG_LEVEL_INFO "Configuring Snort..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/snort/snort.conf
# Define network variables
var HOME_NET 192.168.1.0/24
var EXTERNAL_NET !$HOME_NET

# Define port variables
portvar HTTP_PORTS 80
portvar HTTPS_PORTS 443
portvar SOCKS_PORTS 9050
portvar SSH_PORTS 22

# Define preprocessor settings
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy linux bind_to $HOME_NET
preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy linux, use_static_footprint_sizes
preprocessor stream5_udp: timeout 180
preprocessor http_inspect: global iis_unicode_map unicode.map 65001
preprocessor http_inspect_server: server default \
    profile all ports { $HTTP_PORTS $HTTPS_PORTS } \
    oversize_dir_length 500
preprocessor ssh: server_ports { $SSH_PORTS } \
    autodetect

# Define output settings
output unified2: filename /var/log/snort/snort.log, limit 128

# Define rule path
var RULE_PATH /etc/snort/rules

# Include rule sets
include $RULE_PATH/local.rules
include $RULE_PATH/community.rules
EOF

    # Set permissions immediately after file creation
    chmod 644 /etc/snort/snort.conf
    chown root:root /etc/snort/snort.conf

    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to create Snort configuration file." "$UPDATE_LOG_FILE"
        exit 1
    fi

    # Bereinigen der Datei: Entfernen von leeren Zeilen
    sed -i '/^[[:space:]]*$/d' /etc/snort/snort.conf
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to clean up Snort configuration file." "$UPDATE_LOG_FILE"
        exit 1
    fi
    log $LOG_LEVEL_INFO "Removed empty lines from Snort configuration file." "$UPDATE_LOG_FILE"

    # Verzeichnis für Logs erstellen und prüfen
    if [ ! -d /var/log/snort ]; then
        mkdir -p /var/log/snort
        if [ $? -ne 0 ]; then
            log $LOG_LEVEL_ERROR "Failed to create Snort log directory." "$UPDATE_LOG_FILE"
            exit 1
        fi
        chmod 755 /var/log/snort
        chown root:root /var/log/snort
    fi

    # Log-Datei erstellen
    if [ ! -f /var/log/snort/snort.log ]; then
        touch /var/log/snort/snort.log
        if [ $? -ne 0 ]; then
            log $LOG_LEVEL_ERROR "Failed to create Snort log file." "$UPDATE_LOG_FILE"
            exit 1
        fi
        chmod 644 /var/log/snort/snort.log
        chown root:root /var/log/snort/snort.log
        log $LOG_LEVEL_INFO "Created Snort log file at /var/log/snort/snort.log" "$UPDATE_LOG_FILE"
    fi

    # Konvertieren der Konfiguration in ASCII
    convert_snort_config_to_ascii
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to convert Snort configuration file to ASCII." "$UPDATE_LOG_FILE"
        exit 1
    fi

    log $LOG_LEVEL_INFO "Snort configured successfully." "$UPDATE_LOG_FILE"
}

convert_snort_config_to_ascii() {
    log $LOG_LEVEL_INFO "Converting Snort configuration file to ASCII..." "$UPDATE_LOG_FILE"
    
    if [ ! -f "/etc/snort/snort.conf" ]; then
        log $LOG_LEVEL_ERROR "Snort configuration file not found: /etc/snort/snort.conf" "$UPDATE_LOG_FILE"
        exit 1
    fi

    iconv -f UTF-8 -t ASCII /etc/snort/snort.conf -o /etc/snort/snort_ascii.conf
    if [ $? -eq 0 ]; then
        mv /etc/snort/snort_ascii.conf /etc/snort/snort.conf
        log $LOG_LEVEL_INFO "Snort configuration file converted to ASCII successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to convert Snort configuration file to ASCII." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

create_snort_rules() {
    log $LOG_LEVEL_INFO "Creating rules for Snort..." "$UPDATE_LOG_FILE"
    mkdir -p /etc/snort/rules
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to create Snort rules directory." "$UPDATE_LOG_FILE"
        exit 1
    fi

    cat << 'EOF' > /etc/snort/rules/local.rules
# Snort Rules for Monitoring HTTPS Traffic over SOCKS5 via Tor

# Rule 1: Detect HTTPS Traffic via SOCKS5 (Port 9050)
alert tcp any any -> $HOME_NET 9050 (msg:"HTTPS traffic detected over SOCKS5"; content:"CONNECT"; http_method; sid:2000001; rev:1;)

# Rule 2: Detect Large HTTPS Packets (Potential Data Exfiltration)
alert tcp any any -> $HOME_NET 443 (msg:"Large HTTPS packet detected"; dsize:>1400; sid:2000002; rev:1;)

# Rule 3: Detect Suspicious User-Agent in HTTPS Traffic
alert tcp any any -> $HOME_NET 443 (msg:"Suspicious User-Agent in HTTPS traffic"; content:"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"; http_header; sid:2000003; rev:1;)

# Rule 4: Detect HTTPS Traffic with Potentially Harmful Domains
alert tcp any any -> $HOME_NET 443 (msg:"Potentially harmful domain detected in HTTPS traffic"; content:"malicious.com"; http_uri; nocase; sid:2000004; rev:1;)

# Rule 5: Detect DNS Resolution for Malicious Domains via Tor SOCKS5
alert udp any any -> $HOME_NET 9050 (msg:"DNS resolution for malicious domain via SOCKS5"; content:"malicious.com"; nocase; sid:2000005; rev:1;)

# Rule 6: Detect Possible Port Scan via SOCKS5 Proxy (Tor)
alert tcp any any -> $HOME_NET 9050 (msg:"Port scan detected via SOCKS5 proxy"; flags:S; threshold:type both, track by_src, count 20, seconds 10; sid:2000006; rev:1;)

# Rule 7: Detect HTTPS Traffic with Suspicious Content Over Tor
alert tcp any any -> $HOME_NET 9050 (msg:"Suspicious HTTPS content detected over Tor"; content:"/admin"; http_uri; nocase; sid:2000007; rev:1;)

# Rule 8: Detect High Volume HTTPS Traffic via Tor SOCKS5 Proxy
alert tcp any any -> $HOME_NET 9050 (msg:"High volume HTTPS traffic via SOCKS5 proxy"; flow:to_server,established; threshold:type both, track by_src, count 100, seconds 60; sid:2000008; rev:1;)

# Rule 9: Detect Possible Brute-Force Login Attempts via Tor
alert tcp any any -> $HOME_NET 443 (msg:"Possible brute-force login attempt detected over Tor"; flow:to_server,established; content:"POST"; http_method; threshold:type both, track by_src, count 5, seconds 60; sid:2000009; rev:1;)

# Rule 10: Detect Use of Non-Standard Ports for HTTPS over Tor
alert tcp any any -> $HOME_NET !443 (msg:"Non-standard HTTPS port detected over Tor"; content:"CONNECT"; http_method; sid:2000010; rev:1;)

# Rule 11: Detect Potential Command and Control (C2) Traffic Patterns
alert tcp any any -> $HOME_NET any (msg:"Potential C2 traffic detected"; content:"/gate.php"; http_uri; nocase; sid:2000011; rev:1;)

# Rule 12: Detect Suspicious DNS Queries Over Tor SOCKS5
alert udp any any -> $HOME_NET 9050 (msg:"Suspicious DNS query detected over Tor"; content:"dnslog"; nocase; sid:2000012; rev:1;)

# Rule 13: Detect HTTP Sessions with Suspicious Headers
alert tcp any any -> $HOME_NET 9050 (msg:"Suspicious HTTP header detected via SOCKS5"; content:"X-Forwarded-For"; http_header; sid:2000013; rev:1;)

# Rule 14: Detect Large Data Transfers via Tor (Potential Data Exfiltration)
alert tcp any any -> $HOME_NET 9050 (msg:"Large data transfer detected over Tor"; dsize:>5000; flow:to_server,established; sid:2000014; rev:1;)

# Rule 15: Detect Repeated Connections from the Same Host to Multiple Ports
alert tcp any any -> $HOME_NET any (msg:"Repeated connections to multiple ports detected"; flags:S; threshold:type both, track by_src, count 10, seconds 30; sid:2000015; rev:1;)

# Rule 16: Detect Connections to Known Malicious IPs
alert ip 123.45.67.89 any -> $HOME_NET any (msg:"Connection to known malicious IP detected"; sid:2000016; rev:1;)

# Rule 17: Detect Suspicious Tor Bridge Connections
alert tcp any any -> $HOME_NET 9001 (msg:"Suspicious Tor bridge connection detected"; sid:2000017; rev:1;)

# Rule 18: Detect Attempts to Bypass Tor SOCKS5 Proxy
alert tcp any any -> $HOME_NET !9050 (msg:"Direct connection attempt bypassing SOCKS5 proxy"; sid:2000018; rev:1;)

# Rule 19: Detect Use of Deprecated TLS Versions
alert tcp any any -> $HOME_NET 443 (msg:"Deprecated TLS version detected (TLS 1.0/1.1)"; content:"|16 03 01|"; sid:2000019; rev:1;)

# Rule 20: Detect Brute-Force Attempts on Hidden Services
alert tcp any any -> $HOME_NET 9050 (msg:"Brute-force attack on hidden service detected"; flow:to_server,established; threshold:type both, track by_src, count 5, seconds 60; sid:2000020; rev:1;)

# Rule 21: Detect Connection to Tor Directory Authorities
alert tcp any any -> $HOME_NET any (msg:"Connection to Tor directory authority detected"; content:"dirreq"; sid:2000021; rev:1;)

# Rule 22: Detect Possible DNS Tunneling
alert udp any any -> $HOME_NET 53 (msg:"Possible DNS tunneling detected"; content:"|03|dns"; offset:0; depth:10; sid:2000022; rev:1;)

# Rule 23: Detect Known C2 Communication
alert tcp any any -> $HOME_NET 443 (msg:"Known C2 communication detected"; content:"/api/v1"; http_uri; sid:2000024; rev:1;)

# Rule 24: Detect Unusual SSL Certificates
alert tcp any any -> $HOME_NET 443 (msg:"Unusual SSL certificate detected"; content:"|16 03 01 02|"; sid:2000025; rev:1;)
EOF

    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to create Snort local rules file." "$UPDATE_LOG_FILE"
        exit 1
    fi

    chmod 755 /etc/snort/rules
    chmod 644 /etc/snort/rules/local.rules
    chown root:root /etc/snort/rules
    chown root:root /etc/snort/rules/local.rules

    log $LOG_LEVEL_INFO "Snort rules configured successfully." "$UPDATE_LOG_FILE"
}

create_snort_classification_config() {
    log $LOG_LEVEL_INFO "Creating classification.config for Snort..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/snort/classification.config
config classification: misc-activity, Misc activity, 3
config classification: attempted-recon, Attempted Information Leak, 2
config classification: successful-recon-limited, Information Leak, 2
config classification: successful-recon-largescale, Large Scale Information Leak, 2
config classification: attempted-dos, Attempted Denial of Service, 2
config classification: successful-dos, Denial of Service, 2
config classification: attempted-user, Attempted User Privilege Gain, 1
config classification: successful-user, User Privilege Gain, 1
config classification: attempted-admin, Attempted Administrator Privilege Gain, 1
config classification: successful-admin, Administrator Privilege Gain, 1
EOF

    if [ -f /etc/snort/classification.config ]; then
        chmod 600 /etc/snort/classification.config
        chown root:root /etc/snort/classification.config
        log $LOG_LEVEL_INFO "Snort classification.config created and secured successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to create classification.config for Snort." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

create_snort_reference_config() {
    log $LOG_LEVEL_INFO "Creating reference.config for Snort..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/snort/reference.config
# snort reference configuration
config reference: bugtraq http://www.securityfocus.com/bid/
config reference: cve http://cve.mitre.org/cgi-bin/cvename.cgi?name=
config reference: arachNIDS http://www.whitehats.com/info/IDS
config reference: mcafee http://vil.nai.com/vil/content_v_
config reference: nessus http://cgi.nessus.org/plugins/dump.php3?id=
EOF

    if [ -f /etc/snort/reference.config ]; then
        chmod 600 /etc/snort/reference.config
        chown root:root /etc/snort/reference.config
        log $LOG_LEVEL_INFO "Snort reference.config created and secured successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to create reference.config for Snort." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

create_snort_unicode_map() {
    log $LOG_LEVEL_INFO "Creating unicode.map for Snort..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/snort/unicode.map
# Unicode Map for Snort
10079 (MAC - Icelandic)


1250  (ANSI - Central Europe)
00a1:21 00a2:63 00a3:4c 00a5:59 00aa:61 00b2:32 00b3:33 00b9:31 00ba:6f 00bc:31 00bd:31 00be:33 00c0:41 00c3:41 00c5:41 00c6:41 00c8:45 00ca:45 00cc:49 00cf:49 00d1:4e 00d2:4f 00d5:4f 00d8:4f 00d9:55 00db:55 00e0:61 00e3:61 00e5:61 00e6:61 00e8:65 00ea:65 00ec:69 00ef:69 00f1:6e 00f2:6f 00f5:6f 00f8:6f 00f9:75 00fb:75 00ff:79 0100:41 0101:61 0108:43 0109:63 010a:43 010b:63 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 013b:4c 013c:6c 0145:4e 0146:6e 014c:4f 014d:6f 014e:4f 014f:6f 0152:4f 0153:6f 0156:52 0157:72 015c:53 015d:73 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0180:62 0191:46 0192:66 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c0:7c 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02cb:60 02cd:5f 02dc:7e 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 037e:3b 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2032:27 2035:60 203c:21 2044:2f 2074:34 2075:35 2076:36 2077:37 2078:38 2080:30 2081:31 2082:32 2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:50 2119:50 211a:51 211b:52 211c:52 211d:52 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2191:5e 2194:2d 2195:7c 21a8:7c 2212:2d 2215:2f 2216:5c 2217:2a 221f:4c 2223:7c 2236:3a 223c:7e 2303:5e 2329:3c 232a:3e 2502:2d 250c:2d 2514:4c 2518:2d 251c:2b 2524:2b 252c:54 2534:2b 253c:2b 2550:3d 2554:2d 255a:4c 255d:2d 2566:54 256c:2b 2580:2d 2584:2d 2588:2d 2591:2d 2592:2d 2593:2d 25ac:2d 25b2:5e 25ba:3e 25c4:3c 25cb:30 25d9:30 263c:30 2640:2b 2642:3e 266a:64 266b:64 2758:7c 3000:20 3008:3c 3009:3e 301a:5b 301b:5d ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1251  (ANSI - Cyrillic)
00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d8:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f8:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 203c:21 2190:3c 2191:5e 2192:3e 2193:76 2194:2d 221a:76 221f:4c 2500:2d 250c:2d 2514:4c 2518:2d 251c:2b 2524:2b 252c:54 2534:2b 253c:2b 2550:3d 2552:2d 2558:4c 2559:4c 255a:4c 255b:2d 255c:2d 255d:2d 2564:54 2565:54 2566:54 256a:2b 256b:2b 256c:2b 2580:2d 2584:2d 2588:2d 2591:2d 2592:2d 2593:2d 25ac:2d 25b2:5e 25ba:3e 25c4:3c 25cb:30 25d9:30 263a:4f 263b:4f 263c:30 2640:2b 2642:3e 266a:64 266b:64 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1252  (ANSI - Latin I)
0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0179:5a 017b:5a 017c:7a 0180:62 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c0:7c 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c8:27 02cb:60 02cd:5f 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 037e:3b 0393:47 0398:54 03a3:53 03a6:46 03a9:4f 03b1:61 03b4:64 03b5:65 03c0:70 03c3:73 03c4:74 03c6:66 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2017:3d 2032:27 2035:60 2044:2f 2074:34 2075:35 2076:36 2077:37 2078:38 207f:6e 2080:30 2081:31 2082:32 2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20a7:50 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:50 2119:50 211a:51 211b:52 211c:52 211d:52 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2212:2d 2215:2f 2216:5c 2217:2a 221a:76 221e:38 2223:7c 2229:6e 2236:3a 223c:7e 2261:3d 2264:3d 2265:3d 2303:5e 2320:28 2321:29 2329:3c 232a:3e 2500:2d 250c:2b 2510:2b 2514:2b 2518:2b 251c:2b 252c:2d 2534:2d 253c:2b 2550:2d 2552:2b 2553:2b 2554:2b 2555:2b 2556:2b 2557:2b 2558:2b 2559:2b 255a:2b 255b:2b 255c:2b 255d:2b 2564:2d 2565:2d 2566:2d 2567:2d 2568:2d 2569:2d 256a:2b 256b:2b 256c:2b 2584:5f 2758:7c 3000:20 3008:3c 3009:3e 301a:5b 301b:5d ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1253  (ANSI - Greek)
00b4:2f 00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d8:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f8:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 037e:3b 203c:21 2190:3c 2191:5e 2192:3e 2193:76 2194:2d 221f:4c 2500:2d 250c:2d 2514:4c 2518:2d 251c:2b 2524:2b 252c:54 2534:2b 253c:2b 2550:3d 2554:2d 255a:4c 255d:2d 2566:54 256c:2b 2580:2d 2584:2d 2588:2d 2591:2d 2592:2d 2593:2d 25ac:2d 25b2:5e 25ba:3e 25c4:3c 25cb:30 25d9:30 263a:4f 263b:4f 263c:30 2640:2b 2642:3e 266a:64 266b:64 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1254  (ANSI - Turkish)
00dd:59 00fd:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c0:7c 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c7:5e 02c8:27 02cb:60 02cd:5f 02d8:5e 02d9:27 0300:60 0302:5e 0331:5f 0332:5f 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2032:27 2035:60 203c:21 2044:2f 2074:34 2075:35 2076:36 2077:37 2078:38 2081:30 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:50 2119:50 211a:51 211b:52 211c:52 211d:52 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2191:5e 2193:76 2194:2d 2195:7c 21a8:7c 2212:2d 2215:2f 2216:5c 2217:2a 221f:4c 2223:7c 2236:3a 223c:7e 2303:5e 2329:3c 232a:3e 2502:2d 250c:2d 2514:4c 2518:2d 251c:2b 2524:2b 252c:54 2534:2b 253c:2b 2550:3d 2554:2d 255a:4c 255d:2d 2566:54 256c:2b 2580:2d 2584:2d 2588:2d 2591:2d 2592:2d 2593:2d 25ac:2d 25b2:5e 25ba:3e 25c4:3c 25cb:30 25d9:30 263a:4f 263b:4f 263c:30 2640:2b 2642:3e 266a:64 266b:64 2758:7c 3000:20 3008:3c 3009:3e 301a:5b 301b:3d 301d:22 301e:22 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1255  (ANSI - Hebrew)
0191:46 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1256  (ANSI - Arabic)
00c0:41 00c2:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00ce:49 00cf:49 00d4:4f 00d9:55 00db:55 00dc:55 0191:46 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1257  (ANSI - Baltic)
ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

1258  (ANSI/OEM - Viet Nam)
ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

#INVALID CODEPAGE: 1361
20127 (US-ASCII)
00a0:20 00a1:21 00a2:63 00a4:24 00a5:59 00a6:7c 00a9:43 00aa:61 00ab:3c 00ad:2d 00ae:52 00b2:32 00b3:33 00b7:2e 00b8:2c 00b9:31 00ba:6f 00bb:3e 00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c6:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d0:44 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d8:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e6:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f8:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0191:46 0192:66 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02cb:60 02cd:5f 02dc:7e 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2018:27 2019:27 201a:2c 201c:22 201d:22 201e:22 2022:2e 2026:2e 2032:27 2035:60 2039:3c 203a:3e 2122:54 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

20261 (T.61)
f8dd:5c f8de:5e f8df:60 f8e0:7b f8fc:7d f8fd:7e f8fe:7f 

20866 (Russian - KOI8)
00a7:15 00ab:3c 00ad:2d 00ae:52 00b1:2b 00b6:14 00bb:3e 00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d8:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f8:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 2013:2d 2014:2d 2018:27 2019:27 201a:27 201c:22 201d:22 201e:22 2022:07 2026:3a 2030:25 2039:3c 203a:3e 203c:13 2122:54 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 221f:1c 2302:7f 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e 

28591 (ISO 8859-1 Latin I)
0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0191:46 0192:66 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02cb:60 02cd:5f 02dc:7e 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2018:27 2019:27 201a:2c 201c:22 201d:22 201e:22 2022:2e 2026:2e 2032:27 2035:60 2039:3c 203a:3e 2122:54 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

28592 (ISO 8859-2 Central Europe)
00a1:21 00a2:63 00a5:59 00a6:7c 00a9:43 00aa:61 00ab:3c 00ae:52 00b2:32 00b3:33 00b7:2e 00b9:31 00ba:6f 00bb:3e 00c0:41 00c3:41 00c5:41 00c6:41 00c8:45 00ca:45 00cc:49 00cf:49 00d0:44 00d1:4e 00d2:4f 00d5:4f 00d8:4f 00d9:55 00db:55 00e0:61 00e3:61 00e5:61 00e6:61 00e8:65 00ea:65 00ec:69 00ef:69 00f1:6e 00f2:6f 00f5:6f 00f8:6f 00f9:75 00fb:75 00ff:79 0100:41 0101:61 0108:43 0109:63 010a:43 010b:63 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 013b:4c 013c:6c 0145:4e 0146:6e 014c:4f 014d:6f 014e:4f 014f:6f 0152:4f 0153:6f 0156:52 0157:72 015c:53 015d:73 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0180:62 0189:44 0191:46 0192:66 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02cb:60 02cd:5f 02dc:7e 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2018:27 2019:27 201a:2c 201c:22 201d:22 201e:22 2022:2e 2026:2e 2032:27 2035:60 2039:3c 203a:3e 2122:54 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

#INVALID CODEPAGE: 28595
#INVALID CODEPAGE: 28597
28605 (ISO 8859-15 Latin 9)
00a6:7c 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0138:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014a:4e 014b:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:54 0169:74 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0179:5a 017b:5a 017c:7a 0180:62 0189:44 0191:46 0192:66 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02cb:60 02cd:5f 02dc:7e 0300:60 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2018:27 2019:27 201a:2c 201c:22 201d:22 201e:22 2022:2e 2026:2e 2032:27 2035:60 2039:3c 203a:3e 2122:54 ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

37    (IBM EBCDIC - U.S./Canada)
0004:37 0005:2d 0006:2e 0007:2f 0008:16 0009:05 000a:25 0014:3c 0015:3d 0016:32 0017:26 001a:3f 001b:27 0020:40 0021:5a 0022:7f 0023:7b 0024:5b 0025:6c 0026:50 0027:7d 0028:4d 0029:5d 002a:5c 002b:4e 002c:6b 002d:60 002e:4b 002f:61 003a:7a 003b:5e 003c:4c 003d:7e 003e:6e 003f:6f 0040:7c 005f:6d 0060:79 007c:4f 007f:07 0080:20 0081:21 0082:22 0083:23 0084:24 0085:15 0086:06 0087:17 0088:28 0089:29 008a:2a 008b:2b 008c:2c 008d:09 008e:0a 008f:1b 0090:30 0091:31 0092:1a 0093:33 0094:34 0095:35 0096:36 0097:08 0098:38 0099:39 009a:3a 009b:3b 009c:04 009d:14 009e:3e 00a0:41 00a2:4a 00a6:6a 00ac:5f 00c0:64 00c1:65 00c2:62 00c3:66 00c4:63 00c5:67 00c7:68 00c8:74 00c9:71 00ca:72 00cb:73 00cc:78 00cd:75 00ce:76 00cf:77 00d1:69 00df:59 00e0:44 00e1:45 00e2:42 00e3:46 00e4:43 00e5:47 00e7:48 00e8:54 00e9:51 00ea:52 00eb:53 00ec:58 00ed:55 00ee:56 00ef:57 00f1:49 00f8:70 ff01:5a ff02:7f ff03:7b ff04:5b ff05:6c ff06:50 ff07:7d ff08:4d ff09:5d ff0a:5c ff0b:4e ff0c:6b ff0d:60 ff0e:4b ff0f:61 ff1a:7a ff1b:5e ff1c:4c ff1d:7e ff1e:6e ff20:7c ff3f:6d ff40:79 ff5c:4f 

437   (OEM - United States)
00a4:0f 00a7:15 00a8:22 00a9:63 00ad:2d 00ae:72 00af:5f 00b3:33 00b4:27 00b6:14 00b8:2c 00b9:31 00be:5f 00c0:41 00c1:41 00c2:41 00c3:41 00c8:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d0:44 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d7:78 00d8:4f 00d9:55 00da:55 00db:55 00dd:59 00de:5f 00e3:61 00f0:64 00f5:6f 00f8:6f 00fd:79 00fe:5f 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c0:7c 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02ca:27 02cb:60 02cd:5f 02dc:7e 0300:60 0301:27 0302:5e 0303:7e 0308:22 030e:22 0327:2c 0331:5f 0332:5f 037e:3b 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2017:5f 2018:60 2019:27 201a:2c 201c:22 201d:22 201e:2c 2020:2b 2022:07 2026:2e 2030:25 2032:27 2035:60 2039:3c 203a:3e 203c:13 2044:2f 2074:34 2075:35 2076:36 2077:37 2078:38 2080:30 2081:31 2082:32 2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20dd:09 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:50 2119:50 211a:51 211b:52 211c:52 211d:52 2122:54 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 2212:2d 2215:2f 2216:5c 2217:2a 221f:1c 2223:7c 2236:3a 223c:7e 2302:7f 2303:5e 2329:3c 232a:3e 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e 2758:7c 3000:20 3007:09 3008:3c 3009:3e 301a:5b 301b:5d ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

500   (IBM EBCDIC - International)
0004:37 0005:2d 0006:2e 0007:2f 0008:16 0009:05 000a:25 0014:3c 0015:3d 0016:32 0017:26 001a:3f 001b:27 0020:40 0021:4f 0022:7f 0023:7b 0024:5b 0025:6c 0026:50 0027:7d 0028:4d 0029:5d 002a:5c 002b:4e 002c:6b 002d:60 002e:4b 002f:61 003a:7a 003b:5e 003c:4c 003d:7e 003e:6e 003f:6f 0040:7c 005b:4a 005d:5a 005e:5f 005f:6d 0060:79 007f:07 0080:20 0081:21 0082:22 0083:23 0084:24 0085:15 0086:06 0087:17 0088:28 0089:29 008a:2a 008b:2b 008c:2c 008d:09 008e:0a 008f:1b 0090:30 0091:31 0092:1a 0093:33 0094:34 0095:35 0096:36 0097:08 0098:38 0099:39 009a:3a 009b:3b 009c:04 009d:14 009e:3e 00a0:41 00a6:6a 00c0:64 00c1:65 00c2:62 00c3:66 00c4:63 00c5:67 00c7:68 00c8:74 00c9:71 00ca:72 00cb:73 00cc:78 00cd:75 00ce:76 00cf:77 00d1:69 00df:59 00e0:44 00e1:45 00e2:42 00e3:46 00e4:43 00e5:47 00e7:48 00e8:54 00e9:51 00ea:52 00eb:53 00ec:58 00ed:55 00ee:56 00ef:57 00f1:49 00f8:70 ff01:4f ff02:7f ff03:7b ff04:5b ff05:6c ff06:50 ff07:7d ff08:4d ff09:5d ff0a:5c ff0b:4e ff0c:6b ff0d:60 ff0e:4b ff0f:61 ff1a:7a ff1b:5e ff1c:4c ff1d:7e ff1e:6e ff20:7c ff3b:4a ff3d:5a ff3e:5f ff3f:6d ff40:79 

850   (OEM - Multilingual Latin I)
0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01a9:53 01ab:74 01ae:54 01af:55 01b0:75 01b6:5a 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02cb:27 02cd:5f 02dc:7e 0300:27 0302:5e 0303:7e 030e:22 0331:5f 0332:5f 037e:3b 0393:47 03a3:53 03a6:46 03a9:4f 03b1:61 03b4:64 03b5:65 03c0:70 03c3:73 03c4:74 03c6:66 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2018:27 2019:27 201a:27 201c:22 201d:22 201e:22 2022:07 2024:07 2026:2e 2030:25 2039:3c 203a:3e 203c:13 2044:2f 2070:30 2074:34 2075:35 2076:36 2077:37 2078:39 207f:6e 2080:30 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20a7:50 20dd:4f 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:50 2119:50 211a:51 211b:52 211c:52 211d:52 2122:54 2124:5a 2126:4f 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 2211:53 2212:2d 2215:2f 2216:2f 2217:2a 2219:07 221a:56 221e:38 221f:1c 2229:6e 2236:3a 223c:7e 2248:7e 2261:3d 2264:3d 2265:3d 2302:7f 2303:5e 2320:28 2321:29 2329:3c 232a:3e 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e 2713:56 3000:20 3007:4f 3008:3c 3009:3e 301a:5b 301b:5d ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

860   (OEM - Portuguese)
00a4:0f 00a5:59 00a7:15 00a8:22 00a9:63 00ad:5f 00ae:72 00af:16 00b3:33 00b4:2f 00b6:14 00b8:2c 00b9:31 00be:33 00c4:41 00c5:41 00c6:41 00cb:45 00ce:49 00cf:49 00d0:44 00d6:4f 00d7:58 00d8:4f 00db:55 00dd:59 00de:54 00e4:61 00e5:61 00e6:61 00eb:65 00ee:69 00ef:69 00f0:64 00f6:6f 00f8:6f 00fb:75 00fd:79 00fe:74 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:5c 0161:7c 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0191:46 0192:66 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c0:7c 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 0278:66 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02c9:16 02ca:2f 02cb:60 02cd:5f 02dc:7e 0300:60 0301:2f 0302:5e 0303:7e 0304:16 0305:16 0308:22 030e:22 0327:2c 0331:5f 0332:5f 037e:3b 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:5f 2011:5f 2013:5f 2014:5f 2017:5f 2018:27 2019:27 201a:2c 201c:22 201d:22 201e:22 2022:07 2024:07 2026:2e 2030:25 2032:27 2035:60 2039:3c 203a:3e 203c:13 2044:2f 2070:30 2074:34 2075:35 2076:36 2077:37 2078:38 2080:30 2081:31 2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20dd:4f 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:70 2119:50 211a:51 211b:52 211c:52 211d:52 2122:74 2124:5a 2128:5a 212a:4b 212b:41 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 2205:4f 2212:5f 2215:2f 2216:5c 2217:2a 221f:1c 2223:7c 2236:3a 223c:7e 22c5:07 2302:7f 2303:5e 2329:3c 232a:3e 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e 3000:20 3007:4f 3008:3c 3009:3e 301a:5b 301b:5d 30fb:07 

861   (OEM - Icelandic)
00a2:63 00a4:0f 00a5:59 00a7:15 00a8:22 00a9:63 00aa:61 00ad:5f 00ae:72 00af:16 00b3:33 00b4:2f 00b6:14 00b8:2c 00b9:31 00ba:6f 00be:33 00c0:41 00c2:41 00c3:41 00c8:45 00ca:45 00cb:45 00cc:49 00ce:49 00cf:49 00d1:4e 00d2:4f 00d4:4f 00d5:4f 00d7:58 00d9:55 00db:55 00e3:61 00ec:69 00ee:69 00ef:69 00f1:6e 00f2:6f 00f5:6f 00f9:75 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 0278:66 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02c9:16 02ca:2f 02cb:60 02cd:5f 02dc:7e 0300:60 0301:2f 0302:5e 0303:7e 0304:16 0305:16 0308:22 030e:22 0327:2c 0331:5f 0332:5f 037e:3b 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2017:5f 2018:27 2019:27 201a:27 201c:22 201d:22 201e:22 2022:07 2024:07 2026:07 2030:25 2032:27 2035:27 2039:3c 203a:3e 203c:13 2044:2f 2070:30 2074:34 2075:35 2076:36 2077:37 2078:38 2080:30 2081:31 2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20dd:4f 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:70 2119:50 211a:51 211b:52 211c:52 211d:52 2122:74 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 2205:4f 2212:5f 2215:2f 2216:5c 2217:2a 221f:1c 2223:7c 2236:3a 223c:7e 22c5:07 2302:7f 2303:5e 2329:3c 232a:3e 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e 3000:20 3007:4f 3008:3c 3009:3e 301a:5b 301b:5d 30fb:07 

863   (OEM - Canadian French)
00a1:21 00a5:59 00a9:63 00aa:61 00ad:16 00ae:72 00b9:33 00ba:6f 00c1:41 00c3:41 00c4:41 00c5:41 00c6:41 00cc:49 00cd:49 00d0:44 00d1:4e 00d2:4f 00d3:4f 00d5:4f 00d6:4f 00d7:58 00d8:4f 00da:55 00dd:59 00de:54 00e1:61 00e3:61 00e4:61 00e5:61 00e6:61 00ec:69 00ed:69 00f0:64 00f1:6e 00f2:6f 00f5:6f 00f6:6f 00f8:6f 00fd:79 00fe:74 00ff:79 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:22 02ba:27 02bc:27 02c4:5e 02c6:5e 02c8:27 02c9:16 02cb:60 02cd:5f 02dc:7e 0300:60 0302:5e 0303:7e 0304:16 0305:16 0331:5f 0332:5f 037e:3b 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2018:27 2019:27 201a:27 201c:22 201d:22 201e:22 2022:07 2024:07 2026:07 2030:25 2032:27 2035:27 2039:3c 203a:3e 203c:13 2044:2f 2070:30 2074:34 2075:35 2076:36 2077:37 2078:38 2080:30 2081:31 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20a7:50 20dd:4f 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:70 2119:50 211a:51 211b:52 211c:52 211d:52 2122:74 2124:5a 2128:5a 212a:4b 212b:41 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 2205:4f 2212:5f 2215:2f 2216:5c 2217:2a 221f:1c 2223:7c 2236:3a 223c:7e 22c5:07 2302:7f 2303:5e 2329:3c 232a:3e 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e 3000:20 3007:4f 3008:3c 3009:3e 301a:5b 301b:5d 30fb:07 

865   (OEM - Nordic)
00a2:63 00a5:59 00a7:15 00a8:22 00a9:63 00ad:5f 00ae:72 00af:16 00b3:33 00b4:2f 00b6:14 00b8:2c 00b9:31 00bb:3e 00be:33 00c0:41 00c1:41 00c2:41 00c3:41 00c8:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d0:44 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d7:58 00d9:55 00da:55 00db:55 00dd:59 00de:54 00e3:61 00f0:64 00f5:6f 00fd:79 00fe:74 0100:41 0101:61 0102:41 0103:61 0104:41 0105:61 0106:43 0107:63 0108:43 0109:63 010a:43 010b:63 010c:43 010d:63 010e:44 010f:64 0110:44 0111:64 0112:45 0113:65 0114:45 0115:65 0116:45 0117:65 0118:45 0119:65 011a:45 011b:65 011c:47 011d:67 011e:47 011f:67 0120:47 0121:67 0122:47 0123:67 0124:48 0125:68 0126:48 0127:68 0128:49 0129:69 012a:49 012b:69 012c:49 012d:69 012e:49 012f:69 0130:49 0131:69 0134:4a 0135:6a 0136:4b 0137:6b 0139:4c 013a:6c 013b:4c 013c:6c 013d:4c 013e:6c 0141:4c 0142:6c 0143:4e 0144:6e 0145:4e 0146:6e 0147:4e 0148:6e 014c:4f 014d:6f 014e:4f 014f:6f 0150:4f 0151:6f 0152:4f 0153:6f 0154:52 0155:72 0156:52 0157:72 0158:52 0159:72 015a:53 015b:73 015c:53 015d:73 015e:53 015f:73 0160:53 0161:73 0162:54 0163:74 0164:54 0165:74 0166:54 0167:74 0168:55 0169:75 016a:55 016b:75 016c:55 016d:75 016e:55 016f:75 0170:55 0171:75 0172:55 0173:75 0174:57 0175:77 0176:59 0177:79 0178:59 0179:5a 017b:5a 017c:7a 017d:5a 017e:7a 0180:62 0189:44 0197:49 019a:6c 019f:4f 01a0:4f 01a1:6f 01ab:74 01ae:54 01af:55 01b0:75 01b6:7a 01c3:21 01cd:41 01ce:61 01cf:49 01d0:69 01d1:4f 01d2:6f 01d3:55 01d4:75 01d5:55 01d6:75 01d7:55 01d8:75 01d9:55 01da:75 01db:55 01dc:75 01de:41 01df:61 01e4:47 01e5:67 01e6:47 01e7:67 01e8:4b 01e9:6b 01ea:4f 01eb:6f 01ec:4f 01ed:6f 01f0:6a 0261:67 02b9:27 02ba:22 02bc:27 02c4:5e 02c6:5e 02c8:27 02c9:16 02ca:2f 02cb:60 02cd:5f 02dc:7e 0300:60 0301:2f 0302:5e 0303:7e 0304:16 0305:16 0308:22 030e:22 0327:2c 0331:5f 0332:5f 037e:3b 04bb:68 0589:3a 066a:25 2000:20 2001:20 2002:20 2003:20 2004:20 2005:20 2006:20 2010:2d 2011:2d 2013:2d 2014:2d 2017:5f 2018:27 2019:27 201a:27 201c:22 201d:22 201e:22 2022:07 2024:07 2026:07 2030:25 2032:27 2035:27 2039:3c 203a:3e 203c:13 2044:2f 2070:30 2074:34 2075:35 2076:36 2077:37 2078:38 2080:30 2081:31 2083:33 2084:34 2085:35 2086:36 2087:37 2088:38 2089:39 20dd:4f 2102:43 2107:45 210a:67 210b:48 210c:48 210d:48 210e:68 2110:49 2111:49 2112:4c 2113:6c 2115:4e 2118:70 2119:50 211a:51 211b:52 211c:52 211d:52 2122:74 2124:5a 2128:5a 212a:4b 212c:42 212d:43 212e:65 212f:65 2130:45 2131:46 2133:4d 2134:6f 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 2205:4f 2212:5f 2215:2f 2216:5c 2217:2a 221f:1c 2223:7c 2236:3a 223c:7e 226b:3c 22c5:07 2302:7f 2303:5e 2329:3c 232a:3e 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e 3000:20 3007:4f 3008:3c 3009:3e 300b:3e 301a:5b 301b:5d 30fb:07 

874   (ANSI/OEM - Thai)
00a7:15 00b6:14 203c:13 2190:1b 2191:18 2192:1a 2193:19 2194:1d 2195:12 21a8:17 221f:1c 2302:7f 25ac:16 25b2:1e 25ba:10 25bc:1f 25c4:11 25cb:09 25d8:08 25d9:0a 263a:01 263b:02 263c:0f 2640:0c 2642:0b 2660:06 2663:05 2665:03 2666:04 266a:0d 266b:0e ff01:21 ff02:22 ff03:23 ff04:24 ff05:25 ff06:26 ff07:27 ff08:28 ff09:29 ff0a:2a ff0b:2b ff0c:2c ff0d:2d ff0e:2e ff0f:2f ff10:30 ff11:31 ff12:32 ff13:33 ff14:34 ff15:35 ff16:36 ff17:37 ff18:38 ff19:39 ff1a:3a ff1b:3b ff1c:3c ff1d:3d ff1e:3e ff20:40 ff21:41 ff22:42 ff23:43 ff24:44 ff25:45 ff26:46 ff27:47 ff28:48 ff29:49 ff2a:4a ff2b:4b ff2c:4c ff2d:4d ff2e:4e ff2f:4f ff30:50 ff31:51 ff32:52 ff33:53 ff34:54 ff35:55 ff36:56 ff37:57 ff38:58 ff39:59 ff3a:5a ff3b:5b ff3c:5c ff3d:5d ff3e:5e ff3f:5f ff40:60 ff41:61 ff42:62 ff43:63 ff44:64 ff45:65 ff46:66 ff47:67 ff48:68 ff49:69 ff4a:6a ff4b:6b ff4c:6c ff4d:6d ff4e:6e ff4f:6f ff50:70 ff51:71 ff52:72 ff53:73 ff54:74 ff55:75 ff56:76 ff57:77 ff58:78 ff59:79 ff5a:7a ff5b:7b ff5c:7c ff5d:7d ff5e:7e 

932   (ANSI/OEM - Japanese Shift-JIS)
00a1:21 00a5:5c 00a6:7c 00a9:63 00aa:61 00ad:2d 00ae:52 00b2:32 00b3:33 00b9:31 00ba:6f 00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c6:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d0:44 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d8:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00de:54 00df:73 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e6:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f0:64 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f8:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00fe:74 00ff:79 

936   (ANSI/OEM - Simplified Chinese GBK)
00a6:7c 00aa:61 00ad:2d 00b2:32 00b3:33 00b9:31 00ba:6f 00d0:44 00dd:59 00de:54 00e2:61 00f0:65 00fd:79 00fe:74 

949   (ANSI/OEM - Korean)
00a6:7c 00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00ff:79 20a9:5c 

950   (ANSI/OEM - Traditional Chinese Big5)
00a1:21 00a6:7c 00a9:63 00aa:61 00ad:2d 00ae:52 00b2:32 00b3:33 00b9:31 00ba:6f 00c0:41 00c1:41 00c2:41 00c3:41 00c4:41 00c5:41 00c6:41 00c7:43 00c8:45 00c9:45 00ca:45 00cb:45 00cc:49 00cd:49 00ce:49 00cf:49 00d0:44 00d1:4e 00d2:4f 00d3:4f 00d4:4f 00d5:4f 00d6:4f 00d8:4f 00d9:55 00da:55 00db:55 00dc:55 00dd:59 00de:54 00df:73 00e0:61 00e1:61 00e2:61 00e3:61 00e4:61 00e5:61 00e6:61 00e7:63 00e8:65 00e9:65 00ea:65 00eb:65 00ec:69 00ed:69 00ee:69 00ef:69 00f0:65 00f1:6e 00f2:6f 00f3:6f 00f4:6f 00f5:6f 00f6:6f 00f8:6f 00f9:75 00fa:75 00fb:75 00fc:75 00fd:79 00fe:74 00ff:79 

65000 (UTF-7)


65001 (UTF-8)
00a0:20 00a1:21 00a2:63 00a3:4c 00a5:59 00a6:7c
00a9:43 00aa:61 00ab:3c 00ad:2d 00ae:52 00b2:32
00b3:33 00b7:2e 00b9:31 00ba:6f 00bb:3e 00c0:41
EOF

    if [ -f /etc/snort/unicode.map ]; then
        chmod 600 /etc/snort/unicode.map
        chown root:root /etc/snort/unicode.map
        log $LOG_LEVEL_INFO "Snort unicode.map created and secured successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to create unicode.map for Snort." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

create_snort_threshold_conf() {
    log $LOG_LEVEL_INFO "Creating threshold.conf for Snort..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/snort/threshold.conf
# Snort threshold configuration
suppress gen_id 1, sig_id 2000001, track by_src, ip 192.168.1.1
suppress gen_id 1, sig_id 2000002, track by_src, ip 10.0.0.5
EOF

    if [ -f /etc/snort/threshold.conf ]; then
        chmod 600 /etc/snort/threshold.conf
        chown root:root /etc/snort/threshold.conf
        log $LOG_LEVEL_INFO "Snort threshold.conf created and secured successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to create threshold.conf for Snort." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

create_snort_sid_msg_map() {
    log $LOG_LEVEL_INFO "Creating sid-msg.map for Snort..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /etc/snort/sid-msg.map
2000001 || HTTPS traffic detected over SOCKS5
2000002 || Large HTTPS packet detected
2000003 || Suspicious User-Agent in HTTPS traffic
2000004 || Potentially harmful domain detected in HTTPS traffic
2000005 || DNS resolution for malicious domain via SOCKS5
EOF

    if [ -f /etc/snort/sid-msg.map ]; then
        chmod 600 /etc/snort/sid-msg.map
        chown root:root /etc/snort/sid-msg.map
        log $LOG_LEVEL_INFO "Snort sid-msg.map created and secured successfully." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_ERROR "Failed to create sid-msg.map for Snort." "$UPDATE_LOG_FILE"
        exit 1
    fi
}

create_snort_wrapper() {
    log $LOG_LEVEL_INFO "Creating wrapper for snort..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/start_snort.sh
#!/bin/bash

# Set default value for HOME_NET if not already set
: "${HOME_NET:=192.168.1.0/24}"

# Export HOME_NET for Snort
export HOME_NET

# Funktion zur Bestimmung des primären Netzwerk-Interfaces
get_primary_interface() {
    local interface
    interface=$(ip route | grep default | awk '{print $5}')

    if [ -z "$interface" ]; then
        if ip link show eth0 > /dev/null 2>&1; then
            echo "eth0"
        elif ip link show wlan0 > /dev/null 2>&1; then
            echo "wlan0"
        else
            exit 1
        fi
    else
        echo "$interface"
    fi
}

# Bestimmen Sie das primäre Netzwerk-Interface
PRIMARY_INTERFACE=$(get_primary_interface)

if [ -z "$PRIMARY_INTERFACE" ]; then
    exit 1
fi

# Überprüfen der Snort-Konfigurationsdatei
if [ ! -f "$SNORT_CONF" ]; then
    exit 1
elif ! grep -q "var HOME_NET" "$SNORT_CONF"; then
    exit 1
fi

# Start Snort with the primary network interface
/usr/sbin/snort -c "$SNORT_CONF" -i "$PRIMARY_INTERFACE"
EOF
    chmod 755 /usr/local/bin/start_snort.sh
    chown root:root /usr/local/bin/start_snort.sh
    
    log $LOG_LEVEL_INFO "Snort wrapper created successfully." "$UPDATE_LOG_FILE"
}

create_snort_service() {
    log $LOG_LEVEL_INFO "Creating and enabling Snort service..." "$UPDATE_LOG_FILE"
    cat << EOF > /etc/systemd/system/snort.service
[Unit]
Description=Snort Network Intrusion Detection System
After=network.target

[Service]
Environment="SNORT_CONF=/etc/snort/snort.conf"
ExecStart=/usr/local/bin/start_snort.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to create Snort service file." "$UPDATE_LOG_FILE"
        exit 1
    fi

    chmod 600 /etc/systemd/system/snort.service
    systemctl daemon-reload
    systemctl enable snort.service
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to enable Snort service." "$UPDATE_LOG_FILE"
        exit 1
    fi
    systemctl start snort.service
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to start Snort service." "$UPDATE_LOG_FILE"
        exit 1
    fi

    log $LOG_LEVEL_INFO "Snort service created and enabled." "$UPDATE_LOG_FILE"
}

configure_snort
create_snort_rules
create_snort_classification_config
create_snort_reference_config
create_snort_unicode_map
create_snort_threshold_conf
create_snort_sid_msg_map
create_snort_wrapper
create_snort_service

chmod 755 /var/log/snort
chmod 644 /var/log/snort/snort.log
chown root:root /var/log/snort
chown root:root /var/log/snort/snort.log

# Configure of Fail2ban Service
configure_fail2ban() {
    log $LOG_LEVEL_INFO "Configuring Fail2ban..." "$UPDATE_LOG_FILE"
    apt install -y fail2ban

    # Ensure the Snort log file exists
    if [ ! -f /var/log/snort/snort.log ]; then
        mkdir -p /var/log/snort
        touch /var/log/snort/snort.log
        log $LOG_LEVEL_INFO "Created Snort log file at /var/log/snort/snort.log" "$UPDATE_LOG_FILE"
    fi

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

[snort]
enabled = true
port    = all
logpath = /var/log/snort/snort.log
maxretry = 3
bantime = 86400

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

create_f2b_snort_filter() {
    log $LOG_LEVEL_INFO "Creating f2b filter for snort..." "$UPDATE_LOG_FILE"
    cat << EOF > /etc/fail2ban/filter.d/snort.conf
# Fail2Ban filter for snort
[Definition]

# Example patterns:
# alert tcp any any -> any any (msg:"ET SCAN Potential SSH Scan"; flags:S; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:2001219; rev:3;)
failregex = \[Classification: .*?\] \[Priority: .*?\] {<HOST>}
ignoreregex =
EOF
    chmod 644 /etc/fail2ban/filter.d/snort.conf
    chown root:root /etc/fail2ban/filter.d/snort.conf
    
    log $LOG_LEVEL_INFO "Snort filter created successfully." "$UPDATE_LOG_FILE"
}

configure_fail2ban
create_f2b_snort_filter

# Function to update or create config files
configure_ufw() {
    log $LOG_LEVEL_INFO "Configuring UFW firewall..." "$UPDATE_LOG_FILE"
    
    # Check if UFW is installed
    if ! command -v ufw &> /dev/null; then
        log $LOG_LEVEL_ERROR "UFW is not installed. Please install UFW before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

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

    # Configure UFW rules
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow from $ALLOWED_IP_RANGE to any port 22
    ufw allow 9050/tcp
    ufw allow 9001/tcp
    ufw allow 443/tcp
    ufw limit ssh/tcp
    ufw logging full

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
    log $LOG_LEVEL_INFO "Flushed all iptables rules." "$IPTABLES_LOG_FILE"
    iptables -X
    log $LOG_LEVEL_INFO "Deleted all user-defined iptables chains." "$IPTABLES_LOG_FILE"

    # Set default policies
    iptables -P INPUT DROP
    log $LOG_LEVEL_INFO "Set default policy for INPUT chain to DROP." "$IPTABLES_LOG_FILE"
    iptables -P FORWARD DROP
    log $LOG_LEVEL_INFO "Set default policy for FORWARD chain to DROP." "$IPTABLES_LOG_FILE"
    iptables -P OUTPUT ACCEPT
    log $LOG_LEVEL_INFO "Set default policy for OUTPUT chain to ACCEPT." "$IPTABLES_LOG_FILE"

    # Allow loopback traffic and established connections
    iptables -A INPUT -i lo -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed loopback traffic on INPUT chain." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed established and related connections on INPUT chain." "$IPTABLES_LOG_FILE"

    # Allow specific ports
    iptables -A INPUT -p tcp -s $ALLOWED_IP_RANGE --dport 22 -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed SSH access from $ALLOWED_IP_RANGE on port 22." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p tcp --dport 9050 -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed Tor on port 9050." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p tcp --dport 9001 -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed Tor on port 9001." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed HTTPS on port 443." "$IPTABLES_LOG_FILE"

    # Rate-limit new SSH connections
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
    log $LOG_LEVEL_INFO "Rate-limited new SSH connections." "$IPTABLES_LOG_FILE"

    # Drop invalid packets
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    log $LOG_LEVEL_INFO "Dropped invalid packets on INPUT chain." "$IPTABLES_LOG_FILE"

    # Remove ICMP (ping) requests
    # iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 10 -j ACCEPT
    log $LOG_LEVEL_INFO "Blocked ICMP (ping) requests." "$IPTABLES_LOG_FILE"

    # Create a logging chain
    iptables -N LOGGING
    iptables -A INPUT -j LOGGING
    iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables: " --log-level 4
    iptables -A LOGGING -j DROP
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
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT  # Allow HTTPS
-A INPUT -p tcp --dport 9050 -j ACCEPT  # Allow port 9050
# -A INPUT -p icmp -m limit --limit 1/s --limit-burst 10 -j ACCEPT
COMMIT
EOF
        log $LOG_LEVEL_INFO "Created default iptables rules file." "$IPTABLES_LOG_FILE"
    fi

    # Save the iptables rules
    iptables-save > /etc/iptables/rules.v4
    log $LOG_LEVEL_INFO "iptables rules configured successfully." "$IPTABLES_LOG_FILE"
    return 0
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

    log $LOG_LEVEL_INFO "ProxyChains configured successfully." "$UPDATE_LOG_FILE"
    return 0
}

configure_resolv_conf() {
    log $LOG_LEVEL_INFO "Configuring resolv.conf to prevent DNS leaks..." "$UPDATE_LOG_FILE"
    
    # Backup existing resolv.conf if not already backed up
    if [ ! -f /etc/resolv.conf.backup ]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup
        log $LOG_LEVEL_INFO "Backup of resolv.conf created." "$UPDATE_LOG_FILE"
    else
        log $LOG_LEVEL_INFO "Backup of resolv.conf already exists." "$UPDATE_LOG_FILE"
    fi
    
    # Set DNS servers
    cat <<EOF > /etc/resolv.conf
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

    # Validate the DNS servers by performing DNS queries
    validate_dns_server() {
        local dns=$1
        if dig @$dns google.com &> /dev/null; then
            log $LOG_LEVEL_INFO "DNS server $dns is reachable." "$UPDATE_LOG_FILE"
        else
            log $LOG_LEVEL_ERROR "DNS server $dns is not reachable." "$UPDATE_LOG_FILE"
            return 1
        fi
    }

    if ! validate_dns_server "1.1.1.1" || ! validate_dns_server "8.8.8.8"; then
        log $LOG_LEVEL_CRITICAL "One or more DNS servers are not reachable. Exiting script." "$UPDATE_LOG_FILE"
        exit 1
    fi
    
    # Prevent DHCP client from overwriting resolv.conf
    chattr +i /etc/resolv.conf
    log $LOG_LEVEL_INFO "resolv.conf configured and immutable flag set to prevent changes." "$UPDATE_LOG_FILE"
}

configure_openssl() {
    log $LOG_LEVEL_INFO "Configuring OpenSSL..." "$UPDATE_LOG_FILE"
    
    # Check if OpenSSL is installed
    if ! command -v openssl &> /dev/null; then
        log $LOG_LEVEL_ERROR "OpenSSL is not installed. Please install OpenSSL before running this script." "$UPDATE_LOG_FILE"
        return 1
    fi

    local ssl_dir="/etc/ssl"
    mkdir -p "$ssl_dir/private"
    mkdir -p "$ssl_dir/certs"

    # Generate a self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout "$ssl_dir/private/nginx-selfsigned.key" -out "$ssl_dir/certs/nginx-selfsigned.crt" -subj "/CN=your_domain.com" -sha256

    if [ $? -eq 0 ]; then
        log $LOG_LEVEL_INFO "OpenSSL configured successfully." "$UPDATE_LOG_FILE"
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

configure_ufw &
configure_iptables &
configure_tor &
configure_proxychains &
configure_resolv_conf &
configure_openssl &
setup_monitoring &
setup_syslog &

touch /var/log/khelp_iptables.log
chmod 644 /var/log/khelp_iptables.log
chown root:adm /var/log/khelp_iptables.log

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
    chmod +x /etc/systemd/system/update_proxies.timer
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
    log $LOG_LEVEL_INFO "Configuring Nginx SSL..." "$UPDATE_LOG_FILE"
    
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

    # Create directory for Nginx snippets if it doesn't exist
    mkdir -p /etc/nginx/snippets

    # Configure Nginx SSL
    local nginx_conf="/etc/nginx/snippets/self-signed.conf"
    cat << 'EOF' > "$nginx_conf"
# Nginx SSL configuration

ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_dhparam /etc/ssl/certs/dhparam.pem;
EOF

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

    log $LOG_LEVEL_INFO "Nginx SSL configured successfully." "$UPDATE_LOG_FILE"
    return 0
}

# Nginx SSL-Konfiguration separat ausführen
configure_nginx_ssl 

# Verifying systemd services
log $LOG_LEVEL_INFO "Verifying systemd services..." "$UPDATE_LOG_FILE"
systemctl status update_proxies | tee -a "$UPDATE_LOG_FILE"
systemctl status iptables | tee -a "$UPDATE_LOG_FILE"
systemctl status ufw | tee -a "$UPDATE_LOG_FILE"
systemctl status fail2ban | tee -a "$UPDATE_LOG_FILE"
systemctl status rsyslog | tee -a "$UPDATE_LOG_FILE"
systemctl status snort | tee -a "$UPDATE_LOG_FILE"
systemctl status update_proxies.service | tee -a "$UPDATE_LOG_FILE"
systemctl status update_proxies.timer | tee -a "$UPDATE_LOG_FILE"

# Scan local network
log $LOG_LEVEL_INFO "Scanning local network..." "$UPDATE_LOG_FILE"
check_local_network

log $LOG_LEVEL_INFO "Verification completed." "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "khelp proxfox is done! Traffic is routing through the SOCKS5 Tor network." "$UPDATE_LOG_FILE"