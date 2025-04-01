#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Define the display_logo function
display_logo() {                                                                                                      
echo " _    _          _       "   
echo "| | _| |__   ___| |_ __  "  
echo "| |/ / '_ \ / _ \ | '_ \ " 
echo "|   <| | | |  __/ | |_) |"
echo "|_|\_\_| |_|\___|_| .__/ "
echo "                  |_|    "
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
export HOGEN_LOG_FILE=${HOGEN_LOG_FILE:-"/var/log/khelp_hogen.log"}
export MSPOO_LOG_FILE=${MSPOO_LOG_FILE:-"/var/log/khelp_mspoo.log"}

# Snort environment variables
export SNORT_LOG_DIR="/var/log/khelp/snort"
export SNORT_DOC_DIR=${SNORT_DOC_DIR:-"/usr/local/share/khelp_snort"}
export SNORT_CONF="/etc/snort/snort.conf"
export SNORT_RULES_DIR="/etc/snort/rules"
export SNORT_SERVICE="/etc/systemd/system/snort.service"
export SNORT_DOC_FILE="$SNORT_DOC_DIR/README.md"

# Directories
export KHELP_UPDATE_DIR="/usr/local/share/khelp_update"
export KHELP_INSTALLER_DIR="/usr/local/share/khelp_installer"
export KHELP_PROXYCHAINS_DIR="/usr/local/share/khelp_proxychains"
export KHELP_UFW_DIR="/usr/local/share/khelp_ufw"
export KHELP_FAIL2BAN_DIR="/usr/local/share/khelp_fail2ban"
export KHELP_IPTABLES_DIR="/usr/local/share/khelp_iptables"
export KHELP_TOR_DIR="/usr/local/share/khelp_tor"
export KHELP_TERMINATOR_DIR="/usr/local/share/khelp_terminator"
export KHELP_VERIFY_DIR="/usr/local/share/khelp_verify"
export HOGEN_DOC_DIR=${HOGEN_DOC_DIR:-"/usr/local/share/khelp_hogen"}
export MSPOO_DOC_DIR=${MSPOO_DOC_DIR:-"/usr/local/share/khelp_mspoof"}
export KHELP_LOGGING_DIR="/usr/local/share/khelp_logging"
export KHELP_DEFAULT_TERMINAL_DIR="/usr/local/share/khelp_default_terminal"
export KHELP_STARTUP_VERIFICATION_DIR="/usr/local/share/khelp_startup_verification"

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
export HOGEN_SCRIPT_PATH=${HOGEN_SCRIPT_PATH:-"/usr/local/bin/hogen.sh"}
export MSPOO_SCRIPT_PATH=${MSPOO_SCRIPT_PATH:-"/usr/local/bin/mspoo.sh"}
export STARTUP_SCRIPT_PATH="$USER_HOME/startup_script.sh"
export DESKTOP_ENTRY_PATH="$USER_HOME/.config/autostart/startup_terminal.desktop"

# Service paths
export SYSTEMD_UPDATE_PROXIES_SERVICE="/etc/systemd/system/update_proxies.service"
export SYSTEMD_UPDATE_PROXIES_TIMER="/etc/systemd/system/update_proxies.timer"
export UFW_SERVICE_PATH="/etc/systemd/system/ufw.service"
export IPTABLES_SERVICE_PATH="/etc/systemd/system/iptables.service"
export HOGEN_SERVICE_PATH=${HOGEN_SERVICE_PATH:-"/etc/systemd/system/hogen.service"}
export MSPOO_SERVICE_PATH=${MSPOO_SERVICE_PATH:-"/etc/systemd/system/mspoo.service"}

# Documentation files
export HOGEN_DOC_FILE="$HOGEN_DOC_DIR/README.md"
export MSPOO_DOC_FILE="$MSPOO_DOC_DIR/README.md"
export KHELP_LOGGING_DOC_FILE="$KHELP_LOGGING_DIR/README.md"
export KHELP_DEFAULT_TERMINAL_DOC_FILE="$KHELP_DEFAULT_TERMINAL_DIR/README.md"
export KHELP_STARTUP_VERIFICATION_DOC_FILE="$KHELP_STARTUP_VERIFICATION_DIR/README.md"
export UFW_DOC_FILE="$KHELP_UFW_DIR/README.md"
export FAIL2BAN_DOC_FILE="$KHELP_FAIL2BAN_DIR/README.md"
export IPTABLES_DOC_FILE="$KHELP_IPTABLES_DIR/README.md"
export TOR_DOC_FILE="$KHELP_TOR_DIR/README.md"
export KHELP_INSTALLER_DOC_FILE="$KHELP_INSTALLER_DIR/README.md"
export KHELP_UPDATE_DOC_FILE="$KHELP_UPDATE_DIR/README.md"
export TERMINATOR_DOC_FILE="$KHELP_TERMINATOR_DIR/README.md"

# Proxy API URLs
export PROXY_API_URL1="https://spys.me/socks.txt"

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

    # Rotate log file if it exceeds 1MB
    if [ -f "$log_file" ] && [ $(stat -c%s "$log_file") -gt 1048576 ]; then
        mv "$log_file" "$log_file.$(date +'%Y%m%d%H%M%S')"
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

# Example usage of the log function for different tasks
# Task 1: Proxy
log $LOG_LEVEL_INFO "Starting Proxy task" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "Proxy task completed successfully" "$UPDATE_LOG_FILE"

# Task 2: Hogen
log $LOG_LEVEL_INFO "Starting Hogen task" "$HOGEN_LOG_FILE"
log $LOG_LEVEL_INFO "Hogen task completed successfully" "$HOGEN_LOG_FILE"

# Task 3: MSPoo
log $LOG_LEVEL_INFO "Starting MSPoo task" "$MSPOO_LOG_FILE"
log $LOG_LEVEL_INFO "MSPoo task completed successfully" "$MSPOO_LOG_FILE"

# Example usage of the log function
log $LOG_LEVEL_INFO "This is an informational message." "$UPDATE_LOG_FILE"
log $LOG_LEVEL_ERROR "This is an error message." "$UPDATE_LOG_FILE"
log $LOG_LEVEL_WARNING "This is a warning message." "$UPDATE_LOG_FILE"

# Debugging: Print environment variables
# Log Files
log $LOG_LEVEL_INFO "UPDATE_LOG_FILE=$UPDATE_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "PROXY_UPDATE_LOG_FILE=$PROXY_UPDATE_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_LOG_FILE=$IPTABLES_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "HOGEN_LOG_FILE=$HOGEN_LOG_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "MSPOO_LOG_FILE=$MSPOO_LOG_FILE" "$UPDATE_LOG_FILE"

# Snort Logging Configuration
log $LOG_LEVEL_INFO "SNORT_CONF=$SNORT_CONF" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SNORT_RULES_DIR=$SNORT_RULES_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SNORT_LOG_DIR=$SNORT_LOG_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SNORT_SERVICE=$SNORT_SERVICE" "$UPDATE_LOG_FILE"

# Directories
log $LOG_LEVEL_INFO "KHELP_UPDATE_DIR=$KHELP_UPDATE_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_INSTALLER_DIR=$KHELP_INSTALLER_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_PROXYCHAINS_DIR=$KHELP_PROXYCHAINS_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_UFW_DIR=$KHELP_UFW_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_FAIL2BAN_DIR=$KHELP_FAIL2BAN_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_IPTABLES_DIR=$KHELP_IPTABLES_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_TOR_DIR=$KHELP_TOR_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_TERMINATOR_DIR=$KHELP_TERMINATOR_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_VERIFY_DIR=$KHELP_VERIFY_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "HOGEN_DOC_DIR=$HOGEN_DOC_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "MSPOO_DOC_DIR=$MSPOO_DOC_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_LOGGING_DIR=$KHELP_LOGGING_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_DEFAULT_TERMINAL_DIR=$KHELP_DEFAULT_TERMINAL_DIR" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_STARTUP_VERIFICATION_DIR=$KHELP_STARTUP_VERIFICATION_DIR" "$UPDATE_LOG_FILE"

# Configuration files
log $LOG_LEVEL_INFO "PROXYCHAINS_CONF=$PROXYCHAINS_CONF" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "FAIL2BAN_CONFIG=$FAIL2BAN_CONFIG" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_RULES_FILE=$IPTABLES_RULES_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "CRONTAB_FILE=$CRONTAB_FILE" "$UPDATE_LOG_FILE"

# Script paths
log $LOG_LEVEL_INFO "UPDATE_PROXIES_SCRIPT=$UPDATE_PROXIES_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UFW_SCRIPT=$UFW_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_SCRIPT=$IPTABLES_SCRIPT" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "HOGEN_SCRIPT_PATH=$HOGEN_SCRIPT_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "MSPOO_SCRIPT_PATH=$MSPOO_SCRIPT_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "STARTUP_SCRIPT_PATH=$STARTUP_SCRIPT_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "DESKTOP_ENTRY_PATH=$DESKTOP_ENTRY_PATH" "$UPDATE_LOG_FILE"

# Service paths
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_SERVICE=$SYSTEMD_UPDATE_PROXIES_SERVICE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "SYSTEMD_UPDATE_PROXIES_TIMER=$SYSTEMD_UPDATE_PROXIES_TIMER" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UFW_SERVICE_PATH=$UFW_SERVICE_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_SERVICE_PATH=$IPTABLES_SERVICE_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "HOGEN_SERVICE_PATH=$HOGEN_SERVICE_PATH" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "MSPOO_SERVICE_PATH=$MSPOO_SERVICE_PATH" "$UPDATE_LOG_FILE"

# Documentation files
log $LOG_LEVEL_INFO "HOGEN_DOC_FILE=$HOGEN_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "MSPOO_DOC_FILE=$MSPOO_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_LOGGING_DOC_FILE=$KHELP_LOGGING_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_DEFAULT_TERMINAL_DOC_FILE=$KHELP_DEFAULT_TERMINAL_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_STARTUP_VERIFICATION_DOC_FILE=$KHELP_STARTUP_VERIFICATION_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "UFW_DOC_FILE=$UFW_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "FAIL2BAN_DOC_FILE=$FAIL2BAN_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "IPTABLES_DOC_FILE=$IPTABLES_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "TOR_DOC_FILE=$TOR_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_INSTALLER_DOC_FILE=$KHELP_INSTALLER_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "KHELP_UPDATE_DOC_FILE=$KHELP_UPDATE_DOC_FILE" "$UPDATE_LOG_FILE"
log $LOG_LEVEL_INFO "TERMINATOR_DOC_FILE=$TERMINATOR_DOC_FILE" "$UPDATE_LOG_FILE"

# Log proxy API URLs
log $LOG_LEVEL_INFO "PROXY_API_URL1=$PROXY_API_URL1" "$UPDATE_LOG_FILE"

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

install_terminator() {
    log $LOG_LEVEL_INFO "Installing terminator..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y terminator
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "terminator installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install terminator. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install terminator after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
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

install_snort() {
    log $LOG_LEVEL_INFO "Installing snort..." "$UPDATE_LOG_FILE"
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        apt install -y snort
        if [ $? -eq 0 ]; then
            log $LOG_LEVEL_INFO "snort installed successfully." "$UPDATE_LOG_FILE"
            return 0
        else
            attempts=$((attempts + 1))
            log $LOG_LEVEL_ERROR "Failed to install snort. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log $LOG_LEVEL_ERROR "Failed to install snort after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
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
install_terminator &
install_proxychains &
install_snort &

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
backup_config "/etc/iptables/rules.v4"
backup_config "/etc/fail2ban/jail.local"
backup_config "/etc/sslh/sslh.cfg"

# Function to update or create config files
configure_ufw() {
    log $LOG_LEVEL_INFO "Configuring UFW firewall..." "$UPDATE_LOG_FILE"
    systemctl enable ufw
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow from $ALLOWED_IP_RANGE to any port 22  # Restrict SSH access
    ufw limit ssh/tcp  # Rate limit SSH
    ufw logging on
    log $LOG_LEVEL_INFO "UFW firewall configured successfully." "$UPDATE_LOG_FILE"
}

configure_fail2ban() {
    log $LOG_LEVEL_INFO "Configuring Fail2ban..." "$UPDATE_LOG_FILE"
    apt install -y fail2ban
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
    iptables -P OUTPUT ACCEPT
    log $LOG_LEVEL_INFO "Set default policy for OUTPUT chain to ACCEPT." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -i lo -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed loopback traffic on INPUT chain." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed established and related connections on INPUT chain." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p tcp -s $ALLOWED_IP_RANGE --dport 22 -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed SSH access from $ALLOWED_IP_RANGE on port 22." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
    log $LOG_LEVEL_INFO "Rate-limited new SSH connections." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    log $LOG_LEVEL_INFO "Dropped invalid packets on INPUT chain." "$IPTABLES_LOG_FILE"
    iptables -A INPUT -p icmp -j ACCEPT
    log $LOG_LEVEL_INFO "Allowed ICMP (ping) traffic on INPUT chain." "$IPTABLES_LOG_FILE"
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
-A INPUT -p icmp -j ACCEPT
COMMIT
EOF
        log $LOG_LEVEL_INFO "Created default iptables rules file." "$IPTABLES_LOG_FILE"
    fi
    
    iptables-save > /etc/iptables/rules.v4
    log $LOG_LEVEL_INFO "iptables rules configured successfully." "$IPTABLES_LOG_FILE"
}

configure_tor() {
    log $LOG_LEVEL_INFO "Configuring Tor..." "$UPDATE_LOG_FILE"
    
    systemctl enable tor
    systemctl start tor
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to start Tor service." "$UPDATE_LOG_FILE"
        return 1
    fi

    sed -i '/socks5  127.0.0.1 9050/d' /etc/proxychains.conf
    echo "socks5  127.0.0.1 9050" >> /etc/proxychains.conf

    log $LOG_LEVEL_INFO "Tor configured successfully." "$UPDATE_LOG_FILE"
}

configure_proxychains() {
    log $LOG_LEVEL_INFO "Checking if ProxyChains is installed..." "$UPDATE_LOG_FILE"
    if ! command -v proxychains &> /dev/null; then
        log $LOG_LEVEL_INFO "ProxyChains is not installed. Installing ProxyChains..." "$UPDATE_LOG_FILE"
        local attempts=0
        local max_attempts=3

        while [ $attempts -lt $max_attempts ]; do
            if apt install -y proxychains; then
                log $LOG_LEVEL_INFO "ProxyChains installed successfully." "$UPDATE_LOG_FILE"
                break
            else
                log $LOG_LEVEL_ERROR "Failed to install ProxyChains. Retrying in $((attempts * 5)) seconds..." "$UPDATE_LOG_FILE"
                attempts=$((attempts + 1))
                sleep $((attempts * 5))
            fi

            if [ $attempts -eq $max_attempts ]; then
                log $LOG_LEVEL_ERROR "Failed to install ProxyChains after $max_attempts attempts. Please check your network connection and try again." "$UPDATE_LOG_FILE"
                exit 1
            fi
        done
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

configure_snort() {
    log $LOG_LEVEL_INFO "Configuring Snort..." "$UPDATE_LOG_FILE"
    
    mkdir -p $SNORT_RULES_DIR
    mkdir -p $SNORT_LOG_DIR
    chown snort:snort $SNORT_LOG_DIR
    chmod 750 $SNORT_LOG_DIR

    # Ensure the snort configuration file exists
    if [ ! -f /etc/snort/snort.conf ]; then
        log $LOG_LEVEL_ERROR "Snort configuration file /etc/snort/snort.conf not found." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Test the Snort configuration
    snort -T -c $SNORT_CONF -i $PRIMARY_INTERFACE
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Snort configuration test failed." "$UPDATE_LOG_FILE"
        return 1
    fi

    # Configure Snort rules
    log $LOG_LEVEL_INFO "Creating snort rules..." "$UPDATE_LOG_FILE"
    cat << EOF > $SNORT_RULES_DIR/local.rules
alert tcp \$EXTERNAL_NET any -> \$HOME_NET 22 (msg:"SSH connection attempt"; sid:1000001; rev:1;)
alert tcp \$EXTERNAL_NET any -> \$HOME_NET 80 (msg:"HTTP connection attempt"; sid:1000002; rev:1;)
alert tcp \$HOME_NET 80 -> \$EXTERNAL_NET any (msg:"HTTP response"; sid:1000003; rev:1;)
alert icmp \$EXTERNAL_NET any -> \$HOME_NET any (msg:"ICMP packet"; sid:1000004; rev:1;)
EOF

    log $LOG_LEVEL_INFO "Snort rules created successfully." "$UPDATE_LOG_FILE"
    chown snort:snort $SNORT_RULES_DIR/local.rules
    chmod 644 $SNORT_RULES_DIR/local.rules

    log $LOG_LEVEL_INFO "Snort configured successfully." "$UPDATE_LOG_FILE"
}

# Execute independent tasks in parallel
configure_ufw &
configure_fail2ban &
configure_iptables &
configure_tor &
configure_proxychains &
configure_snort &

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

create_hogen_script() {
    log $LOG_LEVEL_INFO "Creating hostname generator script..." "$HOGEN_LOG_FILE"
    cat << 'EOF' > "$HOGEN_SCRIPT_PATH"
#!/bin/bash

# Lock file location
LOCKFILE="/var/run/hogen.lock"

# Function to log messages
log() {
    local message="$1"
    local log_file="/var/log/hogen.log"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')

    # Ensure the log file exists
    touch $log_file

    # Append the log message with a timestamp
    echo "$timestamp $message" >> $log_file
}

# Function to fetch a random name from the Random User Generator API
fetch_random_name() {
    local api_url="https://randomuser.me/api/"
    local response=$(curl -s $api_url)
    
    if [ -z "$response" ]; then
        log "Failed to fetch data from the API."
        exit 1
    fi

    local first_name=$(echo $response | jq -r '.results[0].name.first')
    local last_name=$(echo $response | jq -r '.results[0].name.last')
    
    if [ -z "$first_name" ] || [ -z "$last_name" ]; then
        log "Failed to extract names from the API response."
        exit 1
    fi

    # Capitalize the first letter of the first name and last name
    first_name=$(echo $first_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    last_name=$(echo $last_name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    local name="${first_name}${last_name}"
    
    echo $name
}

# Check if another instance of the script is running
if [ -e $LOCKFILE ]; then
    log "Another instance of the script is already running. Exiting."
    exit 1
fi

# Create the lock file
touch $LOCKFILE

# Fetch and set the new hostname
newhn=$(fetch_random_name)
if [ $? -ne 0 ]; then
    log "Failed to fetch random name."
    rm -f $LOCKFILE
    exit 1
fi

log "Fetched random name: $newhn"

if hostnamectl set-hostname "$newhn"; then
    log "Hostname set to $newhn"
else
    log "Failed to set hostname to $newhn"
    rm -f $LOCKFILE
    exit 1
fi

# Ensure /etc/hosts has the correct entries
update_hosts_file() {
    local entry="$1"
    if ! grep -q "$entry" /etc/hosts; then
        echo "$entry" >> /etc/hosts
        if [ $? -eq 0 ]; then
            log "Added $entry to /etc/hosts"
        else
            log "Failed to add $entry to /etc/hosts"
            return 1
        fi
    fi
}

update_hosts_file "127.0.0.1    localhost"
update_hosts_file "127.0.0.1    $newhn"

# Ensure the current hostname is also mapped correctly
current_hostname=$(hostname)
update_hosts_file "127.0.0.1    $current_hostname"

log "Hostname set to $newhn and /etc/hosts updated"

# Remove the lock file
rm -f $LOCKFILE
EOF
    chmod +x "$HOGEN_SCRIPT_PATH"
    log $LOG_LEVEL_INFO "Hostname generator script created successfully." "$HOGEN_LOG_FILE"
}

create_mspoo_script() {
    log $LOG_LEVEL_INFO "Creating MAC spoofing script..." "$MSPOO_LOG_FILE"
    cat << 'EOF' > "$MSPOO_SCRIPT_PATH"
#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
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

# Function to validate MAC address format
validate_mac() {
    local mac="$1"
    if [[ ! $mac =~ ^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$ ]]; then
        log $LOG_LEVEL_ERROR "Invalid MAC address format: $mac" "$MSPOO_LOG_FILE"
        return 1
    fi
    return 0
}

# Function to spoof MAC address for a given interface
spoof_mac() {
    local interface=$1
    local new_mac=$(generate_random_mac)
    log $LOG_LEVEL_INFO "Spoofing MAC address for interface $interface with new MAC: $new_mac" "$MSPOO_LOG_FILE"

    if ! ip link set dev $interface down; then
        log $LOG_LEVEL_ERROR "Failed to bring down the network interface $interface." "$MSPOO_LOG_FILE"
        return 1
    fi

    if ! ip link set dev $interface address $new_mac; then
        log $LOG_LEVEL_ERROR "Failed to change the MAC address for $interface." "$MSPOO_LOG_FILE"
        return 1
    fi

    if ! ip link set dev $interface up; then
        log $LOG_LEVEL_ERROR "Failed to bring up the network interface $interface." "$MSPOO_LOG_FILE"
        return 1
    fi

    ip link show $interface | grep ether
    log $LOG_LEVEL_INFO "MAC address for $interface changed to $new_mac" "$MSPOO_LOG_FILE"
    return 0
}

# Function to determine the primary network interface
get_primary_interface() {
    ip route | grep default | awk '{print $5}'
}

# Function to get the secondary interface
get_secondary_interface() {
    local primary_interface=$1
    ip link show | awk -F': ' '{print $2}' | grep -v lo | grep -v $primary_interface
}

# Function to ensure the network interface is up
wait_for_interface() {
    local interface=$1
    for i in {1..10}; do
        if ip link show $interface | grep -q "state UP"; then
            return 0
        fi
        sleep 1
    done
    log $LOG_LEVEL_ERROR "Network interface $interface did not come up" "$MSPOO_LOG_FILE"
    return 1
}

# Main logic
primary_interface=$(get_primary_interface)
if [ -z "$primary_interface" ]; then
    log $LOG_LEVEL_ERROR "No primary network interface detected." "$MSPOO_LOG_FILE"
    exit 1
fi
log $LOG_LEVEL_INFO "Primary network interface detected: $primary_interface" "$MSPOO_LOG_FILE"

# Spoof the primary network interface
if spoof_mac $primary_interface; then
    log $LOG_LEVEL_INFO "Successfully spoofed MAC address for primary interface $primary_interface" "$MSPOO_LOG_FILE"
    wait_for_interface $primary_interface
else
    log $LOG_LEVEL_ERROR "Failed to spoof MAC address for primary interface $primary_interface" "$MSPOO_LOG_FILE"
fi

# Get the secondary network interface
secondary_interfaces=$(get_secondary_interface $primary_interface)
log $LOG_LEVEL_INFO "Secondary network interfaces detected: $secondary_interfaces" "$MSPOO_LOG_FILE"

# Spoof the secondary network interfaces
for secondary_interface in $secondary_interfaces; do
    if spoof_mac $secondary_interface; then
        log $LOG_LEVEL_INFO "Successfully spoofed MAC address for secondary interface $secondary_interface" "$MSPOO_LOG_FILE"
        wait_for_interface $secondary_interface
    else
        log $LOG_LEVEL_ERROR "Failed to spoof MAC address for secondary interface $secondary_interface" "$MSPOO_LOG_FILE"
    fi
done
EOF
    chmod +x "$MSPOO_SCRIPT_PATH"
    log $LOG_LEVEL_INFO "MAC spoofing script created successfully." "$MSPOO_LOG_FILE"
}

create_startup_script() {
    log $LOG_LEVEL_INFO "Creating the startup script..." "$UPDATE_LOG_FILE"
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
sudo ufw status verbose
traceroute www.showmyip.com
EOF
    chmod +x "$STARTUP_SCRIPT_PATH"
    log $LOG_LEVEL_INFO "Startup script created successfully." "$UPDATE_LOG_FILE"
}

create_desktop_entry() {
    log $LOG_LEVEL_INFO "Creating the desktop entry..." "$UPDATE_LOG_FILE"
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
    log $LOG_LEVEL_INFO "Desktop entry created successfully." "$UPDATE_LOG_FILE"
}

create_update_proxies_script() {
    log $LOG_LEVEL_INFO "Creating update_proxies script..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/update_proxies.sh
#!/bin/bash

LOG_LEVEL_INFO=0
LOG_LEVEL_ERROR=1
UPDATE_LOG_FILE="/var/log/update_proxies.log"

log() {
    local level=$1
    local message=$2
    local logfile=$3
    echo "$(date +"%Y-%m-%d %H:%M:%S") [LEVEL $level] $message" >> "$logfile"
}

fetch_and_update_proxies() {
    local proxy_api_url="https://spys.me/socks.txt"
    local proxy_list_file="/etc/proxychains/fetched_proxies.txt"
    local max_proxies=100
    local attempts=0
    local max_attempts=3

    mkdir -p "$(dirname "$proxy_list_file")"

    while [ $attempts -lt $max_attempts ]; do
        log $LOG_LEVEL_INFO "Fetching new proxy list from $proxy_api_url (attempt $((attempts + 1)))..." "$UPDATE_LOG_FILE"
        local response=$(curl -s $proxy_api_url)
        if [ -n "$response" ]; then
            local valid_proxies=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -n $max_proxies)
            if [ -n "$valid_proxies" ]; then
                echo "$valid_proxies" > "$proxy_list_file"
                log $LOG_LEVEL_INFO "Fetched $(echo "$valid_proxies" | wc -l) valid proxies." "$UPDATE_LOG_FILE"
                return 0 # Exit the function after a successful fetch
            else
                log $LOG_LEVEL_ERROR "No valid proxies found in the response from $proxy_api_url." "$UPDATE_LOG_FILE"
            fi
        else
            log $LOG_LEVEL_ERROR "Failed to fetch proxies from $proxy_api_url or the response is empty." "$UPDATE_LOG_FILE"
        fi
        attempts=$((attempts + 1))
        sleep 5
    done

    log $LOG_LEVEL_ERROR "Failed to fetch proxies after $max_attempts attempts. Exiting." "$UPDATE_LOG_FILE"
    exit 1
}

# Fetch and update proxy list
fetch_and_update_proxies

log $LOG_LEVEL_INFO "update_proxies script executed successfully." "$UPDATE_LOG_FILE"
EOF
    chmod +x /usr/local/bin/update_proxies.sh
    log $LOG_LEVEL_INFO "update_proxies script created successfully." "$UPDATE_LOG_FILE"
}

create_snort_script() {
    log $LOG_LEVEL_INFO "Creating snort script..." "$UPDATE_LOG_FILE"
    cat << EOF > "$SNORT_CONF"
# Define network variables
var HOME_NET 192.168.1.0/24
var EXTERNAL_NET any

# Preprocessor configurations
preprocessor stream5_global: track_tcp yes, track_udp yes
preprocessor stream5_tcp: policy windows, detect_anomalies, require_3whs 180, overlap_limit 10, small_segments 3 bytes 150, timeout 180
preprocessor stream5_udp: timeout 180
preprocessor stream5_icmp: timeout 180

preprocessor http_inspect: global iis_unicode_map unicode.map 1252
preprocessor http_inspect_server: server default profile all ports { 80 8080 8180 } oversize_dir_length 500

preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10

preprocessor stream5_ssh: max_sessions 256

preprocessor dcerpc2: memcap 102400, events [co]

preprocessor dns: ports { 53 } enable_rdata_overflow no enable_rdata_txt_overflow no enable_rdata_type_overflow no

preprocessor ssl: noinspect_encrypted

# Include rule sets
include \$RULE_PATH/local.rules
include \$RULE_PATH/community.rules

# Output modules
output alert_fast: stdout
output log_tcpdump: $SNORT_LOG_DIR/snort.log

# Path to rule files
var RULE_PATH $SNORT_RULES_DIR

# Path to dynamic preprocessor libraries
dynamicpreprocessor directory /usr/local/lib/snort_dynamicpreprocessor/
dynamicengine /usr/local/lib/snort_dynamicengine/libsf_engine.so
dynamicdetection directory /usr/local/lib/snort_dynamicrules/

# Customize and add your rules
include \$RULE_PATH/snort.rules
EOF
    chmod +x "$SNORT_LOG_DIR"
    log $LOG_LEVEL_INFO "snort script created successfully." "$UPDATE_LOG_FILE"
}

# Execute script creation tasks in parallel
create_ufw_script &
create_iptables_script &
create_hogen_script &
create_mspoo_script &
create_startup_script &
create_desktop_entry &
create_update_proxies_script &
create_snort_script &

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

create_hogen_service() {
    log $LOG_LEVEL_INFO "Creating and enabling hostname generator service..." "$HOGEN_LOG_FILE"
    cat << EOF > "$HOGEN_SERVICE_PATH"
[Unit]
Description=HOGEN Hostname Generator
Before=display-manager.service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hogen.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    chmod +x "$HOGEN_SERVICE_PATH"
    systemctl daemon-reload
    systemctl enable hogen.service
    systemctl start hogen.service
    log $LOG_LEVEL_INFO "Hostname generator service created and enabled successfully." "$HOGEN_LOG_FILE"
}

create_mspoo_service() {
    log $LOG_LEVEL_INFO "Creating and enabling MAC spoofing service..." "$MSPOO_LOG_FILE"
    cat << EOF > "$MSPOO_SERVICE_PATH"
[Unit]
Description=MSPOO MACSpoofing Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$MSPOO_SCRIPT_PATH
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    chmod +x "$MSPOO_SERVICE_PATH"
    systemctl daemon-reload
    systemctl enable mspoo.service
    systemctl start mspoo.service
    log $LOG_LEVEL_INFO "MAC spoofing service created and enabled successfully." "$MSPOO_LOG_FILE"
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

create_snort_service(){
    log $LOG_LEVEL_INFO "Creating and enabling Snort service..." "$UPDATE_LOG_FILE"
    cat << EOF > "$SNORT_SERVICE_PATH"
[Unit]
Description=Snort Network Intrusion Detection System
After=network.target

[Service]
ExecStart=/usr/sbin/snort -c /etc/snort/snort.conf -i $(get_primary_interface)
ExecReload=/bin/kill -HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Set the correct permissions for the service file
    chmod +x "$SNORT_SERVICE_PATH"

    # Enable and start the Snort service
    systemctl daemon-reload
    systemctl enable snort
    systemctl start snort
    if [ $? -ne 0 ]; then
        log $LOG_LEVEL_ERROR "Failed to enable/start snort service." "$UPDATE_LOG_FILE"
        exit 1
    fi
    log $LOG_LEVEL_INFO "Snort configured and started successfully." "$UPDATE_LOG_FILE"
}

# Execute systemd service creation tasks in parallel
create_ufw_service &
create_iptables_service &
create_hogen_service &
create_mspoo_service &
create_update_proxies_service &
create_update_proxies_timer &
create_snort_service &

# Wait for all background tasks to complete
wait

log $LOG_LEVEL_INFO "All systemd service creation tasks completed successfully." "$UPDATE_LOG_FILE"

# Function to create README.md
create_logging_readme() {
  mkdir -p "$KHELP_LOGGING_DIR"
  cat << 'EOF' > "$KHELP_LOGGING_DIR/README.md"
# Logging Function Documentation

## Table of Contents
1. [Overview](#overview)
2. [Log Levels](#log-levels)
3. [Logging Function](#logging-function)
   - [Parameters](#parameters)
   - [Function Logic](#function-logic)
4. [Example Usage](#example-usage)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the enhanced logging function and log levels used in the scripts. The logging function provides detailed logging with various log levels, log rotation, and metadata formatting to assist in debugging and monitoring the system.

## Log Levels
The following log levels are defined:

- `LOG_LEVEL_DEBUG=0`: Detailed debugging information.
- `LOG_LEVEL_INFO=1`: General informational messages.
- `LOG_LEVEL_WARNING=2`: Warnings about potential issues.
- `LOG_LEVEL_ERROR=3`: Errors that have occurred.
- `LOG_LEVEL_CRITICAL=4`: Critical issues that need immediate attention.

The current log level is set using the `CURRENT_LOG_LEVEL` variable. This can be adjusted as needed to control the verbosity of the logs.

## Logging Function
The logging function `log()` is designed to log messages with different levels of severity, rotate logs if they exceed a certain size, and include detailed metadata in each log entry.

### Parameters
- `level`: The log level of the message (e.g., `LOG_LEVEL_INFO`).
- `message`: The message to be logged.
- `log_file`: The file where the log message should be written.

### Function Logic
1. **Determine Log Level Name**: The log level name is determined based on the provided log level.
2. **Check Log Level**: The function checks if the current log level is sufficient to log the message. If not, it returns immediately.
3. **Log Rotation**: If the log file exceeds 1MB, it is rotated by renaming it with a timestamp.
4. **Metadata Inclusion**: Metadata such as timestamp, script name, user, and hostname are included in the log entry.
5. **Log Formatting and Writing**: The log entry is formatted and written to the specified log file using the `tee` command, which also allows the message to be displayed on the console.

### Example Usage
```bash
# Example usage of the log function
log $LOG_LEVEL_INFO "This is an informational message." "/var/log/khelp_proxy.log"
log $LOG_LEVEL_ERROR "This is an error message." "/var/log/khelp_proxy.log"
log $LOG_LEVEL_WARNING "This is a warning message." "/var/log/khelp_proxy.log"
```
This example demonstrates how to use the logging function to log messages with different levels of severity to a specified log file.

## Troubleshooting
### Common Issues
1. **Log File Not Created**:
   - Ensure the script has write permissions to the directory where the log file is to be created.
   - Check if the `log_file` path is correctly specified.

2. **Log Rotation Not Working**:
   - Verify if the log file size exceeds 1MB.
   - Ensure there are no errors in the log rotation logic.

3. **Log Messages Not Displayed**:
   - Confirm the `CURRENT_LOG_LEVEL` is set to a level that includes the messages being logged.
   - Check if the `tee` command is available and functioning correctly.

## Best Practices
- **Consistent Log Levels**: Use consistent log levels throughout the script to maintain clarity.
- **Clear Messages**: Ensure log messages are clear and provide sufficient context.
- **Regular Log Maintenance**: Regularly check and maintain log files to prevent excessive disk usage.
- **Security Considerations**: Avoid logging sensitive information to prevent security risks.

Feel free to reach out if you encounter any issues or have any questions regarding the logging function.
EOF
}

create_update_readme() {
  mkdir -p "$KHELP_UPDATE_DIR"
  cat << 'EOF' > "$KHELP_UPDATE_DIR/README.md"
# System Update Function Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Parameters](#parameters)
   - [Function Logic](#function-logic)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the `update_system` function, which is designed to update and upgrade the system packages. It includes retry logic to handle potential network or package manager issues, ensuring system stability and reliability.

## Function Explanation

### Parameters
- No parameters are required for this function.

### Function Logic
1. **Logging**: Logs the start of the system update process with an informational log level.
2. **Retry Mechanism**: Attempts to update and upgrade the system up to three times in case of failures.
3. **Update and Upgrade**: Uses `apt update`, `apt full-upgrade -y`, `apt autoremove -y`, and `apt autoclean` to update and clean the system packages.
4. **Logging Success**: Logs a message indicating the completion of the update and upgrade process.
5. **Retry Logic**: If the update fails, it waits and retries up to a maximum of three attempts.
6. **Logging Failure**: Logs an error message if the update fails after the maximum attempts and exits with an error code.

## Example Usage
```bash
# Example usage of the update_system function
update_system
```

## Detailed Steps
1. **Initial Logging**: The function starts by logging an informational message indicating the beginning of the system update.
2. **Loop for Retry**: A loop is used to attempt the update up to three times. If the update is successful, it logs the success and returns.
3. **Update and Upgrade Commands**: The following commands are executed to update the system:
   - `apt update`: Fetches the list of available updates.
   - `apt full-upgrade -y`: Installs the available updates.
   - `apt autoremove -y`: Removes unnecessary packages.
   - `apt autoclean`: Cleans up the local repository of package files.
4. **Failure Handling**: If any of the commands fail, it logs an error message, increments the attempt counter, and waits for a specified time before retrying.
5. **Final Failure Logging**: If all attempts fail, it logs an error message and exits with an error code.

## Troubleshooting
### Common Issues
1. **Network Issues**:
   - Ensure the system has a stable internet connection.
   - Check if the package manager's repository URLs are accessible.

2. **Insufficient Permissions**:
   - Ensure the script is run with sufficient privileges (e.g., using `sudo`).

3. **Package Manager Errors**:
   - Review the error messages logged to identify specific issues with the package manager.
   - Check for broken dependencies or held packages that may need manual intervention.

## Best Practices
- **Regular Updates**: Schedule regular updates to keep the system secure and up-to-date.
- **Monitor Logs**: Regularly review the update logs to ensure updates are applied successfully.
- **Backup Before Updates**: Consider creating backups before performing system updates to prevent data loss in case of issues.
- **Test Updates**: If possible, test updates in a staging environment before applying them to production systems.

Feel free to reach out if you encounter any issues or have any questions regarding the system update function.
EOF
}

create_installer_readme() {
  mkdir -p "$KHELP_INSTALLER_DIR"
  cat << 'EOF' > "$KHELP_INSTALLER_DIR/README.md"
# Package Installation Functions Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Parameters](#parameters)
   - [Function Logic](#function-logic)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the individual package installation functions, which are designed to install essential helper tools and packages with a retry mechanism to handle potential issues during the installation process. Each function incorporates advanced logging and error handling to ensure reliability and ease of debugging.

## Function Explanation

### Parameters
- No parameters are required for these functions.

### Function Logic
1. **Logging**: Logs the start of the package installation process with an informational log level.
2. **Retry Mechanism**: Attempts to install each package up to three times in case of failures.
3. **Package Installation**: Uses `sudo apt install -y` to install the specified packages individually.
4. **Logging Success**: Logs a message indicating the successful installation of each package.
5. **Retry Logic**: If the installation of a package fails, it waits and retries up to a maximum of three attempts.
6. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code for that package.

## Example Usage
```bash
# Install curl
install_curl

# Install tor
install_tor

# Install ufw
install_ufw

# Install jq
install_jq

# Install iptables
install_iptables

# Install fail2ban
install_fail2ban

# Install sslh
install_sslh

# Install terminator
install_terminator

# Install proxychains
install_proxychains

# Install snort
install_snort
```

## Detailed Steps
1. **Initial Logging**: Each function starts by logging an informational message indicating the beginning of the package installation.
2. **Loop for Retry**: For each package, a loop is used to attempt the installation up to three times. If the installation is successful, it logs the success and returns.
3. **Package Installation Command**: The following command is executed to install each package:
   - `sudo apt install -y <package>`
4. **Failure Handling**: If the installation command for a package fails, it logs an error message, increments the attempt counter, and waits for a specified time before retrying.
5. **Final Failure Logging**: If all attempts to install a package fail, it logs an error message and exits with an error code for that package.

## Troubleshooting
### Common Issues
1. **Network Issues**:
   - Ensure the system has a stable internet connection.
   - Check if the package manager's repository URLs are accessible.

2. **Insufficient Permissions**:
   - Ensure the script is run with sufficient privileges (e.g., using `sudo`).

3. **Package Manager Errors**:
   - Review the error messages logged to identify specific issues with the package manager.
   - Check for broken dependencies or held packages that may need manual intervention.

## Best Practices
- **Regular Updates**: Schedule regular updates to keep the system secure and up-to-date.
- **Monitor Logs**: Regularly review the installation logs to ensure packages are installed successfully.
- **Backup Before Installation**: Consider creating backups before installing new packages to prevent data loss in case of issues.
- **Test Installations**: If possible, test the installation process in a staging environment before applying it to production systems.

Feel free to reach out if you encounter any issues or have any questions regarding the package installation functions.
EOF
}

create_proxychains_readme() {
  mkdir -p "$KHELP_PROXYCHAINS_DIR"
  cat << 'EOF' > "$KHELP_PROXYCHAINS_DIR/README.md"
# ProxyChains Configuration Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Checking ProxyChains Installation](#checking-proxychains-installation)
   - [Configuring ProxyChains](#configuring-proxychains)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of ensuring ProxyChains is installed and properly configured. ProxyChains is a tool that allows you to redirect connections through proxy servers.

## Function Explanation

### Checking ProxyChains Installation
1. **Logging**: Logs the start of the process to check if ProxyChains is installed.
2. **Check Installation**: Uses the `command -v proxychains` command to check if ProxyChains is installed.
3. **Installation**: If ProxyChains is not installed, it attempts to install it up to three times using `apt install -y proxychains`.
4. **Logging Success**: Logs a message indicating the successful installation of ProxyChains.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.

### Configuring ProxyChains
1. **Logging**: Logs the start of the process to configure ProxyChains.
2. **Check Configuration File**: Checks if the `/etc/proxychains.conf` file exists.
3. **Creating Configuration File**: If the configuration file does not exist, it creates the file with the default configuration.
4. **Updating Configuration**: Updates the necessary lines in the `proxychains.conf` file to ensure proper configuration.
5. **Appending Proxy List**: Appends the fetched proxy list to the `proxychains.conf` file.
6. **Logging Configuration**: Logs messages indicating the creation or update of the `proxychains.conf` file.

## Example Usage
```bash
# Ensure ProxyChains is installed and configured
configure_proxychains
```

## Detailed Steps
1. **Initial Logging**: The function starts by logging an informational message indicating the beginning of the ProxyChains installation and configuration process.
2. **Check and Install ProxyChains**: Uses `command -v proxychains` to check if ProxyChains is installed. If not, it attempts to install it up to three times.
3. **Check Configuration File**: Checks if the `/etc/proxychains.conf` file exists. If not, creates the file with the default configuration.
4. **Update Configuration**: Uses `sed` to update necessary lines in the `proxychains.conf` file to ensure proper configuration.
5. **Append Proxy List**: Appends the fetched proxy list to the `proxychains.conf` file.
6. **Final Logging**: Logs messages indicating the successful installation and configuration of ProxyChains.

## Troubleshooting
### Common Issues
1. **ProxyChains Not Installed**:
   - Ensure the system has a stable internet connection.
   - Check if the package manager's repository URLs are accessible.

2. **Configuration File Issues**:
   - Verify the permissions of the `/etc/proxychains.conf` file.
   - Ensure the configuration file is correctly formatted.

3. **Proxy List Not Appended**:
   - Check if the proxy list fetching script is running correctly.
   - Verify the validity of the proxy list URLs.

## Best Practices
- **Regular Updates**: Keep the proxy list and ProxyChains configuration updated to ensure optimal performance.
- **Monitor Logs**: Regularly review the logs to identify and resolve any issues.
- **Backup Configuration**: Consider creating backups of the `proxychains.conf` file before making changes.

Feel free to reach out if you encounter any issues or have any questions regarding the ProxyChains configuration.

# Proxy List Setup Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Checking Required Files and Directories](#checking-required-files-and-directories)
   - [Ensuring ProxyChains Installation](#ensuring-proxychains-installation)
   - [Configuring ProxyChains](#configuring-proxychains)
   - [Creating Proxy Fetching Script](#creating-proxy-fetching-script)
   - [Creating Systemd Service](#creating-systemd-service)
   - [Creating Systemd Timer](#creating-systemd-timer)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of ensuring ProxyChains is configured, fetching a list of proxies, and setting up systemd services and timers to keep the proxy list updated.

## Function Explanation

### Checking Required Files and Directories
1. **Logging**: Logs the start of the process to check if required files and directories exist.
2. **Check Existence**: Checks if the specified files and directories exist.
3. **Logging Failure**: Logs an error message if a required file or directory does not exist and exits with an error code.

### Ensuring ProxyChains Installation
1. **Logging**: Logs the start of the process to check if ProxyChains is installed.
2. **Check Installation**: Uses the `command -v proxychains` command to check if ProxyChains is installed.
3. **Installation**: If ProxyChains is not installed, it attempts to install it up to three times using `apt install -y proxychains`.
4. **Logging Success**: Logs a message indicating the successful installation of ProxyChains.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.

### Configuring ProxyChains
1. **Logging**: Logs the start of the process to configure ProxyChains.
2. **Check Configuration File**: Checks if the `/etc/proxychains.conf` file exists and creates it if it does not.
3. **Check and Update Configuration**: Checks if ProxyChains is already configured for Tor and updates the configuration if it is not.
4. **Appending Proxy List**: Appends the fetched proxy list to the `proxychains.conf` file.
5. **Logging Configuration**: Logs messages indicating the creation or update of the `proxychains.conf` file.

### Creating Proxy Fetching Script
1. **Logging**: Logs the start of the process to create a script for fetching and validating proxies.
2. **Script Creation**: Creates the script `/usr/local/bin/update_proxies.sh` to fetch and validate proxies from multiple API URLs.
3. **Logging Script Creation**: Logs a message indicating the creation of the proxy fetching script.

### Creating Systemd Service
1. **Logging**: Logs the start of the process to create a systemd service.
2. **Service Creation**: Creates the systemd service `/etc/systemd/system/update_proxies.service` to run the proxy update script on startup.
3. **Enabling Service**: Enables the systemd service.
4. **Logging Service Creation**: Logs a message indicating the creation and enabling of the systemd service.

### Creating Systemd Timer
1. **Logging**: Logs the start of the process to create a systemd timer.
2. **Timer Creation**: Creates the systemd timer `/etc/systemd/system/update_proxies.timer` to run the proxy update script every 30 minutes.
3. **Enabling Timer**: Enables and starts the systemd timer.
4. **Logging Timer Creation**: Logs a message indicating the creation and starting of the systemd timer.

## Example Usage
```bash
# Ensure ProxyChains is installed and configured
configure_proxychains

# Create proxy fetching script
create_proxy_fetching_script

# Create and enable systemd service and timer
create_systemd_service_and_timer
```

## Detailed Steps
1. **Initial Logging**: The function starts by logging an informational message indicating the beginning of the required file and directory checks.
2. **Check Required Files and Directories**: Checks if the specified files and directories exist. Logs an error message if any are missing.
3. **Ensure ProxyChains Installation**: Uses `command -v proxychains` to check if ProxyChains is installed. If not, attempts to install it up to three times.
4. **Check Configuration File**: Checks if the `/etc/proxychains.conf` file exists and creates it if it does not.
5. **Update Configuration**: Ensures the configuration is set up for Tor and appends the fetched proxy list.
6. **Create Proxy Fetching Script**: Logs the start of the process, creates the script, and logs the completion.
7. **Create Systemd Service**: Logs the start of the process, creates the service, enables it, and logs the completion.
8. **Create Systemd Timer**: Logs the start of the process, creates the timer, enables and starts it, and logs the completion.

## Troubleshooting
### Common Issues
1. **Missing Files/Directories**:
   - Verify the existence and permissions of required files and directories.

2. **ProxyChains Not Installed**:
   - Ensure the system has a stable internet connection.
   - Check if the package manager's repository URLs are accessible.

3. **Configuration File Issues**:
   - Verify the permissions of the `/etc/proxychains.conf` file.
   - Ensure the configuration file is correctly formatted.

4. **Proxy List Not Appended**:
   - Check if the proxy list fetching script is running correctly.
   - Verify the validity of the proxy list URLs.

5. **Systemd Service/Timer Issues**:
   - Ensure the service and timer files are correctly formatted.
   - Check the status of the service and timer using `systemctl status`.

## Best Practices
- **Regular Updates**: Keep the proxy list and ProxyChains configuration updated to ensure optimal performance.
- **Monitor Logs**: Regularly review the logs to identify and resolve any issues.
- **Backup Configuration**: Consider creating backups of the `proxychains.conf` file before making changes.
- **Test Configuration**: Test the proxy fetching script, systemd service, and timer in a staging environment before deploying to production.

Feel free to reach out if you encounter any issues or have any questions regarding the ProxyChains configuration and proxy list setup.
EOF
}

create_ufw_readme() {
  mkdir -p "$KHELP_UFW_DIR"
  cat << 'EOF' > "$KHELP_UFW_DIR/README.md"
# UFW Configuration Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Configuring UFW](#configuring-ufw)
   - [Creating and Enabling UFW Service](#creating-and-enabling-ufw-service)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of configuring UFW (Uncomplicated Firewall) and setting up a systemd service to ensure it runs on startup. UFW is a user-friendly interface for managing iptables firewall rules.

## Function Explanation

### Configuring UFW
1. **Logging**: Logs the start of the UFW configuration process.
2. **Enable UFW**: Uses `systemctl enable ufw` to enable UFW to start at boot.
3. **Force Enable UFW**: Uses `ufw --force enable` to enable UFW with force, ensuring no user interaction is required.
4. **Set Default Policies**: Sets the default policies to deny incoming traffic and allow outgoing traffic.
5. **Allow SSH**: Configures UFW to allow SSH connections.
6. **Enable Logging**: Enables logging for UFW.
7. **Logging Success**: Logs a message indicating the successful configuration of UFW.

### Creating and Enabling UFW Service
1. **Logging**: Logs the start of the process to create and enable the UFW service.
2. **Create Script**: Creates a script `/usr/local/bin/ufw.sh` to enable and start UFW, and keep the script running to prevent the service from deactivating.
3. **Make Script Executable**: Sets the script as executable.
4. **Create Service File**: Creates a systemd service file `/etc/systemd/system/ufw.service` to run the UFW script on startup.
5. **Reload Systemd**: Reloads the systemd daemon to recognize the new service.
6. **Enable Service**: Enables the UFW service to start at boot.
7. **Start Service**: Starts the UFW service.
8. **Logging Success**: Logs a message indicating the successful creation and enabling of the UFW service.

## Example Usage
```bash
# Configure UFW
configure_ufw

# Create and enable UFW service
create_ufw_service
```

## Detailed Steps
### Configuring UFW
1. **Initial Logging**: Logs the start of the UFW configuration process.
2. **Enable UFW**: Executes `systemctl enable ufw` to ensure UFW starts at boot.
3. **Force Enable UFW**: Runs `ufw --force enable` to enable UFW without requiring user interaction.
4. **Set Default Policies**: Configures UFW with default policies to deny all incoming traffic and allow all outgoing traffic:
   ```bash
   ufw default deny incoming
   ufw default allow outgoing
   ```
5. **Allow SSH**: Configures UFW to allow SSH connections:
   ```bash
   ufw allow ssh
   ```
6. **Enable Logging**: Enables UFW logging:
   ```bash
   ufw logging on
   ```
7. **Logging Success**: Logs a message indicating the successful configuration of UFW.

### Creating and Enabling UFW Service
1. **Initial Logging**: Logs the start of the process to create and enable the UFW service.
2. **Create Script**: Creates a script at `/usr/local/bin/ufw.sh` to enable and start UFW, ensuring it remains active:
   ```bash
   #!/bin/bash
   ufw enable
   ufw status
   while true; do sleep 3600; done
   ```
3. **Make Script Executable**: Sets the script as executable:
   ```bash
   chmod +x /usr/local/bin/ufw.sh
   ```
4. **Create Service File**: Creates a systemd service file at `/etc/systemd/system/ufw.service`:
   ```ini
   [Unit]
   Description=UFW Firewall
   After=network.target

   [Service]
   ExecStart=/usr/local/bin/ufw.sh
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```
5. **Reload Systemd**: Reloads the systemd daemon to recognize the new service:
   ```bash
   systemctl daemon-reload
   ```
6. **Enable Service**: Enables the UFW service to start at boot:
   ```bash
   systemctl enable ufw.service
   ```
7. **Start Service**: Starts the UFW service:
   ```bash
   systemctl start ufw.service
   ```
8. **Logging Success**: Logs a message indicating the successful creation and enabling of the UFW service.

## Troubleshooting
### Common Issues
1. **UFW Not Enabled**:
   - Ensure UFW is correctly installed and the system has the necessary permissions.
   - Verify the systemd service and script paths are correct.

2. **Service Fails to Start**:
   - Check the service status using `systemctl status ufw.service` for error messages.
   - Ensure the script `/usr/local/bin/ufw.sh` is executable and correctly formatted.

3. **Firewall Rules Not Applied**:
   - Verify the UFW configuration and rules using `ufw status`.
   - Ensure no conflicting firewall rules are present.

## Best Practices
- **Regularly Review Firewall Rules**: Periodically review and update the firewall rules to ensure they meet current security requirements.
- **Monitor Logs**: Regularly review UFW logs to identify and address any potential security issues.
- **Test Configuration**: Test the UFW configuration in a staging environment before applying it to production systems.

Feel free to reach out if you encounter any issues or have any questions regarding the UFW configuration and service setup.
EOF
}

create_fail2ban_readme() {
  mkdir -p "$KHELP_FAIL2BAN_DIR"
  cat << 'EOF' > "$KHELP_FAIL2BAN_DIR/README.md"
# Fail2ban Configuration Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Configuring Fail2ban](#configuring-fail2ban)
   - [Fail2ban Configuration](#fail2ban-configuration)
   - [Enabling and Starting Fail2ban](#enabling-and-starting-fail2ban)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of configuring Fail2ban, a tool used to protect servers from brute-force attacks by banning IP addresses that show malicious signs.

## Function Explanation

### Configuring Fail2ban
1. **Logging**: Logs the start of the Fail2ban configuration process with an informational log level.
2. **Retry Mechanism**: Attempts to install Fail2ban up to three times in case of failures.
3. **Installation**: Uses `sudo apt install -y fail2ban` to install Fail2ban.
4. **Logging Success**: Logs a message indicating the successful installation of Fail2ban.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.

### Fail2ban Configuration
1. **Create Configuration File**: Creates the `/etc/fail2ban/jail.local` configuration file with the following settings:
   - `ignoreip`: Specifies IP addresses to ignore.
   - `bantime`: Duration for which the IP is banned.
   - `findtime`: Time window for detecting failures.
   - `maxretry`: Maximum number of retries before banning.
   - `[sshd]` and `[sshd-ddos]`: Enables protection for SSH and SSHD-DDoS.
2. **Logging Configuration**: Logs a message indicating the creation and configuration of the `/etc/fail2ban/jail.local` file.

### Enabling and Starting Fail2ban
1. **Enable Fail2ban**: Uses `sudo systemctl enable fail2ban` to enable Fail2ban to start at boot.
2. **Start Fail2ban**: Uses `sudo systemctl start fail2ban` to start Fail2ban.
3. **Check Status**: Checks if Fail2ban is active using `sudo systemctl is-active --quiet fail2ban`.
4. **Logging Success**: Logs a message indicating the successful configuration and start of Fail2ban.
5. **Logging Failure**: Logs an error message if Fail2ban fails to start and exits with an error code.

## Example Usage
```bash
# Configure and start Fail2ban
configure_fail2ban
```

## Detailed Steps
### Configuring Fail2ban
1. **Initial Logging**: Logs the start of the Fail2ban configuration process.
2. **Retry Mechanism**: Attempts to install Fail2ban up to three times using:
   ```bash
   sudo apt install -y fail2ban
   ```
3. **Logging Success/Failure**: Logs a success message if installation is successful, otherwise logs an error message after the maximum attempts.

### Fail2ban Configuration
1. **Create Configuration File**: Creates the `/etc/fail2ban/jail.local` configuration file with the following settings:
   ```ini
   [DEFAULT]
   ignoreip = 127.0.0.1/8
   bantime  = 600
   findtime  = 600
   maxretry = 3

   [sshd]
   enabled = true

   [sshd-ddos]
   enabled = true
   ```
2. **Logging Configuration**: Logs a message indicating the creation and configuration of the `jail.local` file.

### Enabling and Starting Fail2ban
1. **Enable Fail2ban**: Executes:
   ```bash
   sudo systemctl enable fail2ban
   ```
2. **Start Fail2ban**: Executes:
   ```bash
   sudo systemctl start fail2ban
   ```
3. **Check Status**: Verifies if Fail2ban is active:
   ```bash
   sudo systemctl is-active --quiet fail2ban
   ```
4. **Logging Success/Failure**: Logs a success message if Fail2ban is active, otherwise logs an error message if it fails to start.

## Troubleshooting
### Common Issues
1. **Installation Failures**:
   - Ensure the system has a stable internet connection.
   - Verify the package manager's repository URLs are accessible.

2. **Configuration Issues**:
   - Verify the permissions and formatting of the `/etc/fail2ban/jail.local` file.

3. **Service Failures**:
   - Check the status of the Fail2ban service using `systemctl status fail2ban` for error messages.
   - Ensure no conflicting services are running.

## Best Practices
- **Regularly Review Bans**: Periodically review the list of banned IP addresses to ensure no false positives.
- **Monitor Logs**: Regularly review Fail2ban logs to identify and address any potential security issues.
- **Test Configuration**: Test the Fail2ban configuration in a staging environment before applying it to production systems.
- **Update Fail2ban**: Keep Fail2ban up-to-date to benefit from the latest security features and updates.

Feel free to reach out if you encounter any issues or have any questions regarding the Fail2ban configuration.
EOF
}

create_iptables_readme() {
  mkdir -p "$KHELP_IPTABLES_DIR"
  cat << 'EOF' > "$KHELP_IPTABLES_DIR/README.md"
# iptables Configuration Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Ensuring iptables Directory](#ensuring-iptables-directory)
   - [Configuring iptables](#configuring-iptables)
   - [Debugging iptables Setup](#debugging-iptables-setup)
   - [Creating and Enabling iptables Service](#creating-and-enabling-iptables-service)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of configuring iptables, a utility for configuring the Linux kernel firewall, and setting up a systemd service to ensure the iptables rules are applied on startup.

## Function Explanation

### Ensuring iptables Directory
1. **Directory Creation**: Ensures the `/etc/iptables` directory exists using `mkdir -p /etc/iptables`.

### Configuring iptables
1. **Logging**: Logs the start of the iptables configuration process with an informational log level.
2. **Flush Rules**: Uses `iptables -F` to flush all current rules and `iptables -X` to delete all user-defined chains.
3. **Set Default Policies**: Sets the default policies to drop all incoming and forwarded traffic, and to accept all outgoing traffic.
4. **Allow Loopback and Established Connections**: Configures rules to allow loopback traffic and established or related connections.
5. **Allow SSH and ICMP**: Configures rules to allow SSH connections on port 22 and ICMP (ping) traffic.
6. **Save Rules**: Saves the iptables rules to `/etc/iptables/rules.v4` using `iptables-save`.
7. **Logging Success**: Logs a message indicating the successful configuration of iptables.
8. **Logging Failure**: Logs an error message if the rules fail to save and exits with an error code.

### Debugging iptables Setup
1. **Logging**: Logs the current iptables rules after setup for debugging purposes.
2. **List Rules**: Uses `iptables -L -v` to list the current rules and appends the output to `/var/log/iptables_script.log`.

### Creating and Enabling iptables Service
1. **Logging**: Logs the start of the process to create and enable the iptables service.
2. **Create Script**: Creates a script `/usr/local/bin/iptables.sh` to restore iptables rules from `/etc/iptables/rules.v4`.
3. **Make Script Executable**: Sets the script as executable.
4. **Create Service File**: Creates a systemd service file `/etc/systemd/system/iptables.service` to run the iptables restoration script on startup.
5. **Reload Systemd**: Reloads the systemd daemon to recognize the new service.
6. **Enable and Start Service**: Enables and starts the iptables service.
7. **Logging Success**: Logs a message indicating the successful creation and enabling of the iptables service.
8. **Logging Failure**: Logs an error message if the service fails to enable or start and exits with an error code.

## Example Usage
```bash
# Ensure iptables directory exists
ensure_iptables_directory

# Configure iptables
configure_iptables

# Create and enable iptables service
create_iptables_service
```

## Detailed Steps
### Ensuring iptables Directory
1. **Directory Creation**: Ensures the `/etc/iptables` directory exists using:
   ```bash
   mkdir -p /etc/iptables
   ```

### Configuring iptables
1. **Initial Logging**: Logs the start of the iptables configuration process.
2. **Flush Rules**: Executes:
   ```bash
   iptables -F
   iptables -X
   ```
3. **Set Default Policies**: Configures default policies to drop all incoming and forwarded traffic, and accept all outgoing traffic:
   ```bash
   iptables -P INPUT DROP
   iptables -P FORWARD DROP
   iptables -P OUTPUT ACCEPT
   ```
4. **Allow Loopback and Established Connections**: Adds rules to allow loopback traffic and established or related connections:
   ```bash
   iptables -A INPUT -i lo -j ACCEPT
   iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   ```
5. **Allow SSH and ICMP**: Adds rules to allow SSH on port 22 and ICMP traffic:
   ```bash
   iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   iptables -A INPUT -p icmp -j ACCEPT
   ```
6. **Save Rules**: Saves the iptables rules to `/etc/iptables/rules.v4` using:
   ```bash
   iptables-save > /etc/iptables/rules.v4
   ```
7. **Logging Success/Failure**: Logs a success message if rules are saved, otherwise logs an error message.

### Debugging iptables Setup
1. **Initial Logging**: Logs the current iptables rules for debugging purposes.
2. **List Rules**: Executes:
   ```bash
   iptables -L -v
   ```
   and appends the output to `/var/log/iptables_script.log`.

### Creating and Enabling iptables Service
1. **Initial Logging**: Logs the start of the process to create and enable the iptables service.
2. **Create Script**: Creates a script at `/usr/local/bin/iptables.sh` to restore iptables rules:
   ```bash
   #!/bin/bash
   iptables-restore < /etc/iptables/rules.v4
   ```
3. **Make Script Executable**: Sets the script as executable:
   ```bash
   chmod +x /usr/local/bin/iptables.sh
   ```
4. **Create Service File**: Creates a systemd service file at `/etc/systemd/system/iptables.service`:
   ```ini
   [Unit]
   Description=Restore iptables firewall rules
   After=network.target

   [Service]
   ExecStart=/usr/local/bin/iptables.sh
   Type=oneshot
   RemainAfterExit=yes

   [Install]
   WantedBy=multi-user.target
   ```
5. **Reload Systemd**: Reloads the systemd daemon:
   ```bash
   systemctl daemon-reload
   ```
6. **Enable and Start Service**: Enables and starts the iptables service:
   ```bash
   systemctl enable iptables.service
   systemctl start iptables.service
   ```
7. **Logging Success/Failure**: Logs a success message if the service is enabled and started, otherwise logs an error message.

## Troubleshooting
### Common Issues
1. **iptables Rules Not Applied**:
   - Ensure the iptables rules are correctly saved in `/etc/iptables/rules.v4`.
   - Verify the script `/usr/local/bin/iptables.sh` is executable and correctly formatted.

2. **Service Fails to Start**:
   - Check the service status using `systemctl status iptables.service` for error messages.
   - Ensure the service file `/etc/systemd/system/iptables.service` is correctly formatted.

3. **Directory Issues**:
   - Verify the existence and permissions of the `/etc/iptables` directory.

## Best Practices
- **Regularly Review Firewall Rules**: Periodically review and update the firewall rules to ensure they meet current security requirements.
- **Monitor Logs**: Regularly review iptables logs to identify and address any potential security issues.
- **Test Configuration**: Test the iptables configuration in a staging environment before applying it to production systems.
- **Backup Rules**: Consider creating backups of the iptables rules before making changes.

Feel free to reach out if you encounter any issues or have any questions regarding the iptables configuration and service setup.
EOF
}

create_tor_readme() {
  mkdir -p "$KHELP_TOR_DIR"
  cat << 'EOF' > "$KHELP_TOR_DIR/README.md"
# Tor Configuration Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Configuring and Enabling Tor](#configuring-and-enabling-tor)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of configuring and enabling Tor, a software that enables anonymous communication, with a retry mechanism to handle potential installation issues.

## Function Explanation

### Configuring and Enabling Tor
1. **Logging**: Logs the start of the Tor configuration process with an informational log level.
2. **Retry Mechanism**: Attempts to install Tor up to three times in case of failures.
3. **Installation**: Uses `sudo apt install -y tor` to install Tor.
4. **Logging Success**: Logs a message indicating the successful installation of Tor.
5. **Logging Failure**: Logs an error message if the installation fails after the maximum attempts and exits with an error code.
6. **Enable and Start Tor Service**: Uses `sudo systemctl enable tor` and `sudo systemctl start tor` to enable and start the Tor service.
7. **Logging Service Success**: Logs a message indicating the successful configuration and enabling of the Tor service.
8. **Logging Service Failure**: Logs an error message if the Tor service fails to enable or start and exits with an error code.

## Example Usage
```bash
# Configure and enable Tor
configure_and_enable_tor
```

## Detailed Steps
### Configuring and Enabling Tor
1. **Initial Logging**: Logs the start of the Tor configuration process.
2. **Retry Mechanism**: Attempts to install Tor up to three times using:
   ```bash
   sudo apt install -y tor
   ```
3. **Logging Success/Failure**: Logs a success message if installation is successful, otherwise logs an error message after the maximum attempts.
4. **Enable and Start Tor Service**: Executes:
   ```bash
   sudo systemctl enable tor
   sudo systemctl start tor
   ```
5. **Logging Service Success/Failure**: Logs a success message if the Tor service is enabled and started, otherwise logs an error message.

## Troubleshooting
### Common Issues
1. **Installation Failures**:
   - Ensure the system has a stable internet connection.
   - Verify the package manager's repository URLs are accessible.

2. **Service Failures**:
   - Check the service status using `systemctl status tor` for error messages.
   - Ensure no conflicting services are running.

## Best Practices
- **Regularly Review Tor Configuration**: Periodically review and update the Tor configuration to ensure it meets current security requirements.
- **Monitor Logs**: Regularly review Tor logs to identify and address any potential security issues.
- **Test Configuration**: Test the Tor configuration in a staging environment before applying it to production systems.
- **Update Tor**: Keep Tor up-to-date to benefit from the latest security features and updates.

Feel free to reach out if you encounter any issues or have any questions regarding the Tor configuration.
EOF
}

create_default_terminal_readme() {
  mkdir -p "$KHELP_DEFAULT_TERMINAL_DIR"
  cat << 'EOF' > "$KHELP_DEFAULT_TERMINAL_DIR/README.md"
# Setting Terminator as Default Terminal Documentation

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Setting Terminator as Default Terminal for GNOME](#setting-terminator-as-default-terminal-for-gnome)
   - [Setting Terminator as Default Terminal for KDE Plasma](#setting-terminator-as-default-terminal-for-kde-plasma)
   - [Setting Terminator as Default Terminal for XFCE](#setting-terminator-as-default-terminal-for-xfce)
   - [Checking and Setting Default Terminal](#checking-and-setting-default-terminal)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of setting Terminator as the default terminal emulator for various desktop environments, including GNOME, KDE Plasma, and XFCE. The script includes functions to configure the default terminal and a function to check the current default terminal and update it if necessary.

## Function Explanation

### Setting Terminator as Default Terminal for GNOME
1. **Logging**: Logs the start of the process to set Terminator as the default terminal for GNOME.
2. **Set Default Terminal**: Uses `gsettings` to set Terminator as the default terminal.
3. **Logging Success**: Logs a message indicating the successful configuration of Terminator as the default terminal.
4. **Logging Failure**: Logs an error message if the configuration fails and exits with an error code.

### Setting Terminator as Default Terminal for KDE Plasma
1. **Logging**: Logs the start of the process to set Terminator as the default terminal for KDE Plasma.
2. **Set Default Terminal**: Uses `kwriteconfig5` to set Terminator as the default terminal.
3. **Logging Success**: Logs a message indicating the successful configuration of Terminator as the default terminal.
4. **Logging Failure**: Logs an error message if the configuration fails and exits with an error code.

### Setting Terminator as Default Terminal for XFCE
1. **Logging**: Logs the start of the process to set Terminator as the default terminal for XFCE.
2. **Set Default Terminal**: Uses `xfconf-query` to set Terminator as the default terminal.
3. **Logging Success**: Logs a message indicating the successful configuration of Terminator as the default terminal.
4. **Logging Failure**: Logs an error message if the configuration fails and exits with an error code.

### Checking and Setting Default Terminal
1. **Logging**: Logs the current default terminal.
2. **Check Current Terminal**: Checks the current default terminal for the detected desktop environment using appropriate commands (`gsettings`, `kreadconfig5`, or `xfconf-query`).
3. **Set Default Terminal**: If the current terminal is not Terminator, it calls the respective function to set Terminator as the default terminal.
4. **Unsupported Desktop Environment**: Logs an error message and exits if the desktop environment is unsupported.

## Example Usage
```bash
# Check and set Terminator as the default terminal
check_and_set_default_terminal
```

## Detailed Steps
### Setting Terminator as Default Terminal for GNOME
1. **Initial Logging**: Logs the start of the process:
   ```bash
   log $LOG_LEVEL_INFO "Setting Terminator as the default terminal for GNOME..."
   ```
2. **Set Default Terminal**: Executes:
   ```bash
   gsettings set org.gnome.desktop.default-applications.terminal exec terminator
   gsettings set org.gnome.desktop.default-applications.terminal exec-arg "-x"
   ```
3. **Logging Success/Failure**: Logs a success message if the commands are successful, otherwise logs an error message.

### Setting Terminator as Default Terminal for KDE Plasma
1. **Initial Logging**: Logs the start of the process:
   ```bash
   log $LOG_LEVEL_INFO "Setting Terminator as the default terminal for KDE Plasma..."
   ```
2. **Set Default Terminal**: Executes:
   ```bash
   kwriteconfig5 --file ~/.config/kdeglobals --group General --key TerminalApplication terminator
   ```
3. **Logging Success/Failure**: Logs a success message if the command is successful, otherwise logs an error message.

### Setting Terminator as Default Terminal for XFCE
1. **Initial Logging**: Logs the start of the process:
   ```bash
   log $LOG_LEVEL_INFO "Setting Terminator as the default terminal for XFCE..."
   ```
2. **Set Default Terminal**: Executes:
   ```bash
   xfconf-query -c xfce4-session -p /sessions/default/terminal -s terminator
   ```
3. **Logging Success/Failure**: Logs a success message if the command is successful, otherwise logs an error message.

### Checking and Setting Default Terminal
1. **Initial Logging**: Logs the current default terminal.
2. **Check Current Terminal**: Detects the desktop environment and checks the current default terminal using:
   - `gsettings` for GNOME
   - `kreadconfig5` for KDE Plasma
   - `xfconf-query` for XFCE
3. **Set Default Terminal**: If the current terminal is not Terminator, calls the respective function to set Terminator as the default terminal.
4. **Unsupported Desktop Environment**: Logs an error message and exits if the desktop environment is unsupported.

## Troubleshooting
### Common Issues
1. **Command Not Found**:
   - Ensure the desktop environment's configuration tool (`gsettings`, `kwriteconfig5`, or `xfconf-query`) is installed and available in the PATH.

2. **Permission Issues**:
   - Ensure the script has the necessary permissions to modify desktop environment settings.

3. **Unsupported Desktop Environment**:
   - Verify that the desktop environment is supported and that the appropriate commands are used.

## Best Practices
- **Test Configuration**: Test the configuration process in a staging environment before applying it to production systems.
- **Monitor Logs**: Regularly review logs to identify and address any potential issues.
- **Keep Terminator Updated**: Ensure Terminator is up-to-date to benefit from the latest features and bug fixes.

Feel free to reach out if you encounter any issues or have any questions regarding setting Terminator as the default terminal.
EOF
}

create_startup_verification_readme() {
  mkdir -p "$KHELP_STARTUP_VERIFICATION_DIR"
  cat << 'EOF' > "$KHELP_STARTUP_VERIFICATION_DIR/README.md"
# Startup Script and Desktop Entry Documentation for Verification

## Table of Contents
1. [Overview](#overview)
2. [Function Explanation](#function-explanation)
   - [Creating the Startup Script](#creating-the-startup-script)
   - [Creating the Desktop Entry](#creating-the-desktop-entry)
3. [Example Usage](#example-usage)
4. [Detailed Steps](#detailed-steps)
5. [Troubleshooting](#troubleshooting)
6. [Best Practices](#best-practices)

## Overview
This section documents the process of creating a startup script and a desktop entry to run the script at startup. The script ensures that specific services are active before executing additional commands.

## Function Explanation

### Creating the Startup Script
1. **Logging**: Logs the start of the process to create the startup script with an informational log level.
2. **Script Creation**: Creates a script at the specified `STARTUP_SCRIPT_PATH` with the following functionalities:
   - **Wait for Service**: A function `wait_for_service` waits until a specified service is active, retrying up to three times.
   - **Wait for Specific Services**: Waits for `ufw` and `tor` services to be active.
   - **Run Commands**: Runs commands to show system information and the status of the services.
3. **Make Script Executable**: Sets the script as executable.

### Creating the Desktop Entry
1. **Logging**: Logs the start of the process to create the desktop entry with an informational log level.
2. **Desktop Entry Creation**: Creates a desktop entry at the specified `DESKTOP_ENTRY_PATH` with the following properties:
   - **Type**: Set to `Application`.
   - **Exec**: Runs the startup script in a Terminator terminal.
   - **Autostart**: Enables the desktop entry to run at startup.
   - **Name and Comment**: Provides a name and comment for the desktop entry.
3. **Make Desktop Entry Executable**: Sets the desktop entry as executable.

## Example Usage
```bash
# Create and configure the startup script
create_startup_script

# Create and configure the desktop entry
create_desktop_entry
```

## Detailed Steps
### Creating the Startup Script
1. **Initial Logging**: Logs the start of the process:
   ```bash
   log $LOG_LEVEL_INFO "Creating the startup script..."
   ```
2. **Script Creation**: Creates a script at `STARTUP_SCRIPT_PATH` with the following content:
   ```bash
   #!/bin/bash

   wait_for_service() {
       local service="$1"
       local attempts=0
       local max_attempts=3
       while [ $attempts -lt $max_attempts ]; do
           systemctl is-active --quiet "$service" && return 0
           attempts=$((attempts + 1))
           sleep 5
       done
       return 1
   }

   log $LOG_LEVEL_INFO "Waiting for UFW service..."
   wait_for_service "ufw" || { log $LOG_LEVEL_ERROR "UFW service is not active. Exiting."; exit 1; }

   log $LOG_LEVEL_INFO "Waiting for Tor service..."
   wait_for_service "tor" || { log $LOG_LEVEL_ERROR "Tor service is not active. Exiting."; exit 1; }

   log $LOG_LEVEL_INFO "Showing system information and status of services..."
   uname -a
   systemctl status ufw
   systemctl status tor
   ```
3. **Make Script Executable**: Sets the script as executable:
   ```bash
   chmod +x "$STARTUP_SCRIPT_PATH"
   ```

### Creating the Desktop Entry
1. **Initial Logging**: Logs the start of the process:
   ```bash
   log $LOG_LEVEL_INFO "Creating the desktop entry..."
   ```
2. **Desktop Entry Creation**: Creates a desktop entry at `DESKTOP_ENTRY_PATH` with the following content:
   ```ini
   [Desktop Entry]
   Type=Application
   Exec=terminator -e "$STARTUP_SCRIPT_PATH"
   Hidden=false
   NoDisplay=false
   X-GNOME-Autostart-enabled=true
   Name[en_US]=Startup Script
   Comment[en_US]=Runs the startup script to check services and show system information
   ```
3. **Make Desktop Entry Executable**: Sets the desktop entry as executable:
   ```bash
   chmod +x "$DESKTOP_ENTRY_PATH"
   ```

## Troubleshooting
### Common Issues
1. **Script Not Executing**:
   - Ensure the script path is correct and the script is executable.
   - Check for any syntax errors in the script.

2. **Services Not Active**:
   - Verify that the `ufw` and `tor` services are installed and enabled.
   - Check the status of the services using `systemctl status ufw` and `systemctl status tor`.

3. **Desktop Entry Not Running**:
   - Ensure the desktop entry path is correct and the entry is executable.
   - Verify that the desktop environment supports autostart entries.

## Best Practices
- **Test Script and Entry**: Test the startup script and desktop entry in a staging environment before applying them to production systems.
- **Monitor Logs**: Regularly review logs to identify and address any potential issues.
- **Keep Services Updated**: Ensure the services (e.g., `ufw` and `tor`) are up-to-date to benefit from the latest features and security updates.

Feel free to reach out if you encounter any issues or have any questions regarding the startup script and desktop entry creation.
EOF
}

create_mspoo_readme() {
  mkdir -p "$MSPOO_DOC_DIR"
  cat << 'EOF' > "$MSPOO_DOC_FILE"
# MAC Spoofer Script 
MSPOO

## Description
This script changes the MAC address of all network interfaces (except loopback) to a randomly generated address. It includes advanced logging features, error handling, and ensures that network interfaces are correctly managed.

## Functions

### log(level, message, log_file)
Logs messages with a specified log level and rotates the log file if it exceeds 1MB. The log entries include detailed timestamps, script name, user, and hostname.

- **Parameters:**
  - `level`: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
  - `message`: The log message.
  - `log_file`: The log file path.

### generate_random_mac()
Generates a random MAC address with the prefix `02`.

- **Returns:** A randomly generated MAC address.

### validate_mac(mac)
Validates the format of a MAC address.

- **Parameters:**
  - `mac`: The MAC address to validate.
- **Returns:** `0` if the MAC address is valid, `1` otherwise.

### spoof_mac(interface)
Changes the MAC address of a specified network interface to a randomly generated address.

- **Parameters:**
  - `interface`: The network interface to spoof the MAC address for.
- **Returns:** `0` if successful, `1` otherwise.

### get_primary_interface()
Determines the primary network interface.

- **Returns:** The primary network interface.

### get_secondary_interface(primary_interface)
Gets the secondary network interfaces excluding the primary and loopback interfaces.

- **Parameters:**
  - `primary_interface`: The primary network interface.
- **Returns:** A list of secondary network interfaces.

### wait_for_interface(interface)
Ensures the network interface is up.

- **Parameters:**
  - `interface`: The network interface to check.
- **Returns:** `0` if the interface is up, `1` otherwise.

## Log File
Logs are saved to /var/log/khelp_mspoo.log. The log file is rotated if it exceeds 1MB. Log entries include detailed timestamps, log levels, script name, user, and hostname.

## Requirements
- The `ip` command must be available.
- The script must be run as root.

## Tasks Performed

1. **Environment Setup:**
   - Sets environment variables for log file paths.
   - Checks if the script is run as root.

2. **Logging Configuration:**
   - Configures advanced logging with log levels, log rotation, and detailed formatting.
   - Logs messages with different log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL).

3. **MAC Address Spoofing:**
   - Generates a random MAC address.
   - Validates the MAC address format.
   - Changes the MAC address of the primary and secondary network interfaces.
   - Ensures the network interfaces are correctly managed (brought down and up).

4. **Systemd Service Creation:**
   - Creates a systemd service unit file for MAC spoofing.
   - Enables and starts the systemd service.

5. **Documentation:**
   - Creates a detailed README.md file with information about the script, its functions, log file, requirements, and tasks performed.

## Notes
- The script includes error handling and logs errors and info messages.
- The script ensures that the generated MAC address format is valid.
- The script checks and manages the state of network interfaces during the MAC address change process.
EOF
}

create_hogen_readme() {
  mkdir -p "$HOGEN_DOC_DIR"
  cat << 'EOF' > "$HOGEN_DOC_FILE"
# Hostname Spoofer Script 
HOGEN

## Description
This script changes the system hostname to a randomly generated name fetched from the Random User Generator API.

## Functions

### log(level, message, log_file)
Logs messages with a specified log level and rotates the log file if it exceeds 1MB. The log entries include detailed timestamps, script name, user, and hostname.

- **Parameters:**
  - `level`: The log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
  - `message`: The log message.
  - `log_file`: The log file path.

### fetch_random_name()
Fetches a random name from the Random User Generator API.

- **Returns:** A randomly fetched name.

### update_hosts_file(entry)
Ensures the entry is present in the /etc/hosts file.

- **Parameters:**
  - `entry`: The entry to add to /etc/hosts.

## Log File
Logs are saved to /var/log/khelp_hogen.log. The log file is rotated if it exceeds 1MB. Log entries include detailed timestamps, log levels, script name, user, and hostname.

## Requirements
- The `curl` and `jq` commands must be available.
- The script must be run as root.

## Tasks Performed

1. **Environment Setup:**
   - Sets environment variables for log file paths.
   - Checks if the script is run as root.

2. **Logging Configuration:**
   - Configures advanced logging with log levels, log rotation, and detailed formatting.
   - Logs messages with different log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL).

3. **Hostname Generation:**
   - Fetches a random name from the Random User Generator API.
   - Validates the API response and ensures the hostname is set correctly.
   - Ensures /etc/hosts is updated with the correct entries.

4. **Systemd Service Creation:**
   - Creates a systemd service unit file for hostname generation.
   - Enables and starts the systemd service.

5. **Documentation:**
   - Creates a detailed README.md file with information about the script, its functions, log file, requirements, and tasks performed.

## Notes
- The script includes error handling and logs errors and info messages.
- The script ensures that the generated hostname is set correctly and /etc/hosts is updated appropriately.
EOF
}

# Function to create README.md for Snort
create_snort_readme() {
  mkdir -p "$SNORT_DOC_DIR"
  cat << EOF > "$SNORT_DOC_FILE"
# Snort Configuration Documentation

## Table of Contents
1. [Overview](#overview)
2. [Modes of Operation](#modes-of-operation)
3. [Configuration Steps](#configuration-steps)
4. [Environment Variables](#environment-variables)
5. [Conclusion](#conclusion)

## Overview
Snort is an open-source Intrusion Detection and Prevention System (IDPS) developed by Cisco. 
It is used to monitor network traffic in real-time, analyzing packets for signs of malicious activity, policy violations, or other threats. 
Snort can operate in three main modes:

## Modes of Operation
1. **Sniffer Mode**: Captures and displays network packets in real-time.
2. **Packet Logger Mode**: Logs packets to disk for later analysis.
3. **Network Intrusion Detection System (NIDS) Mode**: Analyzes network traffic against a set of rules to detect suspicious activity.

## Configuration Steps
1. **Installation**: Install Snort using the package manager or by compiling from source.
   ```bash
   sudo apt-get update
   sudo apt-get install -y snort
   ```
2. **Configuration File**: Edit the Snort configuration file located at `/etc/snort/snort.conf` to set up network variables, 
     rules paths, and output plugins.
   - Set network variables (e.g., HOME_NET, EXTERNAL_NET).
   - Define the rule paths and include the necessary rule files.
   - Configure output plugins for logging and alerting.

3. **Rules Management**: Download and manage Snort rules from sources like the Snort community rules, Emerging Threats, or other rule providers.
   ```bash
   wget https://www.snort.org/rules/community -O /etc/snort/rules/community.rules
   ```
   - Ensure the downloaded rules are referenced in the Snort configuration file.

4. **Testing Configuration**: Test the Snort configuration to ensure there are no errors.
   ```bash
   sudo snort -T -c /etc/snort/snort.conf
   ```

5. **Running Snort**: Start Snort in the desired mode.
   - Sniffer Mode:
     ```bash
     sudo snort -v
     ```
   - Packet Logger Mode:
     ```bash
     sudo snort -dev -l /var/log/snort
     ```
   - NIDS Mode:
     ```bash
     sudo snort -c /etc/snort/snort.conf -i eth0
     ```

## Environment Variables
- **HOME_NET**: Specifies the internal network range that Snort will monitor.
- **EXTERNAL_NET**: Defines the external network range (usually set to any).
- **RULE_PATH**: Path to the directory containing Snort rules.

## Conclusion
This documentation provides an overview of the Snort configuration steps and the associated environment variables. 
By following these steps, you can ensure that Snort is properly integrated into your network security setup, 
providing real-time intrusion detection alongside UFW, iptables, and Fail2ban.
EOF
}

# Run both functions in parallel
create_default_terminal_readme &
create_startup_verification_readme &
create_logging_readme &
create_update_readme &
create_installer_readme &
create_proxychains_readme &
create_ufw_readme &
create_fail2ban_readme &
create_iptables_readme &
create_tor_readme &
create_mspoo_readme &
create_hogen_readme &
create_snort_readme &

# Wait for all background processes to finish
wait

log $LOG_LEVEL_INFO "All README.md files have been created." "$UPDATE_LOG_FILE"

# Call the display_logo function
display_logo

# Reboot the system to apply changes
log $LOG_LEVEL_INFO "Rebooting the system to apply changes in 1 minute..." "$UPDATE_LOG_FILE"
shutdown -r +1

read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    log $LOG_LEVEL_INFO "Cancelling the reboot..." "$UPDATE_LOG_FILE"
    shutdown -c
else
    log $LOG_LEVEL_INFO "Reboot will proceed in 1 minute." "$UPDATE_LOG_FILE"
fi