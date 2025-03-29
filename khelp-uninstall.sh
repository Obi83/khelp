#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Define log function
log() {
    local level="$1"
    local message="$2"
    echo "[$level] $message"
}

# Ensure USER_HOME is set
if [ -n "$SUDO_USER" ]; then
    USER_HOME=$(eval echo ~${SUDO_USER})
else
    USER_HOME=$HOME
fi

# Stop and disable services
log "INFO" "Stopping and disabling services..."
systemctl stop ufw
systemctl disable ufw
systemctl stop fail2ban
systemctl disable fail2ban
systemctl stop snort
systemctl disable snort
systemctl stop hogen
systemctl disable hogen
systemctl stop mspoo
systemctl disable mspoo
systemctl stop iptables
systemctl disable iptables
systemctl stop update_proxies
systemctl disable update_proxies

# Remove service files
log "INFO" "Removing service files..."
rm -f /etc/systemd/system/ufw.service
rm -f /etc/systemd/system/fail2ban.service
rm -f /etc/systemd/system/snort.service
rm -f /etc/systemd/system/hogen.service
rm -f /etc/systemd/system/mspoo.service
rm -f /etc/systemd/system/iptables.service
rm -f /etc/systemd/system/update_proxies.service
rm -f /etc/systemd/system/update_proxies.timer

# Reload systemd daemon
systemctl daemon-reload

# Remove configuration files and directories
log "INFO" "Removing configuration files and directories..."
rm -rf /usr/local/share/khelp_update
rm -rf /usr/local/share/khelp_installer
rm -rf /usr/local/share/khelp_ufw
rm -rf /usr/local/share/khelp_fail2ban
rm -rf /usr/local/share/khelp_iptables
rm -rf /usr/local/share/khelp_tor
rm -rf /usr/local/share/khelp_terminator
rm -rf /usr/local/share/khelp_verify
rm -rf /usr/local/share/khelp_hogen
rm -rf /usr/local/share/khelp_mspoof
rm -rf /usr/local/share/khelp_snort
rm -f /usr/local/bin/ufw.sh
rm -f /usr/local/bin/iptables.sh
rm -f /usr/local/bin/hogen.sh
rm -f /usr/local/bin/mspoo.sh
rm -f /usr/local/bin/update_proxies.sh
rm -f /etc/proxychains.conf
rm -f /etc/fail2ban/jail.local
rm -rf /etc/snort
rm -rf /var/log/snort

# Remove log files
log "INFO" "Removing log files..."
rm -f /var/log/khelp.log
rm -f /var/log/khelp_hogen.log
rm -f /var/log/khelp_mspoo.log

# Remove desktop entry
log "INFO" "Removing desktop entry..."
rm -f "$USER_HOME/.config/autostart/startup_terminal.desktop"

# Uninstall packages
log "INFO" "Uninstalling packages..."
apt remove --purge -y ufw tor fail2ban snort terminator proxychains
apt autoremove -y
apt autoclean

# Flush iptables rules
log "INFO" "Flushing iptables rules..."
iptables -F
iptables -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

log "INFO" "Uninstallation completed."