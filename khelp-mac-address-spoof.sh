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

# Environment variables for paths and configurations
export USER_HOME=$(eval echo ~${SUDO_USER})

# Debugging: Print environment variables after validation
echo "USER_HOME=$USER_HOME"

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

# Summary and Reboot
log "System is fresh and clean!"
log "khelp configured standard ufw, iptables, fail2ban and sshl"
log "Network setup with tor and proxchains is complete."
log "Script will fetch proxy lists from 6 APIs."
log "mac address spoof is written and enabled!"

log "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

log "Reboot will proceed in 1 minute."
