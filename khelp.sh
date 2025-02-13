#!/bin/bash
echo "#############################################"
echo "#############################################"
echo ""
# Function to display a logo
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

# Display the Logo
display_logo
echo "#############################################"
echo "#######*Author of the Script is Obi83*#######"
echo ""
echo "Starting the khelp script for Kali!"
echo ""

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

echo "Let's start with a standard task to make the system fresh and clean!"
echo "Also khelp will install a few useful helper plus the kali-tweaks large-package."
echo ""

# Update & cleanup
echo "Updating system"
apt update && apt-get upgrade -y && apt autoremove -y && apt autoclean
echo ""

# Install helper packages
apt install -y kali-linux-large kali-tools-windows-resources terminator bpytop htop shellcheck seclists inxi ufw tor fastfetch guake 

# Function to download kalitorify
download_kalitorify() {
    echo "Downloading kalitorify..."
    user_home=$(eval echo ~${SUDO_USER})
    if [ -z "$user_home" ]; then
        echo "Could not determine the home directory of the user."
        exit 1
    fi
    git clone https://github.com/brainfucksec/kalitorify.git "$user_home/kalitorify"
    echo "kalitorify has been downloaded to $user_home/kalitorify."
}

# Download kalitorify
download_kalitorify

echo "khelp will create now: hogen - hostname generator service."
echo ""

# Create the hogen.sh file with hostname change code
echo "create: /usr/local/bin/hogen.sh"
cat << 'EOF' > /usr/local/bin/hogen.sh
#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Syllables
syllables=("la" "na" "se" "xa" "zu" "fo" "ra" "gi" "ja" "bo" "pi" "ke" "se" "ro" "mo" "me" "li" "jo" "lo" "mi" "pa" "ku" "te" "pa" "fo" "vo" "lu" "vo" "wo" "ta" "si" "pe" "ne" "mu" "so" "ma" "na" "ri" "la" "ga" "ja" "fi" "ba" "gu" "ka" "lo" "la" "po" "me" "sa" "va" "xe" "zu" "du" "ke" "ji" "xe" "ne" "nu" "be" "ni" "to" "ru" "su" "no" "la" "me" "na" "ra" "za" "xi" "po" "mi" "ha" "ne" "tu" "lo" "ka" "ta" "ni" "me" "jo" "ta" "re" "mi" "to" "na" "ya" "wa" "nu" "na" "ka" "ra" "pa" "ji" "nu" "fe" "lo" "ja" "ma" "jo" "su" "bo" "me" "re" "ke" "ti" "xu" "bo" "le" "pa" "da" "ku" "ki" "la" "so" "ve" "ba" "me" "zo" "ro" "lo" "je" "si" "mi" "pe" "na" "ga" "vo" "mu" "pa" "la" "sa" "me" "pi" "ho" "la" "mo" "te" "ma" "le" "bi" "jo" "re" "nu" "wi" "pa" "je" "mo" "ne" "la" "ma" "ra" "ru" "wi" "bu" "na" "lo" "ne" "me" "xi" "ko" "fi" "lu" "ji" "do" "ri" "we" "po" "pe" "wa" "ku" "ka" "hi" "yo" "ri" "ji" "ju" "ra" "po" "mo" "lo" "ma" "ko" "le" "ti" "me" "li" "to" "du" "la" "ne" "ka" "ga" "je" "be" "ri" "lo" "mi" "ti" "tu" "ku" "ri" "gi" "sa" "se" "la" "jo" "me" "sa" "pa" "ka" "to" "ta" "ru" "su" "la" "ne" "zi" "go" "po" "wa" "pu" "ka" "vo" "sa" "do" "me" "ki" "su" "me" "jo" "ro" "le" "pa" "me" "no" "ji" "le" "ho" "me" "su" "na" "la" "pa" "we" "le" "ne" "mi" "ku" "mo" "no" "ka" "mo" "me" "wo" "no" "ja" "ki" "ru" "lo" "po" "me" "te" "ri" "ha" "ra" "mi" "ma" "ba" "to" "me" "ja" "le" "mo" "mu" "la" "pa" "te" "la" "ro" "wa" "ze" "bi" "ke" "na" "le" "me" "mo" "ru" "ne" "la" "po" "me" "le" "bu" "lo" "sa" "xi" "me" "la" "ga" "so" "ru" "me" "pa" "sa" "wa" "me" "lo" "ka" "no" "we" "po" "zi" "ha" "re" "da" "me" "ne" "jo" "po" "ja" "ra" "la" "za" "ga" "le" "me" "ka" "no" "me" "la" "je" "me" "la" "na" "po" "so" "ro" "la" "mi" "na" "me" "ka" "le" "jo" "ne" "xi" "me" "le" "la" "nu" "so" "lo" "je" "ra" "me" "pa" "sa" "me" "la" "me" "ne" "la" "me" "pa" "me" "pa" "le" "we" "pa" "lo" "sa" "le" "lo")

# Random name
name=""
while [ ${#name} -lt 8 ]; do
    name="${name}${syllables[RANDOM % ${#syllables[@]}]}"
done

# Make it exactly 8 characters
name=${name:0:8}

# Capitalize letters
name="$(tr '[:lower:]' '[:upper:]' <<< ${name:0:1})${name:1:1}$(tr '[:lower:]' '[:upper:]' <<< ${name:2:1})${name:3}"

# New hostname
newhn=$name
hostnamectl set-hostname $newhn

# Update /etc/hosts
echo "127.0.0.1    localhost" > /etc/hosts
echo "127.0.0.1    $newhn" >> /etc/hosts

exit
EOF

# Make the hogen.sh file executable
chmod +x /usr/local/bin/hogen.sh

echo "create: /etc/systemd/system/hogen.service"
echo ""
# Create the hogen.service file with systemd unit configuration
cat << 'EOF' > /etc/systemd/system/hogen.service
[Unit]
Description=HOGEN Hostname Generator
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/hogen.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Set the correct permissions for the service file
chmod +x /etc/systemd/system/hogen.service

# Reload systemd to recognize the new service, enable it, and start it
systemctl daemon-reload
systemctl enable hogen.service

echo "khelp will now create: mspoo - mac spoofy service"
echo ""

# Create the mspoo.sh file with macspoof code
echo "create: the bash script: /usr/local/bin/mspoo.sh"
cat << 'EOF' > /usr/local/bin/mspoo.sh
#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Make sure that 'ip' command is available
if ! command -v ip &> /dev/null; then
    echo "'ip' command not found. Please install it and try again."
    exit 1
fi

# Determine primary network interface
get_primary_interface() {
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
    
    if [ -z "$INTERFACE" ]; then
        echo "No network interface found."
        exit 1
    fi
}

# Generate random MAC address
generate_random_mac() {
    echo -n "02" # Locally administered address (LAA) and unicast address
    for i in {1..5}; do
        printf ":%02x" $((RANDOM % 256))
    done
    echo # Ensure a newline at the end
}

# Spoof MAC address
spoof_mac() {
    # Get the primary network interface
    get_primary_interface

    # Generate a random MAC address
    NEW_MAC=$(generate_random_mac)

    echo "Spoofing MAC address for interface $INTERFACE with new MAC: $NEW_MAC"

    # Bring the network interface down
    if ! ip link set dev $INTERFACE down; then
        echo "Failed to bring down the network interface."
        exit 1
    fi

    # Change the MAC address
    if ! ip link set dev $INTERFACE address $NEW_MAC; then
        echo "Failed to change the MAC address."
        exit 1
    fi

    # Bring the network interface back up
    if ! ip link set dev $INTERFACE up; then
        echo "Failed to bring up the network interface."
        exit 1
    fi

    # Display the new MAC address
    ip link show $INTERFACE | grep ether
}

# Execute
spoof_mac
EOF

# Make the mspoo.sh file executable
chmod +x /usr/local/bin/mspoo.sh

echo "create: /etc/systemd/system/mspoo.service"
echo ""
# Create the mspoo.service file with systemd unit configuration
cat << 'EOF' > /etc/systemd/system/mspoo.service
[Unit]
Description=MSPOO MACSpoofing Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mspoo.sh
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Set permissions for the service file
chmod +x /etc/systemd/system/mspoo.service

# Enable the new service and start it
systemctl daemon-reload
systemctl enable mspoo.service
echo ""
echo ""
echo "systeme is fresh and clean!"
echo "tools and packages are installed."
echo "hogen spoofing service has been installed and enabled."
echo "mspoo spoofing service has been installed and enabled."
echo "kalitorify has been downloaded to $user_home/kalitorify."
echo ""
echo ""
echo "##*khelp*##+##*khelp*##"
echo "##*khelp*##+##*khelp*##"
echo ""

# Function to display a logo
display_logo() {
    cat << "EOF"
 _    _          _       
| | _| |__   ___| |_ __  
| |/ / '_ \ / _ \ | '_ \ 
|   <| | | |  __/ | |_) |
|_|\_\_| |_|\___|_| .__/ 
                  |_|    
EOF
}

# Display the Logo
display_logo
echo ""
echo "##*khelp*##+##*khelp*##"
echo "##*khelp*##+##*khelp*##"
echo ""
echo ""

# Reboot the system
echo "Rebooting the system to apply changes in 1 minute..."
shutdown -r +1

# Ask the user if they want to cancel the reboot
read -p "Press 'c' to cancel the reboot or any other key to continue: " user_input

if [ "$user_input" = "c" ]; then
    echo "Cancelling the reboot..."
    shutdown -c
else
    echo "Reboot will proceed in 1 minute."
fi
