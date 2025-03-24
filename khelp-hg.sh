#!/bin/bash

# Ensure curl and jq are installed
if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null
then
    echo "curl and jq are required but not installed. Please install them."
    exit 1
fi

# Create and enable hostname generator service
echo "Creating and enabling hostname generator service..."

cat << 'EOF' > /usr/local/bin/hogen.sh
#!/bin/bash

# Function to fetch a random name from the Random User Generator API
fetch_random_name() {
    local api_url="https://randomuser.me/api/"
    local response=$(curl -s $api_url)
    local first_name=$(echo $response | jq -r '.results[0].name.first')
    local last_name=$(echo $response | jq -r '.results[0].name.last')
    local name="${first_name}${last_name}"

    # Capitalize the first letter of the first name and last name
    name=$(echo $name | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    echo $name
}

newhn=$(fetch_random_name)
hostnamectl set-hostname "$newhn"

# Ensure /etc/hosts has the correct entries
grep -q "127.0.0.1    localhost" /etc/hosts || echo "127.0.0.1    localhost" >> /etc/hosts
grep -q "127.0.0.1    $newhn" /etc/hosts || echo "127.0.0.1    $newhn" >> /etc/hosts

echo "Hostname set to $newhn and /etc/hosts updated"
EOF

chmod +x /usr/local/bin/hogen.sh

cat << EOF > /etc/systemd/system/hogen.service
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

chmod +x /etc/systemd/system/hogen.service
systemctl daemon-reload
systemctl enable hogen.service
systemctl start hogen.service