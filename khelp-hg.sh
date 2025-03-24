#!/bin/bash
# Function to fetch a random name from the Random User Generator API
fetch_random_name() {
    local api_url="https://randomuser.me/api/"
    local response=$(curl -s $api_url)
    local first_name=$(echo $response | jq -r '.results[0].name.first')
    local last_name=$(echo $response | jq -r '.results[0].name.last')
    local name="${first_name}${last_name}"

    # Capitalize the first letter of the first name and last name
    name="$(tr '[:lower:]' '[:upper:]' <<< ${name:0:1})${name:1}"
    echo $name
}

newhn=$(fetch_random_name)
hostnamectl set-hostname $newhn

# Update /etc/hosts
cat << EOF > /etc/hosts
127.0.0.1    localhost
127.0.0.1    $newhn
EOF