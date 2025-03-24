#!/bin/bash

# Ensure curl and jq are installed
if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null
then
    echo "curl and jq are required but not installed. Please install them."
    exit 1
fi

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
hostnamectl set-hostname $newhn

# Update /etc/hosts
cat << EOF >> /etc/hosts
127.0.0.1    $newhn
EOF