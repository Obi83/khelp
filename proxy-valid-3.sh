#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Set USER_HOME based on whether the script is run with sudo or not
if [ -n "$SUDO_USER" ]; then
    export USER_HOME=$(eval echo ~${SUDO_USER})
else
    export USER_HOME=$HOME
fi

# Log Files
export UPDATE_LOG_FILE="/var/log/khelp.log"
export PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"

# Textfiles
export PROXY_LIST_FILE="/etc/proxychains/fetched_proxies.txt"

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

create_update_proxies_script() {
    log $LOG_LEVEL_INFO "Creating update_proxies script..." "$UPDATE_LOG_FILE"
    cat << 'EOF' > /usr/local/bin/update_proxies.sh
#!/bin/bash

LOG_LEVEL_INFO=0
LOG_LEVEL_ERROR=1
UPDATE_LOG_FILE="/var/log/khelp.log"
PROXY_UPDATE_LOG_FILE="/var/log/update_proxies.log"
PROXY_API_URL1="https://spys.me/socks.txt"
PROXY_API_URL2="https://www.proxy-list.download/api/v1/get?type=socks5"
PROXY_API_URL3="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"
temp_proxy_list_file1="/tmp/temp_proxies1.txt"
temp_proxy_list_file2="/tmp/temp_proxies2.txt"

log() {
    local level=$1
    local message=$2
    local logfile=$3
    echo "$(date +"%Y-%m-%d %H:%M:%S") [LEVEL $level] $message" >> "$logfile"
}

fetch_proxies_with_fallback() {
  local proxy_list_file="/etc/proxychains/fetched_proxies.txt"
  local valid_proxies=()

  mkdir -p "$(dirname "$proxy_list_file")"
  touch "$temp_proxy_list_file1" "$temp_proxy_list_file2"

  if [ ! -w "$temp_proxy_list_file1" ] || [ ! -w "$temp_proxy_list_file2" ]; then
    log $LOG_LEVEL_ERROR "Cannot write to temporary proxy list files." "$PROXY_UPDATE_LOG_FILE"
    return 1
  fi

  # Function to validate proxies
  validate_proxies() {
    local proxy_list=$1
    local temp_file=$2
    while IFS= read -r proxy; do
      original_ip=$(curl -s https://api.ipify.org)
      proxy_ip=$(curl -x "socks5://$proxy" -s https://api.ipify.org)
      if [ "$original_ip" != "$proxy_ip" ]; then
        echo "$proxy" >> "$temp_file"
      else
        log $LOG_LEVEL_INFO "Proxy $proxy is not anonymous (original IP: $original_ip, proxy IP: $proxy_ip)" "$PROXY_UPDATE_LOG_FILE"
      fi
    done <<< "$proxy_list"
  }

  # Fetch proxies from the first API
  log $LOG_LEVEL_INFO "Fetching new proxy list from $PROXY_API_URL1..." "$PROXY_UPDATE_LOG_FILE"
  local response=$(curl -s $PROXY_API_URL1)
  if [ -z "$response" ]; then
    log $LOG_LEVEL_ERROR "Failed to fetch proxies from $PROXY_API_URL1 or the response is empty." "$PROXY_UPDATE_LOG_FILE"
  else
    local valid_proxies_from_api1=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
    if [ -z "$valid_proxies_from_api1" ]; then
      log $LOG_LEVEL_ERROR "No valid proxies found in the response from $PROXY_API_URL1." "$PROXY_UPDATE_LOG_FILE"
    else
      validate_proxies "$valid_proxies_from_api1" "$temp_proxy_list_file1"
      log $LOG_LEVEL_INFO "Fetched and validated $(cat "$temp_proxy_list_file1" | wc -l) valid proxies from the first API." "$PROXY_UPDATE_LOG_FILE"
    fi
  fi

  # Fetch proxies from the second API
  log $LOG_LEVEL_INFO "Fetching new proxy list from $PROXY_API_URL2..." "$PROXY_UPDATE_LOG_FILE"
  local response=$(curl -s $PROXY_API_URL2)
  if [ -z "$response" ]; then
    log $LOG_LEVEL_ERROR "Failed to fetch proxies from $PROXY_API_URL2 or the response is empty." "$PROXY_UPDATE_LOG_FILE"
  else
    local valid_proxies_from_api2=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
    if [ -z "$valid_proxies_from_api2" ]; then
      log $LOG_LEVEL_ERROR "No valid proxies found in the response from $PROXY_API_URL2." "$PROXY_UPDATE_LOG_FILE"
    else
      validate_proxies "$valid_proxies_from_api2" "$temp_proxy_list_file2"
      log $LOG_LEVEL_INFO "Fetched and validated $(cat "$temp_proxy_list_file2" | wc -l) valid proxies from the second API." "$PROXY_UPDATE_LOG_FILE"
    fi
  fi

  # Combine and shuffle proxies
  if [ -s "$temp_proxy_list_file1" ] || [ -s "$temp_proxy_list_file2" ]; then
    cat "$temp_proxy_list_file1" "$temp_proxy_list_file2" | shuf > "$proxy_list_file"
    if [ $? -ne 0 ]; then
      log $LOG_LEVEL_ERROR "Failed to write combined proxies to $proxy_list_file" "$PROXY_UPDATE_LOG_FILE"
    else
      log $LOG_LEVEL_INFO "Combined and shuffled proxies." "$PROXY_UPDATE_LOG_FILE"
      log $LOG_LEVEL_INFO "Final proxy count: $(cat "$proxy_list_file" | wc -l)" "$PROXY_UPDATE_LOG_FILE"
    fi
  else
    log $LOG_LEVEL_ERROR "No valid proxies found to combine and shuffle." "$PROXY_UPDATE_LOG_FILE"
  fi

  # Cleanup temporary files
  rm -f "$temp_proxy_list_file1" "$temp_proxy_list_file2"

  # Fallback to the third API if the proxy list is empty
  if [ ! -s "$proxy_list_file" ]; then
    log $LOG_LEVEL_INFO "Fallback: Fetching new proxy list from $PROXY_API_URL3..." "$PROXY_UPDATE_LOG_FILE"
    local response=$(curl -s $PROXY_API_URL3)
    if [ -z "$response" ]; then
      log $LOG_LEVEL_ERROR "Failed to fetch proxies from $PROXY_API_URL3 or the response is empty." "$PROXY_UPDATE_LOG_FILE"
    else
      local valid_proxies=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
      if [ -z "$valid_proxies" ]; then
        log $LOG_LEVEL_ERROR "No valid proxies found in the response from $PROXY_API_URL3." "$PROXY_UPDATE_LOG_FILE"
      else
        validate_proxies "$valid_proxies" "$proxy_list_file"
        log $LOG_LEVEL_INFO "Fetched and validated $(cat "$proxy_list_file" | wc -l) valid proxies from the fallback API." "$PROXY_UPDATE_LOG_FILE"
      fi
    fi
  fi

  if [ ! -s "$proxy_list_file" ]; then
    log $LOG_LEVEL_ERROR "Failed to fetch proxies after attempting all APIs. Continuing without updated proxies." "$PROXY_UPDATE_LOG_FILE"
    return 1
  fi
}

# Fetch and update proxy list
fetch_proxies_with_fallback

log $LOG_LEVEL_INFO "update_proxies script executed successfully." "$PROXY_UPDATE_LOG_FILE"
EOF
    chmod +x /usr/local/bin/update_proxies.sh
    log $LOG_LEVEL_INFO "update_proxies script created successfully." "$UPDATE_LOG_FILE"
}

# Create the update_proxies.sh script
create_update_proxies_script

log $LOG_LEVEL_INFO "update_proxies script executed successfully." "$PROXY_UPDATE_LOG_FILE"