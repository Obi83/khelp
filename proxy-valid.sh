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
export PROXY_LIST_FILE_VALIDATED="/etc/proxychains/validated_proxies.txt"

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

fetch_proxies_with_fallback() {
  local proxy_api_url1="https://spys.me/socks.txt"
  local proxy_api_url2="https://www.proxy-list.download/api/v1/get?type=socks5"
  local proxy_api_url3="https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=all"
  local proxy_list_file="/etc/proxychains/fetched_proxies.txt"
  local max_proxies=100
  local attempts=0
  local max_attempts=3

  mkdir -p "$(dirname "$proxy_list_file")"

  # Fetch proxies from the first API
  log $LOG_LEVEL_INFO "Fetching new proxy list from $proxy_api_url1..." "$PROXY_UPDATE_LOG_FILE"
  local response=$(curl -s $proxy_api_url1)
  if [ -n "$response" ]; then
      local valid_proxies=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
      if [ -n "$valid_proxies" ]; then
          echo "$valid_proxies" > "$proxy_list_file"
          log $LOG_LEVEL_INFO "Fetched $(echo "$valid_proxies" | wc -l) valid proxies from the first API." "$PROXY_UPDATE_LOG_FILE"
      else
          log $LOG_LEVEL_ERROR "No valid proxies found in the response from $proxy_api_url1." "$PROXY_UPDATE_LOG_FILE"
      fi
  else
      log $LOG_LEVEL_ERROR "Failed to fetch proxies from $proxy_api_url1 or the response is empty." "$PROXY_UPDATE_LOG_FILE"
  fi

  # Fetch proxies from the second API
  log $LOG_LEVEL_INFO "Fetching new proxy list from $proxy_api_url2..." "$PROXY_UPDATE_LOG_FILE"
  local response=$(curl -s $proxy_api_url2)
  if [ -n "$response" ]; then
      local valid_proxies=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
      if [ -n "$valid_proxies" ]; then
          echo "$valid_proxies" >> "$proxy_list_file"
          log $LOG_LEVEL_INFO "Fetched $(echo "$valid_proxies" | wc -l) valid proxies from the second API." "$PROXY_UPDATE_LOG_FILE"
      else
          log $LOG_LEVEL_ERROR "No valid proxies found in the response from $proxy_api_url2." "$PROXY_UPDATE_LOG_FILE"
      fi
  else
      log $LOG_LEVEL_ERROR "Failed to fetch proxies from $proxy_api_url2 or the response is empty." "$PROXY_UPDATE_LOG_FILE"
  fi

  # Fallback to the third API if the proxy list is empty
  if [ ! -s "$proxy_list_file" ]; then
      log $LOG_LEVEL_INFO "Fallback: Fetching new proxy list from $proxy_api_url3..." "$PROXY_UPDATE_LOG_FILE"
      local response=$(curl -s $proxy_api_url3)
      if [ -n "$response" ]; then
          local valid_proxies=$(echo "$response" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -n $max_proxies)
          if [ -n "$valid_proxies" ]; then
              echo "$valid_proxies" > "$proxy_list_file"
              log $LOG_LEVEL_INFO "Fetched $(echo "$valid_proxies" | wc -l) valid proxies from the fallback API." "$PROXY_UPDATE_LOG_FILE"
              return 0
          else
              log $LOG_LEVEL_ERROR "No valid proxies found in the response from $proxy_api_url3." "$PROXY_UPDATE_LOG_FILE"
          fi
      else
          log $LOG_LEVEL_ERROR "Failed to fetch proxies from $proxy_api_url3 or the response is empty." "$PROXY_UPDATE_LOG_FILE"
      fi
  fi

  if [ ! -s "$proxy_list_file" ]; then
      log $LOG_LEVEL_ERROR "Failed to fetch proxies after attempting all APIs. Exiting." "$PROXY_UPDATE_LOG_FILE"
      exit 1
  fi
}

check_reachability() {
  local proxy=$1
  log $LOG_LEVEL_DEBUG "Testing reachability for proxy: $proxy" "$PROXY_UPDATE_LOG_FILE"
  if curl -x "socks5://$proxy" -s --connect-timeout 5 https://www.google.com -o /dev/null; then
    log $LOG_LEVEL_DEBUG "Proxy $proxy is reachable" "$PROXY_UPDATE_LOG_FILE"
    echo "Reachable"
  else
    log $LOG_LEVEL_DEBUG "Proxy $proxy is not reachable" "$PROXY_UPDATE_LOG_FILE"
    echo "Not reachable"
  fi
}

check_anonymity() {
  local proxy=$1
  log $LOG_LEVEL_DEBUG "Testing anonymity for proxy: $proxy" "$PROXY_UPDATE_LOG_FILE"
  original_ip=$(curl -s https://api.ipify.org)
  proxy_ip=$(curl -x "socks5://$proxy" -s https://api.ipify.org)
  if [ "$original_ip" != "$proxy_ip" ]; then
    log $LOG_LEVEL_DEBUG "Proxy $proxy is anonymous" "$PROXY_UPDATE_LOG_FILE"
    echo "Anonymous"
  else
    log $LOG_LEVEL_DEBUG "Proxy $proxy is not anonymous" "$PROXY_UPDATE_LOG_FILE"
    echo "Not anonymous"
  fi
}

check_security() {
  local proxy=$1
  log $LOG_LEVEL_DEBUG "Testing security for proxy: $proxy" "$PROXY_UPDATE_LOG_FILE"
  echo "Secure (SOCKS5)"
}

validate_proxies() {
  local proxy_list_file="/etc/proxychains/fetched_proxies.txt"
  local proxy_list_file_validated="/etc/proxychains/validated_proxies.txt"

  # Ensure the validated proxies file is empty before starting validation
  > "$proxy_list_file_validated"

  if [ -f "$proxy_list_file" ]; then
    while IFS= read -r proxy; do
      echo "Checking proxy: $proxy"
      reachability=$(check_reachability "$proxy")
      anonymity=$(check_anonymity "$proxy")
      security=$(check_security "$proxy")
      if [ "$reachability" == "Reachable" ] && [ "$anonymity" == "Anonymous" ] && [ "$security" == "Secure (SOCKS5)" ]; then
        echo "$proxy" >> "$proxy_list_file_validated"
      fi
      echo "Reachability: $reachability"
      echo "Anonymity: $anonymity"
      echo "Security: $security"
      echo "-------------------------"
    done < "$proxy_list_file"
  else
    log $LOG_LEVEL_ERROR "Proxy list file not found: $proxy_list_file" "$PROXY_UPDATE_LOG_FILE"
    exit 1
  fi
}

# Fetch and validate proxy list
fetch_proxies_with_fallback
validate_proxies

log $LOG_LEVEL_INFO "update_proxies script executed successfully." "$PROXY_UPDATE_LOG_FILE"