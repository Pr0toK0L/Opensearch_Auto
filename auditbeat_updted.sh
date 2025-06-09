#!/bin/bash

# Menu options:
# -i : install
# -v : version
# -l : latest version
# -a : automated config

AUDITBEAT_VERSION=""
INSTALL=false
AUTOMATED_CONFIG=false
INSTALL_LATEST=false
START=false

validate_version() {
    local version=$1
    
    if ! [[$version =~ ^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
        echo "Error: Version must be in format x.x.x where x is a number from 0-99"
        show_help
        exit 1
    fi

    IFS='.' read -r -a version_parts <<< "$version"
    for part in "${version_parts[@]}"; do
        if [ "  part" -lt 0 ] || [ "$part" -gt 99 ]; then
            echo "Error: Each version number must be between 0 and 99"
            show_help
            exit 1
        fi
    done
}

show_help() {
    echo    "Usage: $0 [-i] [-v] [-l] [-a] [-s]"
    echo    "  -i : install"
    echo    "  -v : version in format x.x.x, x in 0-99"
    echo    "  -l : install latest version"
    echo    "  -a : automated config (not recommended)"
    echo    "  -s : start auditbeat"
    echo    "Example:" 
    echo    "$0 -i -l : install latest version with no config"
}

check_root() {
    if [ $EUID -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
}

while getopts ":iv:las" opt; do
    case ${$opt} in 
        i ) INSTALL=true ;;
        v ) 
            if [ $INSTALL_LATEST=true ]; then
                echo "Error: Cannot use -l and -v options together"
                show_help
                exit 1
            fi
            validate_version "$OPTARG"
            AUDITBEAT_VERSION=$OPTARG
            ;;
        l )
            if [ -n "$AUDITBEAT_VERSION" ]; then
                echo "Error: Cannot use -l and -v options together"
                show_help
                exit 1
            fi
            INSTALL_LATEST=true
            ;;
        a ) 
            AUTOMATED_CONFIG=true
            ;;
        s )
            START=true
            ;;
        \? )
            show_help
            exit 1
            ;;
    esac
done

set -ex

INSTALL_DIR="/usr/share/auditbeat"
CONFIG_DIR="/etc/auditbeat"

install_specific_version() {
    local version=$1
    echo "Installing Auditbeat version $version..."

    if [! -d $INSTALL_DIR ]; then
        sudo mkdir -p "$INSTALL_DIR"
    fi
    local download_url="https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-$version-amd64.deb"
    local temp_file="~/Downloads/auditbeat-$version-amd64.deb"

    echo "Downloading Auditbeat version $version..."
    if ! wget -q "$download_url" -O "$temp_file"; then
        echo "Error: Failed to download Auditbeat $version"
        exit 1
    fi

    echo "Extracting Auditbeat..."
    sudo -i dpkg "$temp_file"

    rm -rf "$temp_file"
    sudo chmod 777 -R "$INSTALL_DIR"
    sudo chmod 777 -R "$CONFIG_DIR"

    if [ $AUTOMATED_CONFIG=true ]; then
        automated_config
    fi

    echo "Auditbeat $version has been installed successfully in $INSTALL_DIR, configuration in $CONFIG_DIR"
}

install_latest_version() {
    echo "Installing latest version..."
    local version=$(curl -s https://www.elastic.co/downloads/past-releases#auditbeat | grep -oP 'Auditbeat \K[^<]+' | sort -V | tail -n 1)
    install_specific_version "$version"
}

start_auditbeat() {
    echo "Starting Auditbeat..."
    sudo service audibeat start
    sudo service auditbeat status
}

automated_config() {
    echo "Configuring Auditbeat automatically..."

    sudo cp "$CONFIG_DIR/config/auditbeat.yml" "$CONFIG_DIR/config/auditbeat.yml.bak"
    # Check bak command
    if [ $? -eq 0 ]; then
        echo "Backup file auditbeat.yml.bak created successfully"
    else
        echo "Error: Failed to create backup file"
        exit 1
    fi

    cat << EOF > "$CONFIG_DIR/config/auditbeat.yml"
auditbeat.modules:

- module: auditd
  # Load audit rules from separate files. Same format as audit.rules(7).
  audit_rule_files: [ '/etc/auditbeat/audit.rules.d/*.conf' ]
  audit_rules: |
    ## Define audit rules here.
    ## Create file watches (-w) or syscall audits (-a or -A). Uncomment these
    ## examples or add your own rules.

    ## If you are on a 64 bit platform, everything should be running
    ## in 64 bit mode. This rule will detect any use of the 32 bit syscalls
    ## because this might be a sign of someone exploiting a hole in the 32
    ## bit API.
    #-a always,exit -F arch=b32 -S all -F key=32bit-abi

    ## Executions.
    -a always,exit -F arch=b64 -S execve,execveat -k exec
    -a always,exit -F arch=b64 -S execve -k command-execution
    -a always,exit -F arch=b32 -S execve -k command-execution
    ## External access (warning: these can be expensive to audit).
    #-a always,exit -F arch=b64 -S accept,bind,connect -F key=external-access

    ## Identity changes.
    #-w /etc/group -p wa -k identity
    #-w /etc/passwd -p wa -k identity
    #-w /etc/gshadow -p wa -k identity

    ## Unauthorized access attempts.
    #-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -k access
    #-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -k access

- module: file_integrity
  paths:
  - /bin
  - /usr/bin
  - /sbin
  - /usr/sbin
  - /etc
  - /home/*/.bash_history
  - /var/www/html
  recursive: false
  include_files:
    - '\.bash_history$'
  exclude_files: []
  scan_at_start: true
  scan_rate_per_sec: 50 MiB
  max_file_size: 100 MiB

- module: system
  datasets:
    - package # Installed, updated, and removed packages

  period: 10s # The frequency at which the datasets check for changes

- module: system
  datasets:
    - host    # General host information, e.g. uptime, IPs
    - login   # User logins, logouts, and system boots.
    - process # Started and stopped processes
    - socket  # Opened and closed sockets
    - user    # User information
  period: 10s
  state.period: 12h
  socket.include_localhost: false
  user.detect_password_changes: true
  login.wtmp_file_pattern: /var/log/wtmp*
  login.btmp_file_pattern: /var/log/btmp*

setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false

output.logstash:
  hosts: ["localhost:5044"]

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
EOF
}

# Logic order:
# - Install
# - Automated config
# - Start
if [ "$INSTALL" = true ]; then
    if [ -n "$AUDITBEAT_VERSION" ]; then
        install_specific_version "$AUDITBEAT_VERSION"
    elif [ "$INSTALL_LATEST" = true ]; then
        install_latest_version
    else
        echo "Error: Please specify either -v or -l option"
        show_help
        exit 1
    fi
    if [ "$AUTOMATED_CONFIG" = true ]; then
        automated_config
    fi
    if [ "$START" = true ]; then
        start_auditbeat
    fi
fi