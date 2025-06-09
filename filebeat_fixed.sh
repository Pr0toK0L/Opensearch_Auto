#!/bin/bash

# Menu options:
# -i : install
# -v : version
# -l : latest version
# -a : automated config

FILEBEAT_VERSION=""
INSTALL=false
AUTOMATED_CONFIG=false
INSTALL_LATEST=false
START=false

validate_version() {
    local version=$1
    
    if ! [[ $version =~ ^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
        echo "Error: Version must be in format x.x.x where x is a number from 0-99"
        show_help
        exit 1
    fi

    IFS='.' read -r -a version_parts <<< "$version"
    for part in "${version_parts[@]}"; do
        if [ "$part" -lt 0 ] || [ "$part" -gt 99 ]; then
            echo "Error: Each version number must be between 0 and 99"
            show_help
            exit 1
        fi
    done
}

show_help() {
    echo "Usage: $0 [-i] [-v] [-l] [-a] [-s]"
    echo "  -i : install"
    echo "  -v : version in format x.x.x, x in 0-99"
    echo "  -l : install latest version"
    echo "  -a : automated config (not recommended)"
    echo "  -s : start filebeat"
    echo "Example:" 
    echo "$0 -i -l : install latest version with no config"
}

check_root() {
    if [ $EUID -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
}

while getopts ":iv:las" opt; do
    case $opt in 
        i ) INSTALL=true ;;
        v ) 
            if [ "$INSTALL_LATEST" = true ]; then
                echo "Error: Cannot use -l and -v options together"
                show_help
                exit 1
            fi
            validate_version "$OPTARG"
            FILEBEAT_VERSION=$OPTARG
            ;;
        l )
            if [ -n "$FILEBEAT_VERSION" ]; then
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

set -e  # Remove -x for production use

INSTALL_DIR="/usr/share/filebeat"
CONFIG_DIR="/etc/filebeat"

install_specific_version() {
    local version=$1
    echo "Installing Filebeat version $version..."

    if [ ! -d "$INSTALL_DIR" ]; then
        sudo mkdir -p "$INSTALL_DIR"
    fi
    
    local download_url="https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-$version-amd64.deb"
    local temp_file="/tmp/filebeat-$version-amd64.deb"

    echo "Downloading Filebeat version $version..."
    if ! wget -q "$download_url" -O "$temp_file"; then
        echo "Error: Failed to download Filebeat $version"
        exit 1
    fi

    echo "Installing Filebeat..."
    if ! sudo dpkg -i "$temp_file"; then
        echo "Error: Failed to install Filebeat package"
        sudo apt-get install -f  # Fix broken dependencies
        exit 1
    fi

    rm -f "$temp_file"
    
    # Set proper permissions instead of 777
    sudo chown -R root:root "$INSTALL_DIR"
    sudo chmod -R 755 "$INSTALL_DIR"
    sudo chown -R root:root "$CONFIG_DIR"
    sudo chmod -R 644 "$CONFIG_DIR"
    sudo chmod 755 "$CONFIG_DIR"

    if [ "$AUTOMATED_CONFIG" = true ]; then
        automated_config
    fi

    echo "Filebeat $version has been installed successfully in $INSTALL_DIR, configuration in $CONFIG_DIR"
}

install_latest_version() {
    echo "Installing latest version..."
    # Better way to get latest version
    local version=$(curl -s "https://api.github.com/repos/elastic/beats/releases/latest" | grep -o '"tag_name": "v[^"]*' | head -1 | cut -d'"' -f4 | sed 's/v//')
    
    if [ -z "$version" ]; then
        echo "Error: Could not determine latest version"
        exit 1
    fi
    
    install_specific_version "$version"
}

start_filebeat() {
    echo "Starting Filebeat..."
    if ! sudo systemctl start filebeat; then
        echo "Error: Failed to start filebeat service"
        exit 1
    fi
    sudo systemctl status filebeat
}

automated_config() {
    echo "Configuring Filebeat automatically..."

    # Create backup - correct path
    if [ -f "$CONFIG_DIR/filebeat.yml" ]; then
        sudo cp "$CONFIG_DIR/filebeat.yml" "$CONFIG_DIR/filebeat.yml.bak"
        if [ $? -eq 0 ]; then
            echo "Backup file filebeat.yml.bak created successfully"
        else
            echo "Error: Failed to create backup file"
            exit 1
        fi
    fi

    # Create configuration file - correct path
    sudo tee "$CONFIG_DIR/filebeat.yml" > /dev/null << 'EOF'
filebeat.inputs:

# Each - is an input. Most options can be set at the input level, so
# you can use different inputs for various configurations.
# Below are the input-specific configurations.

# filestream is an input for collecting log messages from files.
- type: filestream

  # Unique ID among all inputs, an ID is required.
  id: my-filestream-id

  # Change to true to enable this input configuration.
  enabled: true

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    - /var/log/*.log
    - /var/log/apache2/*.log
    - /var/log/nginx/*.log
    - /var/log/syslog
    - /var/log/auth.log

# Log input for system logs
- type: log
  enabled: true
  paths:
    - /var/log/messages
    - /var/log/secure
  fields:
    logtype: system
  fields_under_root: true

filebeat.config.modules:
  # Glob pattern for configuration loading
  path: ${path.config}/modules.d/*.yml

  # Set to true to enable config reloading
  reload.enabled: true

  # Period on which files under path should be checked for changes
  reload.period: 10s

setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false

# Configure what output to use when sending the data collected by the beat.
output.logstash:
  hosts: ["localhost:5044"]

# Alternative: output to Elasticsearch directly
#output.elasticsearch:
#  hosts: ["localhost:9200"]
#  index: "filebeat-%{+yyyy.MM.dd}"

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~

# Set logging level
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644
EOF

    # Set proper permissions for config file
    sudo chmod 644 "$CONFIG_DIR/filebeat.yml"
    
    # Enable some common modules
    echo "Enabling common Filebeat modules..."
    sudo filebeat modules enable system nginx apache || true
}

# Check if running as root
check_root

# Logic order:
# - Install
# - Automated config
# - Start
if [ "$INSTALL" = true ]; then
    if [ -n "$FILEBEAT_VERSION" ]; then
        install_specific_version "$FILEBEAT_VERSION"
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
        start_filebeat
    fi
fi