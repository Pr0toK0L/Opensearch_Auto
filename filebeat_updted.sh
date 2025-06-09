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
    
    if ! [[$version =~ ^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
        echo "Error: Version must be in format x.x.x where x is a number from 0-99"
        show_help
        exit 1
    fi

    IFS='.' read -r -a version_parts <<< "$version"
    for part in "${version_parts[@]}"; do
        if [ "part" -lt 0 ] || [ "$part" -gt 99 ]; then
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
    echo    "  -s : start filebeat"
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

set -ex

INSTALL_DIR="/usr/share/filebeat"
CONFIG_DIR="/etc/filebeat"

install_specific_version() {
    local version=$1
    echo "Installing Filebeat version $version..."

    if [! -d $INSTALL_DIR ]; then
        sudo mkdir -p "$INSTALL_DIR"
    fi
    local download_url="https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-$version-amd64.deb"
    local temp_file="~/Downloads/filebeat-$version-amd64.deb"

    echo "Downloading Filebeat version $version..."
    if ! wget -q "$download_url" -O "$temp_file"; then
        echo "Error: Failed to download Filebeat $version"
        exit 1
    fi

    echo "Extracting Filebeat..."
    sudo -i dpkg "$temp_file"

    rm -rf "$temp_file"
    sudo chmod 777 -R "$INSTALL_DIR"
    sudo chmod 777 -R "$CONFIG_DIR"

    if [ $AUTOMATED_CONFIG=true ]; then
        automated_config
    fi

    echo "Filebeat $version has been installed successfully in $INSTALL_DIR, configuration in $CONFIG_DIR"
}

install_latest_version() {
    echo "Installing latest version..."
    local version=$(curl -s https://www.elastic.co/downloads/past-releases#filebeat | grep -oP 'Filebeat \K[^<]+' | sort -V | tail -n 1)
    install_specific_version "$version"
}

start_filebeat() {
    echo "Starting Filebeat..."
    sudo service filebeat start
    sudo service filebeat status
}

automated_config() {
    echo "Configuring Filebeat automatically..."

    sudo cp "$CONFIG_DIR/config/filebeat.yml" "$CONFIG_DIR/config/filebeat.yml.bak"
    # Check bak command
    if [ $? -eq 0 ]; then
        echo "Backup file filebeat.yml.bak created successfully"
    else
        echo "Error: Failed to create backup file"
        exit 1
    fi

    cat << EOF > "$CONFIG_DIR/config/filebeat.yml"
filebeat.inputs:

# Each - is an input. Most options can be set at the input level, so
# you can use different inputs for various configurations.
# Below are the input-specific configurations.

# filestream is an input for collecting log messages from files.
- type: filestream

  # Unique ID among all inputs, an ID is required.
  id: my-filestream-id

  # Change to true to enable this input configuration.
  enabled: false

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    - /var/log/apache2/access.log*
    - /var/log/apache2/error.log*
    #- c:\programdata\elasticsearch\logs\*

filebeat.config.modules:
  # Glob pattern for configuration loading
  path: ${path.config}/modules.d/*.yml

  # Set to true to enable config reloading
  reload.enabled: false

  # Period on which files under path should be checked for changes
  #reload.period: 10s

setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false

output.logstash:
  hosts: ["localhost:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
EOF


}

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