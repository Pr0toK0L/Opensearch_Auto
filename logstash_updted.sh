#!/bin/bash

# Menu options:
# -i : install
# -v : version
# -l : latest version
# -a : automated config
# -s : start logstash

LOGSTASH_VERSION=""
INSTALL=false
INSTALL_LATEST=false
AUTOMATED_CONFIG=false
START=false

validate_version() {
    local version=$1
    # Check version format
    if ! [[ $version =~ ^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; then
        echo "Error: Version must be in format x.x.x where x is a number from 0-99"
        show_help
        exit 1
    fi

    # Split version into parts
    IFS='.' read -r -a version_parts <<< "$version"
    
    # Check each part is between 0 and 99
    for part in "${version_parts[@]}"; do
        if [ "$part" -lt 0 ] || [ "$part" -gt 99 ]; then
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
    echo    "  -s : start logstash"
    echo    "Example:" 
    echo    "$0 -i -l : install latest version with no config"
}

check_root() {
    if [ $EUID -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Get options menu
while getopts ":iv:las"; do
    case ${opt} in
        i ) INSTALL=true;;
        v ) 
            if [ $INSTALL_LATEST=true ]; then
                echo "Error: Cannot use -v and -l options together"
                show_help
                exit 1
            fi
            validate_version "$OPTARG"
            LOGSTASH_VERSION = $OPTARG
            ;;
        l ) 
            if [ -n "$LOGSTASH_VERSION" ]; then
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

INSTALL_DIR="/usr/share/logstash"
CONFIG_DIR="/etc/logstash"

install_specific_version() {
    local version=$1
    echo "Installing Logstash version $version..."

    if [ ! -d "$INSTALL_DIR" ]; then
        sudo mkdir -p "$INSTALL_DIR"
    fi
    local download_url="https://artifacts.elastic.co/downloads/logstash/logstash-$version-amd64.deb"
    local temp_file="~/Downloads/logstash-$version-amd64.deb"

    echo "Download Logstash version $version..."
    if ! wget -q "$download_url" -O "$temp_file"; then
        echo "Error: Failed to download Logstash $version"
        exit 1
    fi

    echo "Extracting Logstash..."
    sudo -i dpkg "$temp_file"

    rm -rf "$temp_file"
    sudo chmod 777 -R "$INSTALL_DIR"
    sudo chmod 777 -R "$CONFIG_DIR"

    if [ $AUTOMATED_CONFIG=true ]; then
        automated_config
    fi

    echo "Logstash $version has been installed successfully in $INSTALL_DIR, configuration in $CONFIG_DIR"
}

install_latest_version() {
    echo "Installing latest version..."
    local version=$(curl -s https://www.elastic.co/downloads/past-releases#logstash | grep -oP 'Logstash \K[^<]+' | sort -V | tail -n 1)
    install_specific_version "$version"
}

start_logstash() {
    echo "Starting Logstash..."
    cd "$INSTALL_DIR"
    sudo ./bin/logstash -f "$CONFIG_DIR/pipelines.yml"
}

automated_config() {
    echo "Configuring Logstash automatically..."
    cat << EOF > "$CONFIG_DIR/conf.d/input.conf"
input {
    file {
        path => "/var/log/opensearch/*"
    }
}
EOF
    
    cat << EOF > "$CONFIG_DIR/conf.d/filter.conf"
filter {
    json {
        source => "message"
    }
}
EOF

    cat << EOF > "$CONFIG_DIR/conf.d/output.conf"
output {
    opensearch {
        hosts => ["localhost:9200"]
        index => "logstash-logs-%{+YYYY.MM.dd}"
    }
}
EOF
}

# Logic order:
# - Install
# - Automated config
# - Start
if [ "$INSTALL" = true ]; then
    if [ -n "$LOGSTASH_VERSION" ]; then
        install_specific_version "$LOGSTASH_VERSION"
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
        start_logstash
    fi
fi