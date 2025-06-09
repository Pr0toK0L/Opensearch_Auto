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
    echo "Usage: $0 [-i] [-v VERSION] [-l] [-a] [-s]"
    echo "  -i : install"
    echo "  -v : version in format x.x.x, x in 0-99"
    echo "  -l : install latest version"
    echo "  -a : automated config (not recommended)"
    echo "  -s : start logstash"
    echo "Example:" 
    echo "$0 -i -l : install latest version with no config"
    echo "$0 -i -v 8.11.0 : install specific version"
}

check_root() {
    if [ $EUID -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Get options menu
while getopts ":iv:las" opt; do
    case ${opt} in
        i ) 
            INSTALL=true
            ;;
        v ) 
            if [ "$INSTALL_LATEST" = true ]; then
                echo "Error: Cannot use -v and -l options together"
                show_help
                exit 1
            fi
            validate_version "$OPTARG"
            LOGSTASH_VERSION="$OPTARG"
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
            echo "Error: Invalid option -$OPTARG"
            show_help
            exit 1
            ;;
        : )
            echo "Error: Option -$OPTARG requires an argument"
            show_help
            exit 1
            ;;
    esac
done

# Check if install option is provided when other options are used
if [ "$INSTALL" = false ] && ([ "$AUTOMATED_CONFIG" = true ] || [ "$START" = true ]); then
    if [ "$START" = true ] && [ ! -d "/usr/share/logstash" ]; then
        echo "Error: Logstash is not installed. Use -i option to install first."
        exit 1
    fi
fi

# Check root privileges for installation
if [ "$INSTALL" = true ]; then
    check_root
fi

set -e

INSTALL_DIR="/usr/share/logstash"
CONFIG_DIR="/etc/logstash"

install_specific_version() {
    local version=$1
    echo "Installing Logstash version $version..."

    # Create directories if they don't exist
    if [ ! -d "$INSTALL_DIR" ]; then
        sudo mkdir -p "$INSTALL_DIR"
    fi
    
    if [ ! -d "$CONFIG_DIR" ]; then
        sudo mkdir -p "$CONFIG_DIR"
        sudo mkdir -p "$CONFIG_DIR/conf.d"
    fi

    local download_url="https://artifacts.elastic.co/downloads/logstash/logstash-$version-amd64.deb"
    local temp_file="/tmp/logstash-$version-amd64.deb"

    echo "Downloading Logstash version $version..."
    if ! wget -q "$download_url" -O "$temp_file"; then
        echo "Error: Failed to download Logstash $version"
        echo "Please check if the version exists at: $download_url"
        exit 1
    fi

    echo "Installing Logstash package..."
    if ! sudo dpkg -i "$temp_file"; then
        echo "Error: Failed to install Logstash package"
        echo "Attempting to fix dependencies..."
        sudo apt-get install -f -y
        sudo dpkg -i "$temp_file"
    fi

    # Clean up temp file
    rm -f "$temp_file"
    
    # Set appropriate permissions
    sudo chown -R logstash:logstash "$INSTALL_DIR" 2>/dev/null || true
    sudo chown -R logstash:logstash "$CONFIG_DIR" 2>/dev/null || true
    sudo chmod 755 "$INSTALL_DIR"
    sudo chmod 755 "$CONFIG_DIR"

    echo "Logstash $version has been installed successfully in $INSTALL_DIR, configuration in $CONFIG_DIR"
}

install_latest_version() {
    echo "Getting latest Logstash version..."
    
    # Try to get latest version from GitHub releases API
    local version
    version=$(curl -s "https://api.github.com/repos/elastic/logstash/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/' 2>/dev/null)
    
    if [ -z "$version" ] || [ "$version" = "null" ]; then
        echo "Warning: Could not automatically detect latest version"
        echo "Using fallback version 8.11.0"
        version="8.11.0"
    fi
    
    echo "Latest version detected: $version"
    install_specific_version "$version"
}

start_logstash() {
    if [ ! -d "$INSTALL_DIR" ]; then
        echo "Error: Logstash is not installed in $INSTALL_DIR"
        exit 1
    fi

    if [ ! -f "$CONFIG_DIR/pipelines.yml" ] && [ ! -f "$CONFIG_DIR/logstash.yml" ]; then
        echo "Warning: No configuration files found. Creating basic configuration..."
        automated_config
    fi

    echo "Starting Logstash..."
    cd "$INSTALL_DIR"
    
    # Check if pipelines.yml exists, otherwise use conf.d directory
    if [ -f "$CONFIG_DIR/pipelines.yml" ]; then
        sudo -u logstash ./bin/logstash --path.settings="$CONFIG_DIR"
    elif [ -d "$CONFIG_DIR/conf.d" ] && [ "$(ls -A $CONFIG_DIR/conf.d)" ]; then
        sudo -u logstash ./bin/logstash -f "$CONFIG_DIR/conf.d/"
    else
        echo "Error: No valid configuration found"
        exit 1
    fi
}

automated_config() {
    echo "Configuring Logstash automatically..."
    
    # Create conf.d directory if it doesn't exist
    sudo mkdir -p "$CONFIG_DIR/conf.d"
    
    # Create input configuration
    sudo tee "$CONFIG_DIR/conf.d/input.conf" > /dev/null << 'EOF'
input {
    file {
        path => "/var/log/syslog"
        start_position => "beginning"
        sincedb_path => "/dev/null"
    }
}
EOF
    
    # Create filter configuration
    sudo tee "$CONFIG_DIR/conf.d/filter.conf" > /dev/null << 'EOF'
filter {
    if [path] =~ "syslog" {
        grok {
            match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}" }
            overwrite => [ "message" ]
        }
        date {
            match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
    }
}
EOF

    # Create output configuration
    sudo tee "$CONFIG_DIR/conf.d/output.conf" > /dev/null << 'EOF'
output {
    stdout {
        codec => rubydebug
    }
    # Uncomment below to send to Elasticsearch/OpenSearch
    # elasticsearch {
    #     hosts => ["localhost:9200"]
    #     index => "logstash-logs-%{+YYYY.MM.dd}"
    # }
}
EOF

    # Set proper permissions
    sudo chown -R logstash:logstash "$CONFIG_DIR" 2>/dev/null || true
    sudo chmod 644 "$CONFIG_DIR/conf.d/"*.conf

    echo "Basic configuration created in $CONFIG_DIR/conf.d/"
}

# Main execution logic
if [ "$INSTALL" = true ]; then
    if [ -n "$LOGSTASH_VERSION" ]; then
        install_specific_version "$LOGSTASH_VERSION"
    elif [ "$INSTALL_LATEST" = true ]; then
        install_latest_version
    else
        echo "Error: Please specify either -v VERSION or -l option with -i"
        show_help
        exit 1
    fi
fi

if [ "$AUTOMATED_CONFIG" = true ]; then
    automated_config
fi

if [ "$START" = true ]; then
    start_logstash
fi

# If no options provided, show help
if [ "$INSTALL" = false ] && [ "$AUTOMATED_CONFIG" = false ] && [ "$START" = false ]; then
    show_help
fi