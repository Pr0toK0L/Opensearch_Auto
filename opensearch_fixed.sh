#!/bin/bash

# Menu options:
# -i : install
# -v : version
# -l : latest version
# -a : automated config
# -s : start opensearch

OPENSEARCH_VERSION=""
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
    echo "  -s : start opensearch"
    echo "Example:" 
    echo "$0 -i -l : install latest version with no config"
    echo "$0 -i -v 2.12.0 : install specific version"
}

check_root() {
    if [ $EUID -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
}

check_sudo() {
    if ! sudo -v; then
        echo "Error: Cannot get sudo privileges"
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
            OPENSEARCH_VERSION="$OPTARG"
            ;;
        l ) 
            if [ -n "$OPENSEARCH_VERSION" ]; then
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
    if [ "$START" = true ] && [ ! -d "/usr/share/opensearch" ]; then
        echo "Error: OpenSearch is not installed. Use -i option to install first."
        exit 1
    fi
fi

# Check root privileges for installation
if [ "$INSTALL" = true ]; then
    check_root
fi

set -e

INSTALL_DIR="/usr/share/opensearch"
CONFIG_DIR="/etc/opensearch"
DASHBOARDS_DIR="/usr/share/opensearch-dashboards"
DASHBOARDS_CONFIG_DIR="/etc/opensearch-dashboards"

install_specific_version() {
    local version=$1
    echo "Installing OpenSearch version $version..."
    
    # Check version to require admin password
    local major_version=$(echo $version | cut -d'.' -f1)
    local minor_version=$(echo $version | cut -d'.' -f2)
    local admin_password=""
    
    if [ "$major_version" -ge 2 ] && [ "$minor_version" -ge 12 ]; then
        # Require admin password for version 2.12 or higher
        while true; do
            read -s -p "Enter admin password for OpenSearch (minimum 8 characters): " admin_password
            echo
            if [ ${#admin_password} -ge 8 ]; then
                break
            else
                echo "Password must be at least 8 characters long. Please try again."
            fi
        done
    fi
    
    # Create install directory if it doesn't exist
    if [ ! -d "$INSTALL_DIR" ]; then
        sudo mkdir -p "$INSTALL_DIR"
    fi
    
    if [ ! -d "$CONFIG_DIR" ]; then
        sudo mkdir -p "$CONFIG_DIR"
    fi
    
    # Download install file
    local download_url="https://artifacts.opensearch.org/releases/bundle/opensearch/$version/opensearch-$version-linux-x64.deb"
    local temp_file="/tmp/opensearch-$version-linux-x64.deb"

    local download_url_dashboards="https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/$version/opensearch-dashboards-$version-linux-x64.deb"
    local temp_file_dashboards="/tmp/opensearch-dashboards-$version-linux-x64.deb"
    
    echo "Downloading OpenSearch $version..."
    if ! wget -q "$download_url" -O "$temp_file"; then
        echo "Error: Failed to download OpenSearch $version"
        echo "Please check if the version exists at: $download_url"
        exit 1
    fi
    
    echo "Installing OpenSearch..."
    if [ -n "$admin_password" ]; then
        export OPENSEARCH_INITIAL_ADMIN_PASSWORD="$admin_password"
        if ! sudo env OPENSEARCH_INITIAL_ADMIN_PASSWORD="$admin_password" dpkg -i "$temp_file"; then
            echo "Error: Failed to install OpenSearch"
            echo "Attempting to fix dependencies..."
            sudo apt-get install -f -y
            sudo env OPENSEARCH_INITIAL_ADMIN_PASSWORD="$admin_password" dpkg -i "$temp_file"
        fi
    else
        if ! sudo dpkg -i "$temp_file"; then
            echo "Error: Failed to install OpenSearch"
            echo "Attempting to fix dependencies..."
            sudo apt-get install -f -y
            sudo dpkg -i "$temp_file"
        fi
    fi

    echo "Downloading OpenSearch Dashboards $version..."
    if ! wget -q "$download_url_dashboards" -O "$temp_file_dashboards"; then
        echo "Error: Failed to download OpenSearch Dashboards $version"
        exit 1
    fi
    
    echo "Installing OpenSearch Dashboards..."
    if ! sudo dpkg -i "$temp_file_dashboards"; then
        echo "Error: Failed to install OpenSearch Dashboards"
        echo "Attempting to fix dependencies..."
        sudo apt-get install -f -y
        sudo dpkg -i "$temp_file_dashboards"
    fi
    
    # Delete temporary files
    rm -f "$temp_file"
    rm -f "$temp_file_dashboards"

    # Set appropriate permissions
    sudo chown -R opensearch:opensearch "$INSTALL_DIR" 2>/dev/null || true
    sudo chown -R opensearch:opensearch "$CONFIG_DIR" 2>/dev/null || true
    sudo chown -R opensearch-dashboards:opensearch-dashboards "$DASHBOARDS_DIR" 2>/dev/null || true
    sudo chown -R opensearch-dashboards:opensearch-dashboards "$DASHBOARDS_CONFIG_DIR" 2>/dev/null || true
    
    sudo chmod 755 "$INSTALL_DIR"
    sudo chmod 755 "$CONFIG_DIR"
    sudo chmod 755 "$DASHBOARDS_DIR"
    sudo chmod 755 "$DASHBOARDS_CONFIG_DIR"
    
    echo "OpenSearch $version has been installed successfully in $INSTALL_DIR, configuration in $CONFIG_DIR"
    if [ -n "$admin_password" ]; then
        echo "Admin password has been set. Please keep it safe."
    fi
}

install_latest_version() {
    echo "Getting latest OpenSearch version..."
    
    # Try to get latest version from GitHub releases API
    local version
    version=$(curl -s "https://api.github.com/repos/opensearch-project/OpenSearch/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/' 2>/dev/null)
    
    if [ -z "$version" ] || [ "$version" = "null" ]; then
        echo "Warning: Could not automatically detect latest version"
        echo "Using fallback version 2.12.0"
        version="2.12.0"
    fi
    
    echo "Latest version detected: $version"
    install_specific_version "$version"
}

start_opensearch() {
    if [ ! -d "$INSTALL_DIR" ]; then
        echo "Error: OpenSearch is not installed in $INSTALL_DIR"
        exit 1
    fi

    echo "Starting OpenSearch..."
    sudo systemctl enable opensearch
    sudo systemctl start opensearch
    
    # Wait a moment for service to start
    sleep 5
    
    if sudo systemctl is-active --quiet opensearch; then
        echo "OpenSearch service started successfully"
        sudo systemctl status opensearch --no-pager
    else
        echo "Error: OpenSearch service failed to start"
        sudo systemctl status opensearch --no-pager
        exit 1
    fi

    echo "Starting OpenSearch Dashboards..."
    sudo systemctl enable opensearch-dashboards
    sudo systemctl start opensearch-dashboards
    
    # Wait a moment for service to start
    sleep 5
    
    if sudo systemctl is-active --quiet opensearch-dashboards; then
        echo "OpenSearch Dashboards service started successfully"
        sudo systemctl status opensearch-dashboards --no-pager
    else
        echo "Warning: OpenSearch Dashboards service may have failed to start"
        sudo systemctl status opensearch-dashboards --no-pager
    fi
}

automated_config() {
    echo "Configuring OpenSearch automatically..."
    
    # Backup original config
    if [ -f "$CONFIG_DIR/config/opensearch.yml" ]; then
        sudo cp "$CONFIG_DIR/config/opensearch.yml" "$CONFIG_DIR/config/opensearch.yml.bak"
        echo "Backup created: opensearch.yml.bak"
    fi
    
    # Config network
    sudo tee "$CONFIG_DIR/config/opensearch.yml" > /dev/null << 'EOF'
network.host: 0.0.0.0
http.port: 9200
path.data: /var/lib/opensearch
path.logs: /var/log/opensearch
discovery.type: single-node
plugins.security.disabled: false
EOF
    
    # Config JVM heap sizes
    echo "JVM Heap Size Configuration"
    echo "As a starting point, you should set these values to half of the available system memory."
    echo "For dedicated hosts this value can be increased based on your workflow requirements."
    echo "Example: if the host machine has 8 GB of memory, set heap sizes to 4 GB"
    
    local heap_size
    while true; do
        read -p "Enter JVM heap size in GB (integer, e.g., 4): " heap_size
        if [[ "$heap_size" =~ ^[0-9]+$ ]] && [ "$heap_size" -gt 0 ]; then
            break
        else
            echo "Please enter a valid positive integer"
        fi
    done
    
    echo "Setting initial and maximum JVM heap size to: ${heap_size}GB"
    sudo tee "$CONFIG_DIR/jvm.options" > /dev/null << EOF
-Xms${heap_size}g
-Xmx${heap_size}g
EOF
    
    # Config SSL certificates
    echo "Generating SSL certificates..."
    cd "$CONFIG_DIR"
    
    # Remove existing certificates
    sudo rm -f ./*.pem ./*.csr ./*.ext
    
    # Generate root CA
    sudo openssl genrsa -out root-ca-key.pem 2048
    sudo openssl req -new -x509 -sha256 -key root-ca-key.pem -subj "/C=CA/ST=ONTARIO/L=TORONTO/O=ORG/OU=UNIT/CN=ROOT" -out root-ca.pem -days 730

    # Generate admin certificate
    sudo openssl genrsa -out admin-key-temp.pem 2048
    sudo openssl pkcs8 -inform PEM -outform PEM -in admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-key.pem
    sudo openssl req -new -key admin-key.pem -subj "/C=CA/ST=ONTARIO/L=TORONTO/O=ORG/OU=UNIT/CN=A" -out admin.csr
    sudo openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out admin.pem -days 730

    # Generate node certificate
    sudo openssl genrsa -out node1-key-temp.pem 2048
    sudo openssl pkcs8 -inform PEM -outform PEM -in node1-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node1-key.pem
    sudo openssl req -new -key node1-key.pem -subj "/C=CA/ST=ONTARIO/L=TORONTO/O=ORG/OU=UNIT/CN=node1.dns.a-record" -out node1.csr
    sudo sh -c 'echo subjectAltName=DNS:node1.dns.a-record > node1.ext'
    sudo openssl x509 -req -in node1.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out node1.pem -days 730 -extfile node1.ext
    
    # Clean up temporary files
    sudo rm -f ./*temp.pem ./*.csr ./*.ext
    
    # Set proper ownership
    sudo chown opensearch:opensearch ./*.pem 2>/dev/null || true

    # Add SSL configuration to opensearch.yml
    sudo tee -a "$CONFIG_DIR/config/opensearch.yml" > /dev/null << 'EOF'

# Security Configuration
plugins.security.ssl.transport.pemcert_filepath: /etc/opensearch/node1.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/opensearch/node1-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/opensearch/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/opensearch/node1.pem
plugins.security.ssl.http.pemkey_filepath: /etc/opensearch/node1-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/opensearch/root-ca.pem
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - 'CN=A,OU=UNIT,O=ORG,L=TORONTO,ST=ONTARIO,C=CA'
plugins.security.nodes_dn:
  - 'CN=node1.dns.a-record,OU=UNIT,O=ORG,L=TORONTO,ST=ONTARIO,C=CA'
plugins.security.audit.type: internal_opensearch
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]
EOF

    # Verify configuration was updated
    if [ -f "$CONFIG_DIR/config/opensearch.yml.bak" ]; then
        if ! diff "$CONFIG_DIR/config/opensearch.yml.bak" "$CONFIG_DIR/config/opensearch.yml" > /dev/null; then
            echo "Security configuration has been updated successfully"
        else
            echo "Error: Failed to update security configuration"
            exit 1
        fi
    fi

    # Configure internal users
    echo "Configuring OpenSearch users and roles..."
    
    if [ -d "$INSTALL_DIR/plugins/opensearch-security/tools" ]; then
        cd "$INSTALL_DIR/plugins/opensearch-security/tools"
        
        local admin_password
        while true; do
            read -s -p "Enter new admin password (minimum 8 characters): " admin_password
            echo
            if [ ${#admin_password} -ge 8 ]; then
                break
            else
                echo "Password must be at least 8 characters long. Please try again."
            fi
        done
        
        # Generate password hash
        local admin_hash
        admin_hash=$(OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk ./hash.sh <<< "$admin_password" 2>/dev/null | tail -n 1)
        
        if [ -n "$admin_hash" ]; then
            # Backup original internal_users.yml
            if [ -f "$CONFIG_DIR/opensearch-security/internal_users.yml" ]; then
                sudo cp "$CONFIG_DIR/opensearch-security/internal_users.yml" "$CONFIG_DIR/opensearch-security/internal_users.yml.bak"
            fi
            
            # Add new user
            sudo tee -a "$CONFIG_DIR/opensearch-security/internal_users.yml" > /dev/null << EOF

# Custom user
user:
  hash: "$admin_hash"
  reserved: false
  description: "New internal user"
EOF
            echo "Internal user 'user' has been configured"
        else
            echo "Warning: Failed to generate password hash. Skipping internal user configuration."
        fi
    else
        echo "Warning: OpenSearch security tools not found. Skipping internal user configuration."
    fi
    
    # Config OpenSearch Dashboards
    echo "Configuring OpenSearch Dashboards..."
    
    if [ -f "$DASHBOARDS_CONFIG_DIR/opensearch_dashboards.yml" ]; then
        sudo cp "$DASHBOARDS_CONFIG_DIR/opensearch_dashboards.yml" "$DASHBOARDS_CONFIG_DIR/opensearch_dashboards.yml.bak"
    fi
    
    sudo tee -a "$DASHBOARDS_CONFIG_DIR/opensearch_dashboards.yml" > /dev/null << 'EOF'

# Server Configuration
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: ["https://localhost:9200"]
opensearch.ssl.verificationMode: none
opensearch.username: admin
opensearch.password: admin
EOF

    echo "OpenSearch Dashboards configuration updated"
    echo "Configuration completed successfully!"
    echo ""
    echo "Important notes:"
    echo "- OpenSearch will be available at: https://localhost:9200"
    echo "- OpenSearch Dashboards will be available at: http://localhost:5601"
    echo "- Default credentials: admin/admin (change these after first login)"
    echo "- SSL certificates have been generated in $CONFIG_DIR"
    echo "- Configuration backups have been created with .bak extension"
}

# Main execution logic
if [ "$INSTALL" = true ]; then
    if [ -n "$OPENSEARCH_VERSION" ]; then
        install_specific_version "$OPENSEARCH_VERSION"
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
    start_opensearch
fi

# If no options provided, show help
if [ "$INSTALL" = false ] && [ "$AUTOMATED_CONFIG" = false ] && [ "$START" = false ]; then
    show_help
fi