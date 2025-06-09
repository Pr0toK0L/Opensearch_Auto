#!/bin/bash

# Menu options:
# -i : install
# -v : version
# -l : latest version
# -a : automated config

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
    echo    "Usage: $0 [-i] [-v] [-l] [-a] [-s]"
    echo    "  -i : install"
    echo    "  -v : version in format x.x.x, x in 0-99"
    echo    "  -l : install latest version"
    echo    "  -a : automated config (not recommended)"
    echo    "  -s : start opensearch"
    echo    "Example:" 
    echo    "$0 -i -l : install latest version with no config"
}

check_root() {
    if [ $EUID -ne 0 ]; then
        echo "This script must be run as root"
        exit 1
    fi
}

'''
check_sudo() {
    if ! sudo -v; then
        echo "Error: Cannot get sudo privileges"
        exit 1
    fi
} 
'''
# Get options menu
while getopts ":iv:las" opt; do
    case ${opt} in
        i ) INSTALL=true ;;
        v ) 
            if [ "$INSTALL_LATEST" = true ]; then
                echo "Error: Cannot use -v and -l options together"
                show_help
                exit 1
            fi
            validate_version "$OPTARG"
            OPENSEARCH_VERSION=$OPTARG
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
        \? ) show_help
            exit 1 ;;
    esac
done

set -ex

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
    
    # Download install file
    local download_url="https://artifacts.opensearch.org/releases/bundle/opensearch/$version/opensearch-$version-linux-x64.deb"
    local temp_file="~/Downloads/opensearch-$version-linux-x64.deb"

    local download_url_dashboards="https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/$version/opensearch-dashboards-$version-linux-x64.deb"
    local temp_file_dashboards="~/Downloads/opensearch-dashboards-$version-linux-x64.deb"
    
    echo "Downloading OpenSearch $version..."
    if ! wget -q "$download_url" -O "$temp_file"; then
        echo "Error: Failed to download OpenSearch $version"
        exit 1
    fi
    
    echo "Extracting OpenSearch..."
    if [ -n "$admin_password" ]; then

        export OPENSEARCH_INITIAL_ADMIN_PASSWORD="$admin_password"
        if ! sudo env OPENSEARCH_INITIAL_ADMIN_PASSWORD="$admin_password" dpkg -i "$temp_file"; then
            echo "Error: Failed to extract OpenSearch"
            rm "$temp_file"
            exit 1
        fi
    else
        if ! sudo dpkg -i "$temp_file"; then
            echo "Error: Failed to extract OpenSearch"
            rm "$temp_file"
            exit 1
        fi
    fi

    echo "Downloading OpenSearch Dashboards $version..."
    if ! wget -q "$download_url_dashboards" -O "$temp_file_dashboards"; then
        echo "Error: Failed to download OpenSearch Dashboards $version"
        exit 1
    fi
    
    echo "Extracting OpenSearch Dashboards..."
    sudo dpkg -i "$temp_file_dashboards"
    
    # Delete temporary files
    rm "$temp_file"
    rm "$temp_file_dashboards"

    sudo chmod 777 -R "$INSTALL_DIR"
    sudo chmod 777 -R "$CONFIG_DIR"
    sudo chmod 777 -R "$DASHBOARDS_DIR"
    sudo chmod 777 -R "$DASHBOARDS_CONFIG_DIR"
    
    # Automated config if requested
    if [ "$AUTOMATED_CONFIG" = true ]; then
        automated_config
    fi
    
    echo "OpenSearch $version has been installed successfully in $INSTALL_DIR, configuration in $CONFIG_DIR"
    if [ -n "$admin_password" ]; then
        echo "Admin password has been set. Please keep it safe."
    fi
}

install_latest_version() {
    echo "Installing latest version..."
    local version=$(curl -s https://artifacts.opensearch.org/releases/bundle/opensearch/ | grep -oP 'opensearch-\K[^<]+' | sort -V | tail -n 1)
    install_specific_version "$version"
}

start_opensearch() {
    echo "Starting OpenSearch..."
    sudo systemctl enable opensearch
    sudo systemctl start opensearch
    sudo systemctl status opensearch

    echo "Starting OpenSearch Dashboards..."
    sudo systemctl enable opensearch-dashboards
    sudo systemctl start opensearch-dashboards
    sudo systemctl status opensearch-dashboards
}

automated_config() {
    echo "Configuring OpenSearch automatically..."
    # Config network
    cat > "$CONFIG_DIR/config/opensearch.yml" << EOF
    network.host: 0.0.0.0
    http.port: 9200
    path.data: /var/lib/opensearch
    path.logs: /var/log/opensearch
    discovery.type: single-node
    plugins.security.disabled: false
EOF
    # Config JVM heap sizes (not sure)
    echo "Specify initial and maximum JVM heap sizes"
    echo "Modify the values for initial and maximum heap sizes. As a starting point, you should set these values to half of the available system memory. For dedicated hosts this value can be increased based on your workflow requirements."
    echo "As an example, if the host machine has 8 GB of memory, then you might want to set the initial and maximum heap sizes to 4 GB"
    read -s -p "Enter initial and maximum JVM heap sizes (integer): " heap_sizes
    echo "Initial JVM heap size: $heap_sizes"
    echo "Maximum JVM heap size: $heap_sizes"
    cat > "$CONFIG_DIR/jvm.options" << EOF
    -Xms"$heap_sizes"g
    -Xmx"$heap_sizes"g
EOF
    # Config SSL
    cd "$CONFIG_DIR"
    sudo rm -f *pem

    sudo openssl genrsa -out root-ca-key.pem 2048
    sudo openssl req -new -x509 -sha256 -key root-ca-key.pem -subj "/C=CA/ST=ONTARIO/L=TORONTO/O=ORG/OU=UNIT/CN=ROOT" -out root-ca.pem -days 730

    sudo openssl genrsa -out admin-key-pem 2048
    sudo openssl pkcs8 -inform PEM -outform PEM -in admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-key.pem
    sudo openssl req -new -key admin-key.pem -subj "/C=CA/ST=ONTARIO/L=TORONTO/O=ORG/OU=UNIT/CN=A" -out admin.csr
    sudo openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out admin.pem -days 730

    sudo openssl genrsa -out node1-key-temp.pem 2048
    sudo openssl pkcs8 -inform PEM -outform PEM -in node1-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node1-key.pem
    sudo openssl req -new -key node1-key.pem -subj "/C=CA/ST=ONTARIO/L=TORONTO/O=ORG/OU=UNIT/CN=node1.dns.a-record" -out node1.csr
    sudo sh -c 'echo subjectAltName=DNS:node1.dns.a-record > node1.ext'
    sudo openssl x509 -req -in node1.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out node1.pem -days 730 -extfile node1.ext
    
    sudo rm -f *temp.pem *csr *ext
    sudo chown opensearch:opensearch admin-key.pem admin.pem node1-key.pem node1.pem root-ca-key.pem root-ca.pem

    # Add SSL configuration to opensearch.yml
    
    sudo cp "$CONFIG_DIR/config/opensearch.yml" "$CONFIG_DIR/config/opensearch.yml.bak"
    # Check bak command
    if [ $? -eq 0 ]; then
        echo "Backup file opensearch.yml.bak created successfully"
    else
        echo "Error: Failed to create backup file"
        exit 1
    fi

    cat << EOF | sudo tee -a "$CONFIG_DIR/config/opensearch.yml"
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

    # Check if file has changed
    if ! diff "${CONFIG_DIR}/config/opensearch.yml.bak" "$CONFIG_DIR/config/opensearch.yml" > /dev/null; then
        echo "Security configuration has been updated successfully"
    else
        echo "Error: Failed to update security configuration"
        exit 1
    fi

    echo "Configuring OpenSearch users and roles"
    cd $INSTALL_DIR/plugins/opensearch-security/tools

    read -s -p "Enter new admin password: " admin_password
    echo
    admin_hash=$(OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk ./hash.sh <<< "$admin_password")

    cat << EOF | sudo tee -a "$CONFIG_DIR/opensearch-security/internal_users.yml"
user:
    hash: "$admin_hash"
    reserved: false
    description: "New internal user"
EOF
    # Config OpenSearch Dashboards server (not sure)
    echo "Configuring OpenSearch Dashboards server hosts"
    cat << EOF || sudo tee -a "$DASHBOARDS_CONFIG_DIR/opensearch_dashboards.yml"
server.host: 0.0.0.0
server.port: 5601
EOF
}

# Logic order:
# - Install
# - Automated config
# - Start
if [ "$INSTALL" = true ]; then
    if [ -n "$OPENSEARCH_VERSION" ]; then
        install_specific_version "$OPENSEARCH_VERSION"
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
        start_opensearch
    fi
fi