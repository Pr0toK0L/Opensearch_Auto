#!/bin/bash

# Script to install and configure OpenSearch and OpenSearch Dashboards
# Tested on Ubuntu 20.04/22.04

# Variables
OPENSEARCH_VERSION="2.17.1"
DASHBOARDS_VERSION="2.17.1"
INSTALL_DIR="/usr/share"
CONFIG_DIR="/etc"
OPENSEARCH_URL="https://artifacts.opensearch.org/releases/bundle/opensearch/${OPENSEARCH_VERSION}/opensearch-${OPENSEARCH_VERSION}-linux-x64.deb"
DASHBOARDS_URL="https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/${DASHBOARDS_VERSION}/opensearch-dashboards-${DASHBOARDS_VERSION}-linux-x64.deb"

# Exit on error, verbose
set -ex

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for root privileges
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y wget curl tar openjdk-11-jre

# Check if Java is installed
if ! command_exists java; then
    echo "Java installation failed"
    exit 1
fi

# Create OpenSearch user
echo "Creating OpenSearch user..."
useradd -m -s /bin/bash opensearch || echo "User already exists"

# Download and install OpenSearch
echo "Downloading OpenSearch..."
wget -q "$OPENSEARCH_URL" -O "/tmp/opensearch.tar.gz"
mkdir -p "$INSTALL_DIR/opensearch"
tar -xzf "/tmp/opensearch.tar.gz" -C "$INSTALL_DIR/opensearch" --strip-components=1
chown -R opensearch:opensearch "$INSTALL_DIR/opensearch"

# Configure OpenSearch
echo "Configuring OpenSearch..."
cat > "$INSTALL_DIR/opensearch/config/opensearch.yml" << EOF
cluster.name: opensearch-cluster
node.name: node-1
network.host: 0.0.0.0
discovery.type: single-node
plugins.security.disabled: false
EOF

# Set up OpenSearch as a service
echo "Setting up OpenSearch service..."
cat > /etc/systemd/system/opensearch.service << EOF
[Unit]
Description=OpenSearch
After=network.target

[Service]
Type=forking
User=opensearch
Group=opensearch
ExecStart=$INSTALL_DIR/opensearch/bin/opensearch
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Download and install OpenSearch Dashboards
echo "Downloading OpenSearch Dashboards..."
wget -q "$DASHBOARDS_URL" -O "/tmp/dashboards.tar.gz"
mkdir -p "$INSTALL_DIR/opensearch-dashboards"
tar -xzf "/tmp/dashboards.tar.gz" -C "$INSTALL_DIR/opensearch-dashboards" --strip-components=1
chown -R opensearch:opensearch "$INSTALL_DIR/opensearch-dashboards"

# Configure OpenSearch Dashboards
echo "Configuring OpenSearch Dashboards..."
cat > "$INSTALL_DIR/opensearch-dashboards/config/opensearch_dashboards.yml" << EOF
server.host: "0.0.0.0"
server.port: 5601
opensearch.hosts: ["http://localhost:9200"]
opensearch.ssl.verificationMode: none
opensearch.username: "admin"
opensearch.password: "admin"
EOF

# Set up OpenSearch Dashboards as a service
echo "Setting up OpenSearch Dashboards service..."
cat > /etc/systemd/system/opensearch-dashboards.service << EOF
[Unit]
Description=OpenSearch Dashboards
After=network.target

[Service]
Type=simple
User=opensearch
Group=opensearch
ExecStart=$INSTALL_DIR/opensearch-dashboards/bin/opensearch-dashboards
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
echo "Starting services..."
systemctl daemon-reload
systemctl enable opensearch
systemctl start opensearch
systemctl enable opensearch-dashboards
systemctl start opensearch-dashboards

# Clean up
rm -f /tmp/opensearch.tar.gz /tmp/dashboards.tar.gz

# Verify services
echo "Verifying installation..."
sleep 10
if systemctl is-active --quiet opensearch; then
    echo "OpenSearch is running"
else
    echo "OpenSearch failed to start"
    exit 1
fi
if systemctl is-active --quiet opensearch-dashboards; then
    echo "OpenSearch Dashboards is running"
else
    echo "OpenSearch Dashboards failed to start"
    exit 1
fi

echo "Installation complete! Access OpenSearch Dashboards at http://<server-ip>:5601"
echo "Default credentials: admin/admin"