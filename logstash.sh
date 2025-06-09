#!/bin/bash

# Script to install and configure Logstash
# Tested on Ubuntu 20.04/22.04

# Variables
LOGSTASH_VERSION="8.15.2"
LOGSTASH_URL="https://artifacts.elastic.co/downloads/logstash/logstash-oss-${LOGSTASH_VERSION}-linux-x64.tar.gz"
INSTALL_DIR="/usr/share"
CONFIG_DIR="/etc/logstash"

# Exit on error
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

# Create Logstash user
echo "Creating Logstash user..."
useradd -m -s /bin/bash logstash || echo "User already exists"

# Download and install Logstash
echo "Downloading Logstash..."
wget -q "$LOGSTASH_URL" -O "/tmp/logstash.tar.gz"
mkdir -p "$INSTALL_DIR/logstash"
tar -xzf "/tmp/logstash.tar.gz" -C "$INSTALL_DIR/logstash" --strip-components=1
chown -R logstash:logstash "$INSTALL_DIR/logstash"

# Install OpenSearch output plugin
echo "Installing Logstash OpenSearch output plugin..."
"$INSTALL_DIR/logstash/bin/logstash-plugin" install logstash-output-opensearch

# Configure Logstash pipeline
echo "Configuring Logstash pipeline..."
mkdir -p "$CONFIG_DIR/conf.d"
cat > "$CONFIG_DIR/conf.d/logstash.conf" << EOF
input {
  beats {
    port => 5044
  }
}
output {
  opensearch {
    hosts => ["http://localhost:9200"]
    index => "logstash-%{+YYYY.MM.dd}"
    user => "admin"
    password => "admin"
    ssl => false
  }
}
EOF
chown -R logstash:logstash "$CONFIG_DIR"

# Set up Logstash as a service
echo "Setting up Logstash service..."
cat > /etc/systemd/system/logstash.service << EOF
[Unit]
Description=Logstash
After=network.target

[Service]
Type=simple
User=logstash
Group=logstash
Environment="JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64"
ExecStart=$INSTALL_DIR/logstash/bin/logstash -f $CONFIG_DIR/conf.d/logstash.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "Starting Logstash service..."
systemctl daemon-reload
systemctl enable logstash
systemctl start logstash

# Clean up
rm -f /tmp/logstash.tar.gz

# Verify service
echo "Verifying installation..."
sleep 10
if systemctl is-active --quiet logstash; then
    echo "Logstash is running"
else
    echo "Logstash failed to start"
    exit 1
fi

echo "Logstash installation complete! Configured to receive Beats input on port 5044 and output to OpenSearch."