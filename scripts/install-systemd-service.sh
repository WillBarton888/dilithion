#!/bin/bash
# Dilithion Systemd Service Installation Script
# Installs and configures systemd service for node auto-restart
#
# Usage: ./scripts/install-systemd-service.sh [THREADS]
#   THREADS: Number of mining threads (default: 2 for NYC, 1 for others)

set -e  # Exit on error

# Configuration
SERVICE_NAME="dilithion-testnet"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SOURCE_FILE="systemd/dilithion-testnet.service"

# Get thread count from argument or default to 2
THREADS=${1:-2}

echo "=== Dilithion Systemd Service Installer ==="
echo "Service: $SERVICE_NAME"
echo "Threads: $THREADS"
echo ""

# Check if source file exists
if [ ! -f "$SOURCE_FILE" ]; then
    echo "ERROR: Source service file not found: $SOURCE_FILE"
    echo "Run this script from the dilithion root directory"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root"
    echo "Usage: sudo $0 [THREADS]"
    exit 1
fi

# Copy service file
echo "[1/5] Copying service file to $SERVICE_FILE..."
cp "$SOURCE_FILE" "$SERVICE_FILE"

# Set correct thread count if not default
if [ "$THREADS" != "2" ]; then
    echo "[2/5] Configuring $THREADS mining thread(s)..."
    sed -i "s/--threads=2/--threads=$THREADS/" "$SERVICE_FILE"
else
    echo "[2/5] Using default 2 mining threads..."
fi

# Reload systemd
echo "[3/5] Reloading systemd daemon..."
systemctl daemon-reload

# Enable service for auto-start on boot
echo "[4/5] Enabling service for auto-start..."
systemctl enable "$SERVICE_NAME.service"

# Show service status
echo "[5/5] Service installation complete!"
echo ""
echo "=== Service Status ==="
systemctl status "$SERVICE_NAME.service" --no-pager || true
echo ""
echo "=== Next Steps ==="
echo "To transition from nohup to systemd:"
echo "  1. Find current PID: ps aux | grep dilithion-node"
echo "  2. Graceful stop: kill -TERM <PID>"
echo "  3. Wait 10 seconds for clean shutdown"
echo "  4. Start service: systemctl start $SERVICE_NAME.service"
echo "  5. Monitor logs: journalctl -u $SERVICE_NAME.service -f"
echo ""
echo "Service Commands:"
echo "  Start:   systemctl start $SERVICE_NAME.service"
echo "  Stop:    systemctl stop $SERVICE_NAME.service"
echo "  Restart: systemctl restart $SERVICE_NAME.service"
echo "  Status:  systemctl status $SERVICE_NAME.service"
echo "  Logs:    journalctl -u $SERVICE_NAME.service -f"
