#!/bin/bash
# Complete VPS Deployment Script
# Run this ONCE to set up everything

set -e

echo "========================================"
echo "Dilithion Testnet Seed Node Deployment"
echo "========================================"

# Step 1: Stop any existing service
echo "[1/7] Stopping existing service..."
systemctl stop dilithion-testnet 2>/dev/null || true

# Step 2: Kill any running processes
echo "[2/7] Cleaning up processes..."
killall -9 dilithion-node 2>/dev/null || true
sleep 2

# Step 3: Clean up lock files
echo "[3/7] Cleaning up lock files..."
rm -f /root/.dilithion-testnet/blocks/LOCK

# Step 4: Install dependencies
echo "[4/7] Installing dependencies..."
apt update -qq
apt install -y nginx dos2unix curl 2>&1 | grep -v "^Reading" || true

# Step 5: Set up systemd service
echo "[5/7] Setting up systemd service..."
cat > /etc/systemd/system/dilithion-testnet.service << 'EOF'
[Unit]
Description=Dilithion Testnet Seed Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dilithion
ExecStartPre=/bin/bash -c 'killall -9 dilithion-node 2>/dev/null || true'
ExecStartPre=/bin/bash -c 'rm -f /root/.dilithion-testnet/blocks/LOCK'
ExecStart=/root/dilithion-start.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Step 6: Set up stats generation
echo "[6/7] Setting up stats generation..."
mkdir -p /var/www/html

# Set up cron job (runs every minute)
crontab -l 2>/dev/null | grep -v generate-stats-robust.sh > /tmp/crontab.tmp || true
echo "* * * * * /root/generate-stats-robust.sh >/dev/null 2>&1" >> /tmp/crontab.tmp
crontab /tmp/crontab.tmp
rm /tmp/crontab.tmp

# Configure nginx for stats
cat > /etc/nginx/sites-available/default << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html;

    server_name _;

    location /network-stats.json {
        add_header Access-Control-Allow-Origin *;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires 0;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
EOF

# Step 7: Start everything
echo "[7/7] Starting services..."
systemctl daemon-reload
systemctl enable dilithion-testnet
systemctl start dilithion-testnet
systemctl restart nginx

# Enable firewall rules
ufw allow 18444/tcp 2>/dev/null || true
ufw allow 80/tcp 2>/dev/null || true

echo ""
echo "========================================"
echo "Deployment Complete!"
echo "========================================"
echo ""
echo "Checking status..."
sleep 5

systemctl status dilithion-testnet --no-pager | head -20

echo ""
echo "Testing stats generation..."
/root/generate-stats-robust.sh
if [ -f /var/www/html/network-stats.json ]; then
    echo "✓ Stats file generated successfully"
    cat /var/www/html/network-stats.json
else
    echo "⚠ Stats file not yet available (node may still be starting)"
fi

echo ""
echo "Seed node is running on port 18444"
echo "Stats available at: http://$(curl -s ifconfig.me)/network-stats.json"
echo ""
