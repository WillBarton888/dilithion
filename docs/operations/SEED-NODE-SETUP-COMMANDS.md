# VPS Seed Node Setup - Quick Reference

**VPS IP**: 170.64.203.134
**Date**: October 28, 2025

---

## Phase 1: Initial Build (User Running Now)

```bash
ssh root@170.64.203.134

# System setup
apt update && apt upgrade -y
apt install -y build-essential git cmake libleveldb-dev wget curl

# Clone and build
cd /root
git clone https://github.com/WillBarton888/dilithion.git
cd dilithion

# Build dependencies
cd depends/randomx && mkdir -p build && cd build
cmake .. && make -j$(nproc)
cd ../../..

cd depends/dilithium/ref && make
cd ../../..

# Build node
make dilithion-node
./dilithion-node --help
```

**Expected time**: 5-10 minutes

---

## Phase 2: Configure Systemd Service (After Build)

```bash
# Create service file
cat > /etc/systemd/system/dilithion-seed.service << 'EOF'
[Unit]
Description=Dilithion Testnet Seed Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dilithion
ExecStart=/root/dilithion/dilithion-node --datadir=/root/.dilithion --port=8444 --rpcport=8332
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dilithion-seed

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable dilithion-seed
systemctl start dilithion-seed

# Check status
systemctl status dilithion-seed
```

---

## Phase 3: Configure Firewall

```bash
# Allow SSH (critical - don't lock yourself out!)
ufw allow 22/tcp

# Allow P2P port
ufw allow 8444/tcp

# Enable firewall
ufw --force enable

# Verify
ufw status
```

---

## Phase 4: Monitor & Verify

```bash
# Check service status
systemctl status dilithion-seed

# View logs (live)
journalctl -u dilithion-seed -f

# View last 50 lines
journalctl -u dilithion-seed -n 50

# Check if port is listening
netstat -tulpn | grep 8444

# Test RPC locally
curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getinfo","params":[],"id":1}'

# Check peer connections (from outside)
# (Run this from your local machine)
telnet 170.64.203.134 8444
```

---

## Phase 5: Maintenance Commands

```bash
# Restart node
systemctl restart dilithion-seed

# Stop node
systemctl stop dilithion-seed

# Start node
systemctl start dilithion-seed

# View status
systemctl status dilithion-seed

# Update to latest version
cd /root/dilithion
systemctl stop dilithion-seed
git pull origin main
make clean
make dilithion-node
systemctl start dilithion-seed
```

---

## Expected Results

### Service Status (should show):
```
● dilithion-seed.service - Dilithion Testnet Seed Node
     Loaded: loaded (/etc/systemd/system/dilithion-seed.service; enabled)
     Active: active (running) since...
```

### Logs (should show):
```
Dilithion Node v1.0.0
Post-Quantum Cryptocurrency
======================================
Network: MAINNET
Data directory: /root/.dilithion
P2P port: 8444
RPC port: 8332

Initializing blockchain storage...
  ✓ Blockchain database opened
...
Starting P2P networking server...
  ✓ P2P server listening on port 8444
```

### Port Check (should show):
```
tcp        0      0 0.0.0.0:8444      0.0.0.0:*       LISTEN      12345/dilithion-nod
```

---

## Troubleshooting

### Service won't start
```bash
# Check logs
journalctl -u dilithion-seed -n 100 --no-pager

# Check file permissions
ls -la /root/dilithion/dilithion-node

# Test manually
cd /root/dilithion
./dilithion-node --help
```

### Port not listening
```bash
# Check if service is running
systemctl status dilithion-seed

# Check firewall
ufw status

# Check port binding
ss -tulpn | grep 8444
```

### Can't connect from outside
```bash
# Test locally first
telnet localhost 8444

# Check firewall
ufw status | grep 8444

# Check DigitalOcean firewall (in dashboard)
```

---

## Seed Node Information

Once running, share this info with miners:

**Seed Node Connection String**:
```bash
--addnode=170.64.203.134:8444
```

**Example Usage** (for testnet users):
```bash
./dilithion-node --addnode=170.64.203.134:8444 --mine --threads=4
```

---

## Performance Expectations

- **CPU Usage**: 5-10% (no mining)
- **Memory**: 500-700 MB
- **Bandwidth**: ~0.25 Mbps
- **Disk**: <1 GB for blockchain
- **Connections**: Up to 117 inbound peers

---

## Security Notes

1. **SSH Key**: Recommend setting up SSH key authentication
2. **Root Password**: Change default password
3. **Firewall**: Only ports 22 (SSH) and 8444 (P2P) open
4. **RPC**: NOT exposed to internet (localhost only)
5. **Updates**: Run `apt update && apt upgrade` weekly

---

## Monitoring Script

Create `/root/check_seed.sh`:
```bash
#!/bin/bash
echo "=== Dilithion Seed Node Status ==="
echo ""
echo "Service Status:"
systemctl is-active dilithion-seed
echo ""
echo "Recent Logs:"
journalctl -u dilithion-seed -n 20 --no-pager | tail -10
echo ""
echo "Connections:"
ss -tn | grep :8444 | wc -l
echo ""
echo "Disk Usage:"
du -sh /root/.dilithion
```

Make executable:
```bash
chmod +x /root/check_seed.sh
```

Run:
```bash
./check_seed.sh
```

---

## Cost

**DigitalOcean Droplet**: $5-6/month
- 1 vCPU
- 1 GB RAM
- 25 GB SSD
- 1 TB bandwidth

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
