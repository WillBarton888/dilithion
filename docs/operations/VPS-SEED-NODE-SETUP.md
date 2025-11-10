# VPS Seed Node Setup Guide

Complete guide for setting up a reliable Dilithion testnet seed node on a VPS.

---

## Why Run a Seed Node?

**Benefits:**
- Help the Dilithion testnet grow
- Enable easier peer discovery for new users
- Recognition as an early contributor
- Listed in official seed node documentation

**Requirements:**
- $5-10/month VPS cost
- 30 minutes setup time
- Basic Linux knowledge

---

## Step 1: Choose a VPS Provider

### Recommended Providers (Sydney/Australia Region)

**DigitalOcean** (Recommended)
- Cost: $6/month (Basic Droplet)
- Location: Sydney datacenter
- RAM: 1GB (sufficient for testnet)
- Disk: 25GB SSD
- Sign up: https://www.digitalocean.com/

**Linode (Akamai)**
- Cost: $5/month (Nanode)
- Location: Sydney datacenter
- RAM: 1GB
- Disk: 25GB SSD
- Sign up: https://www.linode.com/

**Vultr**
- Cost: $6/month (Regular Cloud Compute)
- Location: Sydney datacenter
- RAM: 1GB
- Disk: 25GB SSD
- Sign up: https://www.vultr.com/

**AWS Lightsail**
- Cost: $5/month (smallest instance)
- Location: Singapore (closest to Australia)
- RAM: 1GB
- Disk: 20GB SSD
- Sign up: https://aws.amazon.com/lightsail/

### Minimum Requirements
- **RAM**: 2GB (1GB works but 2GB recommended)
- **Disk**: 20GB
- **Bandwidth**: Unmetered or 1TB+ per month
- **OS**: Ubuntu 20.04 LTS or Ubuntu 22.04 LTS
- **Network**: Static IP address (included with all VPS)

---

## Step 2: Create VPS Instance

### DigitalOcean Example (Other providers similar)

1. **Create Account**
   - Sign up at https://www.digitalocean.com/
   - Add payment method
   - Verify email

2. **Create Droplet**
   - Click "Create" → "Droplets"
   - Choose image: **Ubuntu 22.04 LTS**
   - Choose plan: **Basic → $6/month (1GB RAM)**
   - Choose datacenter: **Sydney**
   - Authentication: **SSH keys** (recommended) or Password
   - Hostname: `dilithion-seed-1`
   - Click "Create Droplet"

3. **Note Your IP Address**
   - Wait 1-2 minutes for droplet to start
   - Copy the IP address (e.g., `203.0.113.45`)
   - This is your seed node IP

---

## Step 3: Connect to VPS

### On Windows (PowerShell/WSL)

```powershell
# Replace with your VPS IP
ssh root@203.0.113.45
```

### On Mac/Linux

```bash
# Replace with your VPS IP
ssh root@203.0.113.45
```

### First-Time Connection
- Type `yes` when asked about host authenticity
- Enter password (if using password authentication)

---

## Step 4: Initial Server Setup

### Update System

```bash
# Update package list
apt update

# Upgrade installed packages
apt upgrade -y

# Install essential tools
apt install -y build-essential git cmake wget curl
```

### Create Dedicated User (Optional but Recommended)

```bash
# Create dilithion user
adduser dilithion

# Add to sudo group
usermod -aG sudo dilithion

# Switch to dilithion user
su - dilithion
```

---

## Step 5: Install Dependencies

### Install Build Tools

```bash
# Install g++ compiler
sudo apt install -y g++ gcc make

# Install CMake
sudo apt install -y cmake

# Install LevelDB
sudo apt install -y libleveldb-dev
```

### Verify Installations

```bash
g++ --version
cmake --version
```

---

## Step 6: Clone and Build Dilithion

### Clone Repository

```bash
# Navigate to home directory
cd ~

# Clone Dilithion repository
git clone https://github.com/WillBarton888/dilithion.git

# Enter directory
cd dilithion
```

### Build RandomX Dependency

```bash
cd depends/randomx
mkdir build && cd build
cmake ..
make
cd ~/dilithion
```

### Build Dilithium Dependency

```bash
cd depends/dilithium/ref
make
cd ~/dilithion
```

### Build Dilithion Node

```bash
# Compile dilithion-node
make dilithion-node

# Verify binary exists
ls -lh dilithion-node
```

**Expected output:**
```
-rwxr-xr-x 1 dilithion dilithion 2.5M Oct 28 12:34 dilithion-node
```

---

## Step 7: Configure Firewall

### Open Required Ports

```bash
# Enable UFW firewall
sudo ufw enable

# Allow SSH (IMPORTANT - do this first!)
sudo ufw allow 22/tcp

# Allow Dilithion P2P port
sudo ufw allow 8444/tcp

# Check status
sudo ufw status
```

**Expected output:**
```
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
8444/tcp                   ALLOW       Anywhere
```

### ⚠️ IMPORTANT Security Notes

**DO NOT expose RPC port (8445/8332) to the internet!**

RPC should only be accessible from localhost for security:
- DO NOT run: `sudo ufw allow 8445/tcp`
- DO NOT run: `sudo ufw allow 8332/tcp`

If you need remote RPC access:
1. Use SSH tunneling instead
2. Set up RPC authentication
3. Use a VPN

---

## Step 8: Start Dilithion Node

### Run Node in Foreground (Testing)

```bash
cd ~/dilithion

# Start node (testnet mode)
./dilithion-node
```

### Verify It's Running

You should see output like:
```
[INFO] Dilithion node starting...
[INFO] Loading blockchain from LevelDB...
[INFO] Genesis block loaded
[INFO] Starting P2P server on port 8444
[INFO] Listening for connections...
```

**Press Ctrl+C to stop** (after testing)

### Run Node in Background (Production)

```bash
# Start as background process
nohup ./dilithion-node > dilithion.log 2>&1 &

# Check it's running
ps aux | grep dilithion-node

# View logs
tail -f dilithion.log
```

---

## Step 9: Create Systemd Service (Recommended)

### Why Use Systemd?
- Automatic restart if node crashes
- Starts on server reboot
- Easy to manage (start/stop/status)

### Create Service File

```bash
sudo nano /etc/systemd/system/dilithion-node.service
```

### Paste This Configuration

```ini
[Unit]
Description=Dilithion Testnet Seed Node
After=network.target

[Service]
Type=simple
User=dilithion
WorkingDirectory=/home/dilithion/dilithion
ExecStart=/home/dilithion/dilithion/dilithion-node
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dilithion-node

[Install]
WantedBy=multi-user.target
```

**Save and exit:** Ctrl+X, then Y, then Enter

### Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable dilithion-node

# Start service now
sudo systemctl start dilithion-node

# Check status
sudo systemctl status dilithion-node
```

### Manage Service

```bash
# Start
sudo systemctl start dilithion-node

# Stop
sudo systemctl stop dilithion-node

# Restart
sudo systemctl restart dilithion-node

# View logs (live)
sudo journalctl -u dilithion-node -f

# View logs (last 100 lines)
sudo journalctl -u dilithion-node -n 100
```

---

## Step 10: Monitor Your Seed Node

### Check Node Status

```bash
# Check if process is running
ps aux | grep dilithion-node

# Check open ports
sudo netstat -tulpn | grep 8444

# Check peer connections
./dilithion-cli getpeerinfo
```

### Check Logs

```bash
# If using systemd
sudo journalctl -u dilithion-node -f

# If using nohup
tail -f ~/dilithion/dilithion.log
```

### Monitor Resource Usage

```bash
# CPU and memory usage
htop

# Disk usage
df -h

# Network usage
iftop
```

---

## Step 11: Register as Official Seed Node

### Share Your IP

1. **Get your public IP:**
   ```bash
   curl ifconfig.me
   ```

2. **Post in GitHub Discussions:**
   - Go to: https://github.com/WillBarton888/dilithion/discussions
   - Find "Dilithion Testnet Launch - Join Here!" thread
   - Post:
     ```
     Running seed node:
     IP: YOUR_IP:8444
     Location: Sydney, Australia
     Provider: DigitalOcean
     Uptime commitment: 99%+
     ```

3. **Update TESTNET-LAUNCH.md:**
   - Fork repository
   - Add your IP to seed node list
   - Submit pull request

---

## Step 12: Maintenance & Monitoring

### Daily Checks (5 minutes)

```bash
# Check node is running
sudo systemctl status dilithion-node

# Check peer count (should be 1+)
./dilithion-cli getnetworkinfo

# Check blockchain syncing
./dilithion-cli getblockcount
```

### Weekly Checks (10 minutes)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Check disk space (should have 10GB+ free)
df -h

# Check logs for errors
sudo journalctl -u dilithion-node -n 500 | grep -i error

# Restart if needed
sudo systemctl restart dilithion-node
```

### Update Dilithion (When New Release)

```bash
# Stop node
sudo systemctl stop dilithion-node

# Update code
cd ~/dilithion
git pull

# Rebuild
make clean
make dilithion-node

# Restart node
sudo systemctl start dilithion-node

# Check status
sudo systemctl status dilithion-node
```

---

## Troubleshooting

### Node Not Starting

```bash
# Check logs
sudo journalctl -u dilithion-node -n 100

# Check if port is already in use
sudo netstat -tulpn | grep 8444

# Check if binary exists
ls -lh ~/dilithion/dilithion-node

# Try running manually
cd ~/dilithion
./dilithion-node
```

### No Peer Connections

```bash
# Check firewall
sudo ufw status

# Verify port 8444 is open
sudo netstat -tulpn | grep 8444

# Test external connectivity
# (run from your local machine)
telnet YOUR_VPS_IP 8444
```

### High CPU Usage

```bash
# Check if mining is enabled (shouldn't be for seed nodes)
./dilithion-cli getmininginfo

# Stop mining if enabled
./dilithion-cli stopmining

# Monitor CPU
htop
```

### Out of Disk Space

```bash
# Check disk usage
df -h

# Check blockchain size
du -sh ~/.dilithion/

# If needed, expand disk or clean up
sudo apt autoremove -y
sudo apt clean
```

---

## Cost Estimate

### Monthly Costs

| Provider | Plan | Cost/Month | Location |
|----------|------|------------|----------|
| DigitalOcean | Basic Droplet | $6 | Sydney |
| Linode | Nanode | $5 | Sydney |
| Vultr | Regular | $6 | Sydney |
| AWS Lightsail | Smallest | $5 | Singapore |

**Total: ~$5-6/month**

### Annual Cost: ~$60-72/year

**Benefits:**
- Support Dilithion testnet
- Learn VPS management
- Recognition in project documentation
- First to know about mainnet seed node opportunities

---

## Security Best Practices

### Essential Security

1. **Use SSH Keys** (not passwords)
2. **Keep system updated** (weekly)
3. **Enable firewall** (UFW)
4. **Don't expose RPC** to internet
5. **Monitor logs** for unusual activity

### Optional But Recommended

6. **Change SSH port** from 22 to custom port
7. **Install fail2ban** to prevent brute force
8. **Set up automatic security updates**
9. **Enable 2FA** on VPS provider account
10. **Regular backups** (though testnet data is not critical)

---

## Quick Reference

### Essential Commands

```bash
# Start node
sudo systemctl start dilithion-node

# Stop node
sudo systemctl stop dilithion-node

# Restart node
sudo systemctl restart dilithion-node

# Check status
sudo systemctl status dilithion-node

# View logs (live)
sudo journalctl -u dilithion-node -f

# Get peer info
./dilithion-cli getpeerinfo

# Get blockchain info
./dilithion-cli getblockchaininfo

# Get network info
./dilithion-cli getnetworkinfo
```

### File Locations

- **Dilithion directory:** `~/dilithion/`
- **Node binary:** `~/dilithion/dilithion-node`
- **Blockchain data:** `~/.dilithion/`
- **Systemd service:** `/etc/systemd/system/dilithion-node.service`
- **Logs:** `sudo journalctl -u dilithion-node`

---

## Next Steps

1. **Set up your VPS** (30 minutes)
2. **Install and start node** (30 minutes)
3. **Register as seed node** (5 minutes)
4. **Monitor daily** (5 minutes/day)
5. **Update weekly** (10 minutes/week)

---

## Support & Questions

- **GitHub Discussions:** https://github.com/WillBarton888/dilithion/discussions
- **GitHub Issues:** https://github.com/WillBarton888/dilithion/issues
- **Email:** will@bananatree.com.au (for seed node operators)

---

## Thank You!

By running a seed node, you're helping build the foundation for Dilithion's testnet. Your contribution is valuable and will be recognized in the project documentation.

**You'll be listed in:**
- TESTNET-LAUNCH.md (seed node operators section)
- SEED-NODE-OPERATORS.md (when created)
- GitHub discussions acknowledgments

---

**Ready to launch your seed node?** 🚀

Start with Step 1: Choose a VPS provider above!

**Questions?** Ask in GitHub Discussions!

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
