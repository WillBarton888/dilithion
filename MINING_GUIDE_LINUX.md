# Mining Dilithion on Linux

This guide covers mining both **DIL** and **DilV** on Linux.

**DIL** uses RandomX (CPU mining) — more CPU power = better odds.
**DilV** uses VDF (fair distribution) — every computer has equal odds.

You can mine both at the same time!

---

## What You Need

- 64-bit Linux (Ubuntu 20.04+, Debian 11+, Fedora 36+, Arch, or similar)
- 4 GB RAM minimum for DIL (RandomX uses ~2.5 GB), 1 GB for DilV only
- 1 GB free disk space
- Internet connection

---

## One-Time Setup: Install Dependencies

**Ubuntu / Debian:**
```
sudo apt-get update
sudo apt-get install libleveldb-dev libsnappy-dev
```

**Fedora / RHEL:**
```
sudo dnf install leveldb-devel snappy-devel
```

**Arch Linux:**
```
sudo pacman -S leveldb snappy
```

You only need to do this once.

---

## Mining DIL (RandomX)

### Step 1: Download

Go to **https://github.com/dilithion/dilithion/releases/latest**

Download: `dilithion-vX.X.X-mainnet-linux-x64.tar.gz`

Or from the command line:
```
cd ~
wget https://github.com/dilithion/dilithion/releases/latest/download/dilithion-v4.0.6-mainnet-linux-x64.tar.gz
```

### Step 2: Extract

```
tar -xzf dilithion-v*-mainnet-linux-x64.tar.gz
cd dilithion-v*
chmod +x *.sh dilithion-node check-wallet-balance
```

### Step 3: Start Mining

```
./start-mining.sh
```

Or for the interactive setup wizard (recommended first time):
```
./setup-and-start.sh
```

### Step 4: Wait for Sync

The node downloads the blockchain first. You'll see:
```
Downloading blocks... height 1000/35000
```
This takes 10-30 minutes depending on your internet speed.

Once synced, the node will register your miner identity (MIK). You'll see:
```
[Mining] First-time setup: Registering miner identity...
[Mining] This is a one-time process. Mining starts automatically after.
```
This is a one-time proof-of-work computation that can take 30 minutes or more. It only happens on your very first run — don't close the terminal! Once complete, mining starts automatically:
```
[Mining] Miner identity registered successfully!
Mining block at height 35001...
```

### Step 5: Check Your Balance

Open **`wallet.html`** from the same folder in your browser. This connects to your running node and shows your balance, addresses, and transaction history.

Your wallet file is at: `~/.dilithion/wallet.dat`

**Back up this file!** If you lose it, you lose your DIL.
```
cp ~/.dilithion/wallet.dat ~/wallet-dil-backup.dat
```

### What to Expect

- **Block time:** ~4 minutes (network average)
- **Block reward:** 49 DIL per block you find (50 DIL base reward minus 2% mining tax)
- **CPU usage:** High — expected for RandomX mining
- **Threads:** Auto-detected by default. For manual control:
  ```
  ./dilithion-node --mine --threads=4
  ```
  Adjust based on how many cores you want to dedicate.

---

## Mining DilV (VDF)

### Step 1: Download

Go to **https://github.com/dilithion/dilithion/releases/latest**

Download: `dilv-vX.X.X-mainnet-linux-x64.tar.gz` (separate download from DIL)

Or from the command line:
```
cd ~
wget https://github.com/dilithion/dilithion/releases/latest/download/dilv-v4.0.6-mainnet-linux-x64.tar.gz
```

### Step 2: Extract

```
tar -xzf dilv-v*-mainnet-linux-x64.tar.gz
cd dilv-v*
chmod +x *.sh dilv-node check-wallet-balance
```

### Step 3: Start Mining

```
./start-mining.sh
```

Or `./setup-and-start.sh` for the setup wizard.

### Step 4: Wait for Sync

DilV syncs faster than DIL — usually just a few minutes.

Once synced, the node will register your miner identity (MIK) — a one-time process that can take 30 minutes or more. Don't close the terminal! Mining starts automatically after:
```
[Mining] Miner identity registered successfully!
VDF mining started...
Computing VDF proof for height 5001...
```

### Step 5: Check Your Balance

Open **`wallet.html`** from the DilV folder in your browser. Make sure you switch to the DilV chain in the wallet interface (DilV uses port 9332, not 8332).

Your DilV wallet file is at: `~/.dilv/wallet.dat` (different from your DIL wallet!)

**Back up this file too!**
```
cp ~/.dilv/wallet.dat ~/wallet-dilv-backup.dat
```

### What to Expect

- **Block time:** ~45 seconds (network average)
- **Block reward:** 98 DilV per block you find (100 DilV base reward minus 2% mining tax)
- **CPU usage:** Moderate — VDF uses one CPU core, computing each proof takes 4-11 seconds
- **Fair distribution:** A Raspberry Pi has the same odds as a server

---

## Running Both at the Same Time

**Option 1: Two terminal windows**

Terminal 1 (DIL):
```
cd ~/dilithion-v*
./start-mining.sh
```

Terminal 2 (DilV):
```
cd ~/dilv-v*
./start-mining.sh
```

**Option 2: Using screen (recommended for servers/VPS)**

```
# Start DIL miner in a screen session
screen -dmS dil bash -c 'cd ~/dilithion-v* && ./start-mining.sh'

# Start DilV miner in a screen session
screen -dmS dilv bash -c 'cd ~/dilv-v* && ./start-mining.sh'

# View running sessions
screen -ls

# Attach to DIL miner
screen -r dil

# Detach: press Ctrl+A then D
```

**Option 3: Using tmux**

```
tmux new-session -d -s dil 'cd ~/dilithion-v* && ./start-mining.sh'
tmux new-session -d -s dilv 'cd ~/dilv-v* && ./start-mining.sh'

# Attach: tmux attach -t dil
# Detach: Ctrl+B then D
```

They use different ports and data directories — no conflicts. DilV only uses one CPU core, so it has minimal impact on your DIL mining.

**Tip:** By default each chain creates its own wallet. If you want to use the same wallet for both, you can either copy your `wallet.dat` into the other chain's data directory, or import your 24-word recovery phrase when setting up the second chain.

---

## Running as a Systemd Service (Auto-Start on Boot)

To keep your miner running 24/7 and auto-restart on reboot:

```
sudo tee /etc/systemd/system/dilithion.service > /dev/null << 'EOF'
[Unit]
Description=Dilithion DIL Miner
After=network-online.target

[Service]
Type=simple
User=YOUR_USERNAME
ExecStart=/home/YOUR_USERNAME/dilithion-v4.0.6/dilithion-node --mine --threads=4
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

Replace `YOUR_USERNAME` and the path, then:
```
sudo systemctl daemon-reload
sudo systemctl enable dilithion
sudo systemctl start dilithion

# Check status
sudo systemctl status dilithion

# View logs
journalctl -u dilithion -f
```

Repeat with a separate service file for DilV if desired.

---

## Stopping the Miner

Press **Ctrl+C** in the terminal. The node saves its state and shuts down cleanly.

If running as a service: `sudo systemctl stop dilithion`

**Don't use `kill -9`** — always let the node shut down gracefully to avoid database corruption.

---

## Troubleshooting

**"error while loading shared libraries: libleveldb.so"**
- Install dependencies (see One-Time Setup above)
- If already installed, try: `sudo ldconfig`

**"No peers found" / 0 connections**
- Check your internet connection
- DIL uses port 8444, DilV uses port 9444
- Check firewall: `sudo ufw allow 8444` and `sudo ufw allow 9444`
- Or with firewalld: `sudo firewall-cmd --add-port=8444/tcp --permanent && sudo firewall-cmd --reload`

**"Permission denied"**
- Make sure files are executable: `chmod +x *.sh dilithion-node dilv-node check-wallet-balance`

**Sync is stuck or very slow**
- Check available RAM: `free -h` (need at least 4 GB for DIL's RandomX)
- Check disk space: `df -h` (need at least 1 GB free)
- Try restarting the miner

**Balance shows 0**
- Wait for the node to fully sync first
- Mined blocks need a few confirmations before showing up
- DIL wallet is in `~/.dilithion/wallet.dat` — DilV wallet is in `~/.dilv/wallet.dat` (different directories by default)

**"Another instance is running" / lock file error**
- Check for running processes: `pgrep -a dilithion` or `pgrep -a dilv`
- If no process is running, remove stale lock: `rm ~/.dilithion/blocks/LOCK` or `rm ~/.dilv/blocks/LOCK`

**Out of memory (OOM killed)**
- RandomX needs ~2.5 GB RAM. If you have 4 GB total, reduce threads: `--threads=1`
- Add swap space if needed:
  ```
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  ```

**VPS / headless server tips**
- Use `screen` or `tmux` so the miner keeps running after you disconnect
- Or set up the systemd service (see above)
- A $5/month VPS can mine DilV (VDF is lightweight)

**"Mining not available from datacenter/VPN IPs" (DilV only)**
- If you're using a VPN or proxy, you'll need to temporarily disable it for the one-time MIK registration step. Most VPN services route through datacenter infrastructure, which triggers Sybil attack protection.
- **What to do:** Disable your VPN → restart the node → let it complete registration → re-enable your VPN. Mining continues normally after.
- Your residential IP is only shared with the 4 project-operated seed nodes during registration — it is not stored on-chain or visible to other miners.
- **Note for VPS miners:** DilV mining from a VPS/datacenter will be blocked. DIL mining from a VPS is unaffected.

**"Block found" but not showing on explorer (DilV)**
- Occasionally your node finds a block but another miner's block wins the race. Your wallet may briefly show the reward, but it disappears after a few confirmations. This is normal — you haven't lost anything.

---

## Useful Links

- **Releases:** https://github.com/dilithion/dilithion/releases
- **Website:** https://dilithion.org
- **Web Wallet:** https://dilithion.org/wallet.html
- **Mining Calculator:** https://dilithion.org/mining-calculator.html
- **Discord:** Ask in #mining for help!
