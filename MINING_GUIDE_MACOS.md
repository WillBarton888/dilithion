# Mining Dilithion on macOS

This guide covers mining both **DIL** and **DilV** on macOS.

**DIL** uses RandomX (CPU mining) — more CPU power = better odds.
**DilV** uses VDF (fair distribution) — every computer has equal odds.

You can mine both at the same time!

---

## What You Need

- macOS 10.13 (High Sierra) or newer
- 4 GB RAM minimum for DIL (RandomX uses ~2.5 GB), 1 GB for DilV only
- 1 GB free disk space
- Internet connection
- Intel or Apple Silicon Mac (Apple Silicon runs via Rosetta 2 — works fine, just slightly slower)

---

## One-Time Setup: Install LevelDB

Open **Terminal** (Applications → Utilities → Terminal) and run these commands:

**Install Homebrew** (if you don't already have it):
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Install LevelDB:**
```
brew install leveldb
```

You only need to do this once.

---

## Mining DIL (RandomX)

### Step 1: Download

Go to **https://github.com/dilithion/dilithion/releases/latest**

Download: `dilithion-vX.X.X-mainnet-macos-x64.tar.gz`

### Step 2: Extract

Open Terminal and run:
```
cd ~/Downloads
tar -xzf dilithion-v*-mainnet-macos-x64.tar.gz
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

**macOS Gatekeeper warning?** If you see "unidentified developer":
1. Go to **System Settings → Privacy & Security**
2. Scroll down — you'll see a message about `dilithion-node` being blocked
3. Click **"Open Anyway"**
4. Run the script again

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

**Back up this file!** Copy it somewhere safe. If you lose it, you lose your DIL.
```
cp ~/.dilithion/wallet.dat ~/Desktop/wallet-dil-backup.dat
```

### What to Expect

- **Block time:** ~4 minutes (network average)
- **Block reward:** 49 DIL per block you find (50 DIL base reward minus 2% mining tax)
- **CPU usage:** High — fans will spin up. Normal for RandomX mining.
- **Threads:** Auto-detected by default (recommended). For manual control:
  ```
  ./dilithion-node --mine --threads=4
  ```
  Start with auto and adjust — fewer threads if your computer feels sluggish, more if you want to dedicate the machine to mining.

---

## Mining DilV (VDF)

### Step 1: Download

Go to **https://github.com/dilithion/dilithion/releases/latest**

Download: `dilv-vX.X.X-mainnet-macos-x64.tar.gz` (separate download from DIL)

### Step 2: Extract

```
cd ~/Downloads
tar -xzf dilv-v*-mainnet-macos-x64.tar.gz
cd dilv-v*
chmod +x *.sh dilv-node check-wallet-balance
```

### Step 3: Start Mining

```
./start-mining.sh
```

Or `./setup-and-start.sh` for the setup wizard.

**Same Gatekeeper process** as DIL if you get the "unidentified developer" warning.

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
cp ~/.dilv/wallet.dat ~/Desktop/wallet-dilv-backup.dat
```

### What to Expect

- **Block time:** ~45 seconds (network average)
- **Block reward:** 98 DilV per block you find (100 DilV base reward minus 2% mining tax)
- **CPU usage:** Moderate — VDF uses one CPU core, computing each proof takes 4-11 seconds
- **Fair distribution:** A MacBook Air has the same odds as a Mac Studio

---

## Running Both at the Same Time

Open two Terminal windows:

**Terminal 1 (DIL):**
```
cd ~/Downloads/dilithion-v*
./start-mining.sh
```

**Terminal 2 (DilV):**
```
cd ~/Downloads/dilv-v*
./start-mining.sh
```

They use different ports and data directories — no conflicts. DilV only uses one CPU core, so it has minimal impact on your DIL mining.

**Tip:** By default each chain creates its own wallet. If you want to use the same wallet for both, you can either copy your `wallet.dat` into the other chain's data directory, or import your 24-word recovery phrase when setting up the second chain.

**Tip:** Use `screen` or `tmux` to keep them running in the background:
```
screen -S dil ./start-mining.sh
```
Detach with Ctrl+A then D. Reattach with `screen -r dil`.

---

## Stopping the Miner

Press **Ctrl+C** in the Terminal window. The node saves its state and shuts down cleanly.

**Don't just close Terminal** — always use Ctrl+C to avoid database issues.

---

## Troubleshooting

**"unidentified developer" / macOS blocks the app**
- System Settings → Privacy & Security → scroll down → click "Open Anyway"
- You may need to do this for each binary (`dilithion-node`, `check-wallet-balance`, etc.)

**"Library not loaded: libleveldb" error**
- Install LevelDB: `brew install leveldb`
- If you already installed it, try: `brew reinstall leveldb`

**"No peers found" / 0 connections**
- Check your internet connection
- DIL uses port 8444, DilV uses port 9444
- macOS firewall: System Settings → Network → Firewall → allow the miner

**Sync is stuck or very slow**
- Make sure you have at least 4 GB of free RAM
- Check disk space — need at least 1 GB free
- Try restarting the miner

**Balance shows 0**
- Wait for the node to fully sync first
- Mined blocks need a few confirmations before showing up
- DIL wallet is in `~/.dilithion/wallet.dat` — DilV wallet is in `~/.dilv/wallet.dat` (different directories by default)

**Not finding any blocks**
- Keep the miner running. Your first block may take hours.
- DilV has better odds since blocks come every 45 seconds
- Make sure you see mining messages in the Terminal output

**Apple Silicon (M1/M2/M3/M4) performance**
- The binary runs through Rosetta 2 translation — this works fine
- Slightly slower than native, but perfectly functional
- A native Apple Silicon build is planned for the future

**"Mining not available from datacenter/VPN IPs" (DilV only)**
- If you're using a VPN or proxy, you'll need to temporarily disable it for the one-time MIK registration step. Most VPN services route through datacenter infrastructure, which triggers Sybil attack protection.
- **What to do:** Disable your VPN → restart the node → let it complete registration → re-enable your VPN. Mining continues normally after.
- Your residential IP is only shared with the 4 project-operated seed nodes during registration — it is not stored on-chain or visible to other miners.

**"Block found" but not showing on explorer (DilV)**
- Occasionally your node finds a block but another miner's block wins the race. Your wallet may briefly show the reward, but it disappears after a few confirmations. This is normal — you haven't lost anything.

---

## Useful Links

- **Releases:** https://github.com/dilithion/dilithion/releases
- **Website:** https://dilithion.org
- **Web Wallet:** https://dilithion.org/wallet.html
- **Mining Calculator:** https://dilithion.org/mining-calculator.html
- **Discord:** Ask in #mining for help!
