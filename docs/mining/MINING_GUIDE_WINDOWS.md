# Mining Dilithion on Windows

This guide covers mining both **DIL** and **DilV** on Windows.

**DIL** uses RandomX (CPU mining) — more CPU power = better odds.
**DilV** uses VDF (fair distribution) — every computer has equal odds.

You can mine both at the same time!

---

## What You Need

- Windows 10 or newer (64-bit)
- 4 GB RAM minimum for DIL (RandomX uses ~2.5 GB), 1 GB for DilV only
- 1 GB free disk space
- Internet connection

---

## Mining DIL (RandomX)

### Step 1: Download

Go to **https://github.com/dilithion/dilithion/releases/latest**

Download: `dilithion-vX.X.X-mainnet-windows-x64.zip`

### Step 2: Extract

Right-click the `.zip` file → **Extract All** → choose a folder (e.g. your Desktop).

**Important:** Extract ALL files. The `.dll` files in the zip are required — the miner won't work without them.

### Step 3: Start Mining

Double-click **`START-MINING.bat`** — that's it! A terminal window opens and mining begins.

Or double-click **`SETUP-AND-START.bat`** for a step-by-step setup wizard (recommended for first-time users).

### Step 4: Wait for Sync

The node needs to download the blockchain first. You'll see:
```
Downloading blocks... height 1000/35000
```
This takes 10-30 minutes depending on your internet speed.

Once synced, the node will register your miner identity (MIK). You'll see:
```
[Mining] First-time setup: Registering miner identity...
[Mining] This is a one-time process. Mining starts automatically after.
```
This is a one-time proof-of-work computation that can take 30 minutes or more. It only happens on your very first run — don't close the window! Once complete, mining starts automatically:
```
[Mining] Miner identity registered successfully!
Mining block at height 35001...
```

### Step 5: Check Your Balance

Open **`wallet.html`** from the same folder in your browser. This connects to your running node and shows your balance, addresses, and transaction history.

Your wallet file is at: `C:\Users\YourName\AppData\Roaming\.dilithion\wallet.dat`

**Back up this file!** Copy it to a USB drive or cloud storage. If you lose it, you lose your DIL.

### What to Expect

- **Block time:** ~4 minutes (network average)
- **Block reward:** 49 DIL per block you find (50 DIL base reward minus 2% mining tax)
- **CPU usage:** High — your fans will spin up. This is normal.
- **Threads:** The miner auto-detects how many cores to use (recommended). For manual control:
  ```
  dilithion-node.exe --mine --threads=4
  ```
  Start with auto and adjust — fewer threads if your computer feels sluggish, more if you want to dedicate the machine to mining.

---

## Mining DilV (VDF)

### Step 1: Download

Go to **https://github.com/dilithion/dilithion/releases/latest**

Download: `dilv-vX.X.X-mainnet-windows-x64.zip` (separate download from DIL)

### Step 2: Extract

Right-click the `.zip` file → **Extract All** → choose a **different folder** from your DIL miner.

**Important:** Extract ALL files — the `.dll` files are required.

### Step 3: Start Mining

Double-click **`START-DILV-MINING.bat`**

Or double-click **`SETUP-DILV.bat`** for the setup wizard.

### Step 4: Wait for Sync

DilV syncs faster than DIL — usually just a few minutes.

Once synced, the node will register your miner identity (MIK) — a one-time process that can take 30 minutes or more. Don't close the window! Mining starts automatically after:
```
[Mining] Miner identity registered successfully!
VDF mining started...
Computing VDF proof for height 5001...
```

### Step 5: Check Your Balance

Open **`wallet.html`** from the DilV folder in your browser. Make sure you switch to the DilV chain in the wallet interface (DilV uses port 9332, not 8332).

Your DilV wallet file is at: `C:\Users\YourName\AppData\Roaming\.dilv\wallet.dat` (different from your DIL wallet!)

**Back up this file too!**

### What to Expect

- **Block time:** ~45 seconds (network average)
- **Block reward:** 98 DilV per block you find (100 DilV base reward minus 2% mining tax)
- **CPU usage:** Moderate — VDF uses one CPU core, computing each proof takes 4-11 seconds
- **Fair distribution:** Your odds are the same whether you have a cheap laptop or an expensive PC

---

## Running Both at the Same Time

1. Open the DIL folder → double-click `START-MINING.bat`
2. Open the DilV folder → double-click `START-DILV-MINING.bat`

Two terminal windows will run side by side. They use different ports and data directories, so they don't interfere with each other. DilV only uses one CPU core, so it has minimal impact on your DIL mining.

**Tip:** By default each chain creates its own wallet. If you want to use the same wallet for both, you can either copy your `wallet.dat` into the other chain's data directory, or import your 24-word recovery phrase when setting up the second chain.

---

## Stopping the Miner

Click on the terminal window and press **Ctrl+C**. The node saves its state and shuts down cleanly.

**Don't just close the window** — always use Ctrl+C to avoid database issues.

---

## Troubleshooting

**Miner won't start / crashes immediately**
- Make sure you extracted ALL files from the zip, including the 6 `.dll` files
- Make sure you're running 64-bit Windows 10 or newer
- Try right-clicking the `.exe` → "Run as administrator"

**Windows Defender blocks the file**
- Click "More info" → "Run anyway"
- Or add the folder to Windows Defender exclusions: Settings → Virus & threat protection → Exclusions

**"No peers found" / 0 connections**
- Check your internet connection
- Windows Firewall may be blocking it — when prompted, click "Allow access"
- DIL uses port 8444, DilV uses port 9444

**Sync is stuck or very slow**
- Make sure you have at least 4 GB of free RAM
- Check disk space — need at least 1 GB free
- Try restarting the miner
- If the chain state is truly wedged, reset chain data only:
  ```
  dilithion-node.exe --reset-chain
  ```
  (or `dilv-node.exe --reset-chain` for DilV). Wipes `blocks/`, `chainstate/`, `headers/`, `dna_registry/`, `dfmp_identity/`, `mempool.dat`. **Preserves** `wallet.dat`, `mik_registration.dat` (saves ~25 min MIK PoW on re-sync), `peers.dat`, configs. Add `--yes` to skip the `RESET` confirmation prompt in scripts.

**Balance shows 0**
- Wait for the node to fully sync first
- Mined blocks need a few confirmations before they show up
- Make sure you're checking the right chain's data directory (DIL and DilV store wallets in different locations by default)

**"Another instance is running" / lock file error**
- Only one instance of each miner can run at a time
- Check Task Manager for `dilithion-node.exe` or `dilv-node.exe` and end any leftover processes
- Or delete the lock file at `C:\Users\YourName\AppData\Roaming\.dilithion\blocks\LOCK` (DIL) or `C:\Users\YourName\AppData\Roaming\.dilv\blocks\LOCK` (DilV)

**High CPU / computer is hot**
- Expected for DIL mining! Reduce threads: `dilithion-node.exe --mine --threads=1`
- DilV uses one CPU core for VDF computation. It shouldn't max out your whole system — if it does, restart the miner.

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
