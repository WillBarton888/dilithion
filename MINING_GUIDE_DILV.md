# Mining DilV - Getting Started Guide

## What is DilV?

DilV is Dilithion's second chain — a **VDF (Verifiable Delay Function)** distribution chain. Unlike traditional mining where more CPU power = more blocks, DilV uses a fair distribution system. Every miner computes a VDF proof, and the **lowest output wins** the block.

This means a cheap laptop has the same chance of winning a block as an expensive server.

- **Block time:** ~45 seconds
- **Block reward:** 98 DilV (100 DilV base minus 2% mining tax)
- **Algorithm:** VDF (fair distribution — CPU power doesn't matter)
- **Max supply:** 210,000,000 DilV

---

## Step 1: Download the DilV Miner

Go to the latest release:
**https://github.com/dilithion/dilithion/releases/latest**

Download the **DilV** file for your operating system:

| OS | File |
|----|------|
| Windows | `dilv-vX.X.X-mainnet-windows-x64.zip` |
| macOS | `dilv-vX.X.X-mainnet-macos-x64.tar.gz` |
| Linux | `dilv-vX.X.X-mainnet-linux-x64.tar.gz` |

> **Note:** DilV is a separate download from DIL. If you want to mine both, download both packages.

---

## Step 2: Extract the Files

**Windows:** Right-click the `.zip` file → "Extract All" → Choose a folder (e.g. your Desktop)

**macOS/Linux:** Open a terminal in your Downloads folder and run:
```
tar -xzf dilv-v*-mainnet-*.tar.gz
```

---

## Step 3: Start Mining

### Windows (Easiest)
1. Open the extracted folder
2. Double-click **`START-DILV-MINING.bat`**
3. That's it! A window will open and mining begins

**Or** double-click **`SETUP-DILV.bat`** for an interactive setup wizard.

### macOS
1. Open Terminal
2. Navigate to the extracted folder:
   ```
   cd ~/Downloads/dilv-v*
   ```
3. Make the scripts executable and run:
   ```
   chmod +x *.sh dilv-node
   ./start-mining.sh
   ```

> **First time on macOS?** You'll need LevelDB installed first:
> ```
> /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
> brew install leveldb
> ```

### Linux
1. Open a terminal
2. Navigate to the extracted folder:
   ```
   cd ~/Downloads/dilv-v*
   ```
3. Install dependencies (one time only):
   - **Ubuntu/Debian:** `sudo apt-get install libleveldb-dev libsnappy-dev`
   - **Fedora:** `sudo dnf install leveldb-devel snappy-devel`
   - **Arch:** `sudo pacman -S leveldb snappy`
4. Make executable and run:
   ```
   chmod +x *.sh dilv-node
   ./start-mining.sh
   ```

---

## Step 4: Wait for Sync

When you first start the node, it needs to download the blockchain. You'll see messages like:

```
Connecting to seed nodes...
Downloading blocks... height 1000/5000
```

**DilV syncs faster than DIL** because blocks are smaller. Usually just a few minutes.

Once synced, you'll see VDF mining messages:

```
VDF mining started...
Computing VDF proof for height 5001...
```

---

## Step 5: Check Your Balance

Your wallet is created automatically when you first run the miner. To check your balance:

**Windows:** Double-click `check-wallet-balance.exe`

**macOS/Linux:** Run `./check-wallet-balance` in the same folder

Your DilV wallet file is stored at:
- **Windows:** `C:\Users\YourName\.dilv\wallet.dat`
- **macOS/Linux:** `~/.dilv/wallet.dat`

> **IMPORTANT: Back up your `wallet.dat` file!** If you lose it, you lose your DilV. Copy it to a USB drive or cloud storage.

> **Note:** DilV has a separate wallet from DIL. They use different data directories (`.dilv` vs `.dilithion`).

---

## Advanced: Command Line Options

If you want more control, run the node directly:

```
./dilv-node --mine
```

| Option | What it does |
|--------|-------------|
| `--mine` | Enable mining |
| `--quiet` or `-q` | Quiet mode — only shows block events (PRODUCED/CONFIRMED), errors, and warnings |
| `--verbose` or `-v` | Show detailed debug output (for troubleshooting) |

**You don't need to set threads for DilV!** Unlike DIL's RandomX mining, VDF only uses one core for the computation. More CPU power doesn't help you — it's fair distribution.

**Tip:** If the logs are too noisy, use `--quiet` for a cleaner experience. You'll still see when you produce a block and whether it's confirmed.

---

## What to Expect

- **Blocks come every ~45 seconds** on the network. Whether YOU win one depends on the VDF distribution.
- **It's fair** — a $200 laptop has the same chance as a $5,000 desktop. The VDF output is essentially random.
- **Each block you find = 98 DilV** sent to your wallet (2% mining tax goes to dev fund).
- **Low CPU usage** — VDF mining is very lightweight compared to RandomX. You can mine DilV without your fans spinning up.
- **You can mine DIL and DilV at the same time!** They use different ports and different data directories, so they don't interfere with each other.

---

## Mining Both DIL and DilV

You can run both miners simultaneously on the same computer:

1. Start DIL miner in one terminal window
2. Start DilV miner in another terminal window

They use separate:
- Data directories (`.dilithion` vs `.dilv`)
- Network ports (8444 vs 9444)
- Wallets (`wallet.dat` in each data dir)

DilV only uses one CPU core, so it has minimal impact on your DIL mining performance.

---

## Troubleshooting

### "No peers found" / "0 connections"
- Check your internet connection
- Make sure port **9444** isn't blocked by your firewall (note: different port from DIL!)
- Try restarting the node

### Node exits immediately / crashes on start
- **Windows:** Make sure you extracted ALL files from the zip (especially the `.dll` files)
- **macOS:** If you get "unidentified developer" warning: System Settings → Privacy & Security → click "Open Anyway"
- **Linux:** Make sure dependencies are installed (Step 3 above)

### Sync is stuck / very slow
- DilV blocks are small — sync should be fast. If stuck, try restarting.
- Check that you have a stable internet connection
- Make sure you have at least **1 GB free disk space**
- If the chain state is truly wedged, reset chain data only:
  ```
  ./dilv-node --reset-chain
  ```
  Wipes `blocks/`, `chainstate/`, `headers/`, `dna_registry/`, `dfmp_identity/`, `mempool.dat`. **Preserves** `wallet.dat`, `mik_registration.dat` (saves ~25 min MIK PoW on re-sync), `peers.dat`, configs. Add `--yes` to skip the `RESET` confirmation prompt in scripts.

### "wallet.dat not found" or balance shows 0
- The wallet is created on first run. If you just started, wait for the node to sync first.
- Balance only shows confirmed blocks
- **Remember:** DilV wallet is in `~/.dilv/`, NOT `~/.dilithion/`

### Not finding any blocks
- DilV is fair distribution — sometimes you win, sometimes you don't. Keep the miner running.
- Make sure you see "VDF mining" messages in the log (confirms you're participating)
- Check that your node is synced to the latest block

### "MIK registration" messages
- MIK (Mining Identity Key) is registered automatically — you don't need to do anything
- You may see messages about MIK registration when you first start. This is normal.
- The node handles everything for you

### "Mining not available from datacenter/VPN IPs"
- **If you're using a VPN or proxy**, you'll need to temporarily disable it for the one-time MIK registration step. Most VPN services route through datacenter infrastructure, which triggers Sybil attack protection.
- **What to do:** Disable your VPN → restart the node → let it complete MIK registration → re-enable your VPN. Mining will continue normally after registration.
- **Privacy note:** Your residential IP is only shared with the 4 project-operated seed nodes during registration. It is not stored on-chain or visible to other miners. After registration, you can mine through a VPN with no issues.
- This protection exists because the DilV chain was previously attacked by someone spinning up 100 VMs to take over block production.

### "Block found" but not on explorer (orphaned blocks)
- Sometimes your node finds a block, but another miner's block wins the race. Your local wallet may briefly show the reward, but it will disappear after a few confirmations when the network settles on the other miner's chain.
- This is normal blockchain behavior and happens occasionally to all miners. The reward was never confirmed — you haven't lost anything.

### Node won't start because another instance is running
- Only one DilV node can run at a time
- Check for a leftover lock file at `~/.dilv/blocks/LOCK`
- On Windows, check Task Manager for `dilv-node.exe`
- On macOS/Linux: `pgrep dilv-node`

---

## Stopping the Miner

Press **Ctrl+C** in the terminal/command window. The node will save its state and shut down gracefully. Don't just close the window — always use Ctrl+C.

---

## DilV vs DIL — Quick Comparison

| | DIL | DilV |
|---|-----|------|
| **Algorithm** | RandomX (CPU mining) | VDF (fair distribution) |
| **Block time** | ~4 minutes | ~45 seconds |
| **Block reward** | 49 DIL (2% tax) | 98 DilV (2% tax) |
| **CPU usage** | High (uses all assigned cores) | Low (single core, lightweight) |
| **Fairness** | More CPU = better odds | Equal odds for everyone |
| **Port** | 8444 | 9444 |
| **Data dir** | `~/.dilithion` | `~/.dilv` |

---

## Useful Links

- **Releases:** https://github.com/dilithion/dilithion/releases
- **Website:** https://dilithion.org
- **Web Wallet:** https://dilithion.org/wallet.html
- **Mining Calculator:** https://dilithion.org/mining-calculator.html
- **Discord:** Ask in #mining for help!
