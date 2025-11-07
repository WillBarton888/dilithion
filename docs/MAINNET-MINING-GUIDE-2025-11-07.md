# Dilithion Mainnet Mining Guide

**Version:** 1.0.0
**Network:** Mainnet
**Mining Algorithm:** RandomX (CPU-friendly, ASIC-resistant)
**Launch Date:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

Complete guide to mining Dilithion (DIL) cryptocurrency using RandomX proof-of-work algorithm.

---

## Table of Contents

1. [Mining Overview](#mining-overview)
2. [Hardware Requirements](#hardware-requirements)
3. [Quick Start](#quick-start)
4. [Mining Configuration](#mining-configuration)
5. [Performance Optimization](#performance-optimization)
6. [Mining Rewards](#mining-rewards)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)
9. [Mining Economics](#mining-economics)

---

## Mining Overview

### What is RandomX?

RandomX is a **proof-of-work algorithm** designed to be:
- ✅ **CPU-friendly:** Optimized for general-purpose processors
- ✅ **ASIC-resistant:** Memory-hard algorithm prevents specialized hardware advantage
- ✅ **Fair:** Anyone with a CPU can mine competitively
- ✅ **Secure:** Randomized computation makes attacks expensive

**Key Features:**
- Memory requirement: ~2 GB per mining thread
- Cache-hard: Requires L3 cache access
- Favors modern CPUs with AVX2 instructions
- Designed for decentralization (The People's Coin philosophy)

### Why Mine Dilithion?

✅ **No ASICs:** Your CPU competes equally with everyone else
✅ **Post-Quantum Secure:** Future-proof cryptocurrency
✅ **Fair Launch:** No premine, no instamine, equal opportunity
✅ **Block Rewards:** 50 DIL per block (halving every 210,000 blocks)
✅ **Solo Mining:** Run your own node, keep all rewards

---

## Hardware Requirements

### Minimum Specifications

**CPU:** 2 cores (x64 architecture with AES-NI)
**RAM:** 6 GB (4 GB system + 2 GB per mining thread)
**Storage:** 50 GB available (for blockchain)
**Network:** 10+ Mbps stable connection
**Power:** Stable power supply

**Expected hashrate:** ~65-130 H/s (2 threads)

### Recommended Specifications

**CPU:** 8+ cores with AVX2 support
- Intel: Core i7-8700K, i9-9900K, or newer
- AMD: Ryzen 7 3700X, Ryzen 9 5900X, or newer
**RAM:** 16-32 GB DDR4-3200MHz or faster
**Cooling:** Quality air cooler or AIO liquid cooling
**Storage:** 100 GB+ NVMe SSD
**Power:** 650W+ PSU (80+ Gold or better)

**Expected hashrate:** ~500-1000 H/s (8 threads)

### High-Performance Mining Rig

**CPU:** AMD Ryzen 9 5950X (16 cores)
**RAM:** 64 GB DDR4-3600MHz CL16
**Motherboard:** X570 chipset with good VRM
**Cooling:** 280mm+ AIO liquid cooler
**Storage:** 500 GB NVMe SSD
**Power:** 850W+ PSU (80+ Platinum)

**Expected hashrate:** ~1600-2000 H/s (16 threads)

### CPU Comparison Table

| CPU Model | Cores/Threads | Expected H/s | Power (W) | Efficiency (H/s/W) |
|-----------|---------------|--------------|-----------|-------------------|
| Intel i5-12400F | 6/12 | ~450 H/s | 65W | 6.9 |
| Intel i7-12700K | 12/20 | ~900 H/s | 125W | 7.2 |
| AMD Ryzen 5 5600X | 6/12 | ~480 H/s | 65W | 7.4 |
| AMD Ryzen 7 5800X | 8/16 | ~700 H/s | 105W | 6.7 |
| AMD Ryzen 9 5900X | 12/24 | ~1100 H/s | 105W | 10.5 |
| AMD Ryzen 9 5950X | 16/32 | ~1800 H/s | 105W | 17.1 |

**Note:** Hashrates are approximate and vary with configuration

---

## Quick Start

### Step 1: Ensure Node is Running

**Verify node is synced:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```

**Check sync status:**
- `blocks` should equal network height
- `headers` should match `blocks`

### Step 2: Start Mining

**Basic mining (auto-detect CPU cores):**
```bash
./dilithion-node --mine
```

**Specify thread count:**
```bash
./dilithion-node --mine --threads=8
```

**Mining with custom data directory:**
```bash
./dilithion-node --mine --threads=8 --datadir=/path/to/data
```

### Step 3: Verify Mining is Active

**Check mining status:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

**Expected response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "mining": true,
    "threads": 8,
    "hashrate": 650.5,
    "blocks_found": 3,
    "difficulty": 1048576.0
  },
  "id": 1
}
```

**Monitor in real-time:**
```bash
watch -n 5 'curl -s -X POST http://localhost:8332 -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"getmininginfo\",\"params\":[],\"id\":1}" | jq .result'
```

---

## Mining Configuration

### Thread Optimization

**Rule of thumb:**
- **CPU cores - 1** for desktop use (leaves 1 core for system)
- **CPU cores** for dedicated mining rig
- **Never exceed CPU threads** (causes context switching overhead)

**Find your CPU thread count:**
```bash
# Linux
nproc

# macOS
sysctl -n hw.ncpu

# Windows (PowerShell)
$env:NUMBER_OF_PROCESSORS
```

**Example configurations:**

**4-core CPU (desktop use):**
```bash
./dilithion-node --mine --threads=3
```

**8-core CPU (dedicated mining):**
```bash
./dilithion-node --mine --threads=8
```

**16-core CPU (optimal):**
```bash
./dilithion-node --mine --threads=16
```

### Memory Configuration

**RandomX Memory Modes:**

1. **Fast Mode (Recommended):**
   - Uses ~2 GB per thread
   - Significantly faster
   - Requires sufficient RAM

2. **Light Mode (Low RAM):**
   - Uses ~256 MB per thread
   - Slower hashrate (~50% penalty)
   - Fallback for limited RAM

**Memory requirements:**

| Threads | Fast Mode RAM | Light Mode RAM |
|---------|---------------|----------------|
| 2 | 6 GB | 4 GB |
| 4 | 10 GB | 4.5 GB |
| 8 | 18 GB | 5 GB |
| 16 | 34 GB | 6 GB |

**The node auto-selects mode based on available RAM**

### Huge Pages (Linux - Performance Boost)

**Enable huge pages for ~10-15% hashrate increase:**

```bash
# Check current huge pages
cat /proc/meminfo | grep HugePages

# Calculate required pages (2MB each)
# Formula: (Threads * 2GB) / 2MB
# Example for 8 threads: (8 * 2048MB) / 2MB = 8192 pages

# Temporary (until reboot):
sudo sysctl -w vm.nr_hugepages=8192

# Permanent:
echo "vm.nr_hugepages=8192" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Verify huge pages allocated:**
```bash
cat /proc/meminfo | grep HugePages_Free
# Should show allocated pages
```

**Start mining with huge pages:**
```bash
./dilithion-node --mine --threads=8
# Node will automatically use huge pages if available
```

### CPU Affinity (Advanced)

**Pin mining threads to specific CPU cores:**

```bash
# Install numactl
sudo apt install numactl

# Run mining on specific cores (e.g., cores 0-7)
numactl --physcpubind=0-7 ./dilithion-node --mine --threads=8
```

**Benefits:**
- Reduces cache thrashing
- Improves thermal distribution
- Better for NUMA systems

---

## Performance Optimization

### BIOS/UEFI Settings

**For maximum hashrate:**

1. **Enable Precision Boost Overdrive (AMD) or Turbo Boost (Intel)**
   - Increases clock speeds under load

2. **Set Power Plan to "Performance"**
   - BIOS: Power Management → Performance mode
   - OS: High Performance power plan

3. **Enable XMP/DOCP for RAM**
   - Runs RAM at rated speeds (e.g., 3200MHz)

4. **Disable C-States (optional, increases power usage)**
   - Prevents CPU from downclocking

5. **SMT/Hyper-Threading: Enabled**
   - RandomX benefits from simultaneous threads

### Operating System Optimization

**Linux:**

```bash
# Set CPU governor to performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable CPU idle states (keeps max clocks)
sudo cpupower idle-set -D 0

# Increase process priority
sudo nice -n -20 ./dilithion-node --mine --threads=8
```

**Windows:**

1. Power Options → High Performance
2. Advanced → Processor power management → Minimum 100%
3. Run Dilithion as Administrator (higher priority)

**macOS:**

```bash
# Prevent sleep during mining
caffeinate -i ./dilithion-node --mine --threads=8
```

### Cooling Optimization

**CPU temperature directly affects hashrate:**

| Temperature | Performance |
|-------------|-------------|
| <70°C | 100% hashrate |
| 70-80°C | 95-100% (thermal throttling begins) |
| 80-90°C | 80-95% (moderate throttling) |
| >90°C | <80% (heavy throttling or shutdown) |

**Cooling solutions:**

1. **Clean dust from heatsink** (easiest improvement)
2. **Replace thermal paste** (Arctic MX-5, Thermal Grizzly)
3. **Improve case airflow** (intake + exhaust fans)
4. **Upgrade cooler:**
   - Air: Noctua NH-D15, be quiet! Dark Rock Pro 4
   - AIO: Arctic Liquid Freezer II 280mm+

**Monitor temperatures:**
```bash
# Linux
sensors

# Windows
# Use HWInfo64, Core Temp, or AIDA64

# macOS
# Use iStat Menus or Intel Power Gadget
```

### Monitoring Performance

**Check hashrate:**
```bash
watch -n 2 'curl -s -X POST http://localhost:8332 -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"getmininginfo\",\"params\":[],\"id\":1}" | jq .result.hashrate'
```

**Check CPU usage:**
```bash
htop
# Look for dilithion-node process
```

**Check memory usage:**
```bash
free -h
# Ensure enough RAM available
```

---

## Mining Rewards

### Block Reward Schedule

**Initial reward:** 50 DIL per block
**Block time:** 4 minutes (average)
**Halving interval:** Every 210,000 blocks (~1.6 years)

| Block Range | Reward per Block | Timeframe |
|-------------|------------------|-----------|
| 0 - 209,999 | 50 DIL | Year 1-2 |
| 210,000 - 419,999 | 25 DIL | Year 2-3 |
| 420,000 - 629,999 | 12.5 DIL | Year 3-5 |
| 630,000 - 839,999 | 6.25 DIL | Year 5-6 |

**Total supply:** 21,000,000 DIL (max)

### Coinbase Maturity

**Mining rewards require 100 confirmations before spending**

- **Maturity time:** 100 blocks × 4 minutes = ~6.7 hours
- **Why:** Prevents orphaned block reward spending
- **Safety:** Ensures reward is on main chain

**Check immature balance:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":["*", 0],"id":1}'
```

### Transaction Fees

**Miners also receive transaction fees from blocks**

- Fee calculation: Sum of (inputs - outputs) for all transactions
- Average fees: Varies with network usage
- High-fee transactions prioritized by miners

---

## Mining Economics

### Profitability Calculation

**Formula:**
```
Daily DIL = (Your Hashrate / Network Hashrate) × Daily Blocks × Block Reward

Daily Blocks = (24 hours × 60 minutes) / 4 minutes = 360 blocks
```

**Example (at network launch):**

Your hashrate: 800 H/s
Network hashrate: 10,000 H/s (estimated)
Block reward: 50 DIL

```
Daily DIL = (800 / 10,000) × 360 × 50 = 1,440 DIL
```

**Network hashrate grows over time, reducing individual share**

### Power Costs

**Example calculation:**

CPU: AMD Ryzen 9 5900X
Power consumption: 105W (mining)
Electricity cost: $0.12/kWh
Daily cost: 105W × 24h × $0.12 = $0.302

**Compare to expected earnings at current DIL price**

### Solo vs Pool Mining

**Solo Mining (Current Default):**
- ✅ Keep 100% of block rewards
- ✅ No pool fees
- ✅ True decentralization
- ❌ Irregular payouts (variance)
- ❌ May wait days/weeks for block (on small hashrate)

**Pool Mining (Future):**
- ✅ Regular, predictable payouts
- ✅ Lower variance
- ❌ Pool fees (typically 1-3%)
- ❌ Slight centralization risk

**Recommendation for network launch:** Solo mine to support decentralization

---

## Monitoring

### Real-Time Dashboard

**Create monitoring script** (`monitor_mining.sh`):

```bash
#!/bin/bash
while true; do
    clear
    echo "==================================="
    echo "  Dilithion Mining Monitor"
    echo "==================================="
    echo ""

    # Get mining info
    MINING_INFO=$(curl -s -X POST http://localhost:8332 \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}' | jq -r '.result')

    echo "Mining: $(echo $MINING_INFO | jq -r '.mining')"
    echo "Threads: $(echo $MINING_INFO | jq -r '.threads')"
    echo "Hashrate: $(echo $MINING_INFO | jq -r '.hashrate') H/s"
    echo "Blocks Found: $(echo $MINING_INFO | jq -r '.blocks_found')"
    echo "Difficulty: $(echo $MINING_INFO | jq -r '.difficulty')"
    echo ""

    # Get balance
    BALANCE=$(curl -s -X POST http://localhost:8332 \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}' | jq -r '.result')

    echo "Balance: $BALANCE DIL"
    echo ""

    # CPU temperature (Linux)
    if command -v sensors &> /dev/null; then
        TEMP=$(sensors | grep 'Package id 0' | awk '{print $4}')
        echo "CPU Temp: $TEMP"
    fi

    sleep 5
done
```

**Run monitor:**
```bash
chmod +x monitor_mining.sh
./monitor_mining.sh
```

### Log Analysis

**Check mining logs:**
```bash
tail -f ~/.dilithion/debug.log | grep -i mining
```

**Look for:**
- `[Mining] Thread X started` - Mining active
- `[Mining] Block found! Height: XXX` - Successful block
- `[Mining] Hashrate: XXX H/s` - Performance metrics

---

## Troubleshooting

### Mining Not Starting

**Issue:** Mining flag set but no hashing

**Solutions:**

1. **Check node is synced:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getblockchaininfo","params":[],"id":1}'
```
Mining doesn't start until fully synced.

2. **Verify mining command:**
```bash
ps aux | grep dilithion-node
# Should show --mine flag
```

3. **Check RPC response:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

4. **Restart with mining:**
```bash
# Stop node
pkill dilithion-node

# Start with mining
./dilithion-node --mine --threads=8
```

### Low Hashrate

**Expected hashrate not achieved**

**Diagnose:**

1. **Check CPU throttling:**
```bash
# Linux
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq

# Should be near max frequency
```

2. **Check temperature:**
```bash
sensors
# If >80°C, thermal throttling likely
```

3. **Verify thread count:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}' | jq .result.threads
```

4. **Check for huge pages (Linux):**
```bash
cat /proc/meminfo | grep HugePages_Free
# Should show allocated pages
```

5. **Background processes:**
```bash
top
# Check if other programs using CPU
```

**Solutions:**
- Clean CPU cooler
- Enable huge pages
- Close background applications
- Increase fan speeds
- Verify AVX2 support: `cat /proc/cpuinfo | grep avx2`

### Memory Errors

**Issue:** "Failed to allocate RandomX dataset"

**Cause:** Insufficient RAM for fast mode

**Solutions:**

1. **Reduce mining threads:**
```bash
./dilithion-node --mine --threads=4
# Requires less memory
```

2. **Close memory-intensive applications:**
```bash
# Free up RAM
```

3. **Add swap space (emergency, slower):**
```bash
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

4. **Upgrade RAM** (recommended for serious mining)

### Invalid Block Errors

**Issue:** "Block rejected - invalid proof of work"

**Causes:**
- System clock incorrect
- Stale block (someone else found same height)
- Corrupted blockchain database

**Solutions:**

1. **Sync system clock:**
```bash
# Linux
sudo ntpdate pool.ntp.org

# Or enable NTP
sudo timedatectl set-ntp true
```

2. **Verify blockchain integrity:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"verifychain","params":[],"id":1}'
```

3. **Check peer connections:**
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getpeerinfo","params":[],"id":1}'
# Ensure 8+ peers
```

### High Orphan Rate

**Issue:** Finding blocks but they're getting orphaned

**Causes:**
- Poor network connectivity
- Slow block propagation
- Low peer count

**Solutions:**

1. **Increase peer connections:**

Edit `~/.dilithion/dilithion.conf`:
```ini
maxconnections=125
```

2. **Ensure port forwarding:**
- Forward port 8444 on router
- Allows incoming connections

3. **Check internet speed:**
```bash
speedtest-cli
# Need stable, low-latency connection
```

4. **Add reliable seed nodes:**
```ini
addnode=seed1.dilithion.org:8444
addnode=seed2.dilithion.org:8444
```

---

## Advanced Topics

### Mining on Multiple Machines

**Coordinate mining across multiple computers:**

1. **Run full node on main machine**
2. **Use RPC to control remote miners** (future feature)
3. **Each machine mines to same wallet**

**Benefits:**
- Scale hashrate across hardware
- Geographic distribution
- Redundancy

### Benchmark Mode

**Test optimal thread count:**

```bash
for threads in 2 4 6 8 10 12 14 16; do
    echo "Testing $threads threads..."
    ./dilithion-node --mine --threads=$threads &
    PID=$!
    sleep 60
    curl -s -X POST http://localhost:8332 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}' | jq .result.hashrate
    kill $PID
done
```

**Find sweet spot for your hardware**

---

## Next Steps

**Your Dilithion mining operation is now running!** ⛏️

### Continue Learning:

1. **[Node Setup Guide](MAINNET-NODE-SETUP-2025-11-07.md)** - Optimize your full node
2. **[Wallet Guide](MAINNET-WALLET-GUIDE-2025-11-07.md)** - Manage your mining rewards
3. **[Troubleshooting](TROUBLESHOOTING-2025-11-07.md)** - Solve common issues

### Join Mining Community:

- **Discord #mining channel:** https://discord.gg/c25WwRNg
- **Mining subreddit:** r/dilithion (coming soon)
- **Hardware optimization discussions**
- **Share your hashrates and setups**

### Maximize Rewards:

✅ Run mining 24/7 for consistent blocks
✅ Monitor temperatures and optimize cooling
✅ Keep node updated to latest version
✅ Maintain good network connectivity (8+ peers)

**Happy mining! May the hash be with you!** ⚡

---

**Document Version:** 1.0.0
**Mainnet Launch:** January 1, 2026 00:00:00 UTC
**Last Updated:** November 7, 2025

---

*Dilithion - The People's Coin - Fair CPU Mining for Everyone* 🛡️⛏️
