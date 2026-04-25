# Dilithion Mining Guide

**Version:** 1.0.0
**Algorithm:** RandomX
**Last Updated:** October 25, 2025

---

## Table of Contents

1. [Introduction](#introduction)
2. [Mining Algorithm](#mining-algorithm)
3. [Getting Started](#getting-started)
4. [Performance Expectations](#performance-expectations)
5. [Optimization Tips](#optimization-tips)
6. [Mining Pools](#mining-pools)
7. [Profitability](#profitability)
8. [Troubleshooting](#troubleshooting)

---

## Introduction

Welcome to Dilithion mining! This guide will help you start mining Dilithion (DIL) using your CPU.

### Why Mine Dilithion?

✅ **CPU-Friendly:** RandomX is optimized for CPUs, not ASICs
✅ **Fair Distribution:** No ASIC advantage means fairer coin distribution
✅ **Energy Efficient:** Lower power consumption than GPU/ASIC mining
✅ **Post-Quantum Secure:** Future-proof cryptocurrency

### Mining Rewards

- **Block Reward:** 50 DIL per block (subject to halvings)
- **Block Time:** ~2 minutes (target)
- **Total Supply:** 21 million DIL
- **First Halving:** Block 210,000 (~8 months)

---

## Mining Algorithm

### RandomX

Dilithion uses **RandomX**, a proof-of-work algorithm designed to be:

- **CPU-friendly:** Optimized for modern x64 processors
- **ASIC-resistant:** Memory-hard, random code execution
- **Fair:** Equal opportunity for all miners

### Technical Details

- **Algorithm:** RandomX
- **Hash Function:** AES, SHA-3
- **Memory Requirement:** ~2GB per thread
- **Difficulty Adjustment:** Every 2016 blocks (~1 week)

---

## Getting Started

### Requirements

**Minimum:**
- CPU: 2 cores (Intel/AMD x64)
- RAM: 4GB
- Storage: 10GB free space
- OS: Linux, Windows (WSL2), macOS

**Recommended:**
- CPU: 8+ cores (modern processor)
- RAM: 16GB
- Cooling: Adequate CPU cooling
- Power: Reliable power supply

### Starting Solo Mining

**1. Run Node with Mining:**
```bash
./dilithion-node --mine
```

**2. Specify Thread Count:**
```bash
# Mine with 8 threads
./dilithion-node --mine --threads=8
```

**3. Use All CPU Cores:**
```bash
# Auto-detect and use all cores
./dilithion-node --mine --threads=$(nproc)
```

### Checking Mining Status

**Via RPC:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "mining": true,
    "hashrate": 520,
    "threads": 8
  },
  "id": 1
}
```

### Stopping Mining

```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"stopmining","params":[],"id":1}'
```

Or simply stop the node (Ctrl+C).

---

## Performance Expectations

### Hash Rate by CPU

| CPU Model | Cores | Hash Rate | Notes |
|-----------|-------|-----------|-------|
| **Intel Core i9-12900K** | 16 | ~1040 H/s | High-end desktop |
| **AMD Ryzen 9 5900X** | 12 | ~845 H/s | High-end desktop |
| **Intel Core i7-12700** | 12 | ~780 H/s | Mid-range desktop |
| **AMD Ryzen 7 5800X** | 8 | ~560 H/s | Mid-range desktop |
| **Intel Core i5-12400** | 6 | ~390 H/s | Budget desktop |
| **AMD Ryzen 5 5600X** | 6 | ~395 H/s | Budget desktop |
| **Intel Core i3-10100** | 4 | ~260 H/s | Entry-level |

**Average:** ~65 H/s per core

### Factors Affecting Hash Rate

1. **CPU Architecture**
   - Newer CPUs: Better RandomX performance
   - AVX2/AVX-512: Significant boost
   - Large L3 Cache: Better performance

2. **RAM Speed**
   - DDR4-3200+: Optimal
   - Dual Channel: +10-15% performance
   - Low latency: Slight improvement

3. **Thermal Throttling**
   - Keep temps under 80°C
   - Better cooling = sustained performance

4. **System Load**
   - Dedicated mining: Best performance
   - Background apps: Reduced hash rate
   - OS overhead: ~5-10% impact

### Expected Block Times

**Network Hash Rate Examples:**

| Network Hash Rate | Your Hash Rate | Avg. Time to Block |
|-------------------|----------------|---------------------|
| 10 KH/s | 500 H/s | ~40 minutes |
| 100 KH/s | 500 H/s | ~6.7 hours |
| 1 MH/s | 500 H/s | ~2.8 days |
| 10 MH/s | 500 H/s | ~28 days |

**Note:** These are averages. Actual time varies due to randomness.

---

## Optimization Tips

### 1. Use All CPU Cores

```bash
# Linux/macOS
./dilithion-node --mine --threads=$(nproc)

# Windows (WSL)
./dilithion-node --mine --threads=$(nproc)
```

### 2. Enable Large Pages (Linux)

Large pages improve RandomX performance by ~1-2%.

**Enable:**
```bash
sudo sysctl -w vm.nr_hugepages=1250
```

**Permanent (add to /etc/sysctl.conf):**
```
vm.nr_hugepages=1250
```

**Verify:**
```bash
cat /proc/meminfo | grep HugePages
```

### 3. CPU Affinity

Pin mining threads to specific cores for better cache utilization.

**Example (Linux):**
```bash
taskset -c 0-7 ./dilithion-node --mine --threads=8
```

### 4. Disable Hyperthreading (Optional)

For some CPUs, disabling SMT/Hyperthreading can improve per-core performance.

**Check if helpful:**
```bash
# Test with HT enabled
./dilithion-node --mine --threads=16

# Test with HT disabled (BIOS setting)
# Reboot and test again
```

### 5. Cooling Optimization

- **Clean dust:** Improves airflow
- **Reapply thermal paste:** Every 1-2 years
- **Improve case airflow:** More fans
- **Undervolt:** Reduce temps without losing performance

### 6. Power Management

**Linux - Disable CPU Frequency Scaling:**
```bash
sudo cpupower frequency-set -g performance
```

**Verify:**
```bash
cpupower frequency-info
```

### 7. Close Unnecessary Applications

Free up CPU resources:
- Close browsers
- Stop background services
- Disable antivirus scans during mining

---

## Mining Pools

### Solo vs Pool Mining

**Solo Mining:**
✅ Keep 100% of block rewards
✅ No pool fees
❌ Irregular payouts
❌ Requires patience

**Pool Mining:**
✅ Regular payouts
✅ Predictable income
❌ Pool fees (1-3%)
❌ Centralization risk

### Pool Mining Setup

**Note:** Pool mining requires pool software integration (coming soon).

**When Available:**
1. Choose a pool
2. Get pool address
3. Configure miner
4. Monitor earnings

### Recommended Pools

**Coming Soon:** Pool directory will be published post-launch.

---

## Profitability

### Calculating Profitability

**Formula:**
```
Daily Revenue = (Your Hash Rate / Network Hash Rate) × Blocks Per Day × Block Reward
```

**Example:**
- Your hash rate: 500 H/s
- Network hash rate: 100 KH/s (100,000 H/s)
- Blocks per day: 720 (144 blocks × 5 days)
- Block reward: 50 DIL

```
Daily DIL = (500 / 100,000) × 720 × 50 = 180 DIL
```

### Costs

**Electricity:**
- CPU Power: ~65-95W per 8-core CPU
- Full System: ~150-250W
- Cost/kWh: Varies by location ($0.05-0.30)

**Example Cost:**
- System power: 200W
- Mining 24/7: 4.8 kWh/day
- Electricity: $0.10/kWh
- **Daily cost: $0.48**

### Break-Even Analysis

Compare daily revenue (in USD) vs. electricity cost:

```
Break-even: Daily DIL Revenue > Daily Electricity Cost
```

**Note:** DIL price will fluctuate. Monitor profitability regularly.

---

## Troubleshooting

### Low Hash Rate

**Problem:** Getting much lower than expected hash rate

**Solutions:**
1. **Check CPU usage:**
   ```bash
   top
   # Should show 100% CPU usage
   ```

2. **Verify thread count:**
   ```bash
   # Check mining info
   curl http://localhost:8332 -X POST -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
   ```

3. **Check for thermal throttling:**
   ```bash
   # Linux
   sensors
   # Should be under 80°C
   ```

4. **Reduce threads if overheating:**
   ```bash
   ./dilithion-node --mine --threads=6
   ```

### Mining Not Starting

**Problem:** Mining doesn't start when using `--mine` flag

**Solutions:**
1. **Check logs:** Look for error messages at startup
2. **Verify RandomX:** Ensure dependencies are installed
3. **Check memory:** RandomX needs ~2GB RAM per thread
4. **Try fewer threads:**
   ```bash
   ./dilithion-node --mine --threads=2
   ```

### High CPU Temperature

**Problem:** CPU temperature exceeds 85°C

**Solutions:**
1. **Reduce thread count:**
   ```bash
   ./dilithion-node --mine --threads=4
   ```

2. **Improve cooling:**
   - Clean CPU cooler
   - Improve case airflow
   - Reapply thermal paste

3. **Undervolt CPU:**
   - Use BIOS or software tools
   - Reduce voltage by 50-100mV

4. **Limit power:**
   ```bash
   # Linux - limit CPU frequency
   sudo cpupower frequency-set -u 3.0GHz
   ```

### System Freezing

**Problem:** System becomes unresponsive during mining

**Solutions:**
1. **Reserve 1-2 cores for system:**
   ```bash
   # Total cores - 2
   ./dilithion-node --mine --threads=6  # If you have 8 cores
   ```

2. **Reduce RAM pressure:**
   - Close other applications
   - Upgrade RAM if possible

3. **Check for overheating:**
   - Monitor temperatures
   - Improve cooling

---

## Mining Statistics

### Monitoring Your Mining

**Real-Time Stats:**
```bash
# Watch mining output
./dilithion-node --mine | grep "Mining"
```

**Output:**
```
[Mining] Hash rate: 518 H/s, Total hashes: 5,180,000
[Mining] Hash rate: 521 H/s, Total hashes: 10,210,000
```

**Hash Rate Calculation:**
- Measured every 10 seconds
- Average over last period
- Updates automatically

### Tracking Blocks Found

When you find a block:
```
[Mining] ✅ BLOCK FOUND!
[Mining] Block hash: 000000abc...
[Mining] Reward: 50 DIL
```

---

## Advanced Topics

### Custom Difficulty

For testing or private networks:

**Low Difficulty (testing):**
```bash
# Edit genesis.h: const uint32_t NBITS = 0x1d7fffff;
# Rebuild and run
```

### Mining Pool Development

Interested in running a pool? See:
- Pool protocol documentation (coming soon)
- Stratum implementation guide
- Pool operator best practices

### FPGA/ASIC Resistance

RandomX is designed to resist FPGA and ASIC mining through:
- Random code execution
- Memory-hard algorithm
- Frequent memory access patterns
- Cache optimization benefits CPUs

---

## Community

### Join the Mining Community

- **Discord:** https://discord.gg/dilithion
- **Reddit:** /r/dilithion
- **Telegram:** @dilithionmining
- **Forum:** forum.dilithion.org

### Share Your Results

Help the community by sharing:
- Your CPU model
- Hash rate achieved
- Power consumption
- Optimizations used

---

## FAQ

**Q: Can I mine on a laptop?**
A: Yes, but watch temperatures. Laptops have limited cooling. Consider reducing threads.

**Q: Can I mine while using my computer?**
A: Yes, but reserve 1-2 cores for system tasks. Performance will be reduced.

**Q: Do I need a GPU?**
A: No! Dilithion uses CPU-only mining (RandomX).

**Q: How much can I earn?**
A: Depends on your hash rate, network difficulty, and DIL price. Calculate using the profitability formula.

**Q: Is mining Dilithion profitable?**
A: It depends on electricity costs and DIL market price. Calculate your costs first.

**Q: Can I mine to multiple addresses?**
A: Currently, mining rewards go to your first wallet address. Multiple address support coming soon.

**Q: How often will I find blocks?**
A: Depends on network hash rate. Solo mining with 500 H/s on a 100 KH/s network: ~1 block every 6-7 hours (average).

---

## Safety & Best Practices

### Electrical Safety

⚠️ **Never:**
- Overload power circuits
- Use damaged power cables
- Mine in poorly ventilated areas
- Leave mining unattended without monitoring

### Hardware Protection

✅ **Always:**
- Monitor temperatures
- Use surge protectors
- Ensure adequate cooling
- Clean dust regularly
- Check for unusual sounds/smells

### Fire Safety

- Keep clear of flammable materials
- Install smoke detectors
- Have fire extinguisher nearby
- Never block airflow

---

## Getting Help

**Issues with mining?**

1. Check [Troubleshooting](#troubleshooting) section
2. Review [USER-GUIDE.md](USER-GUIDE.md)
3. Visit community Discord
4. Open GitHub issue

**Performance questions?**

Share your setup on Discord:
- CPU model
- RAM specs
- OS version
- Hash rate
- Thread count

---

**Happy Mining!** ⛏️

Remember: Mining is a marathon, not a sprint. Be patient, optimize your setup, and enjoy being part of The People's Coin!
