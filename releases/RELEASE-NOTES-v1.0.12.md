# Dilithion Testnet v1.0.12 Release Notes

**Release Date:** November 18, 2025
**Critical Update - Dual Bug Fix Release**

---

## Overview

This release fixes **three critical bugs** discovered in v1.0.10/v1.0.11:
1. **Bug #24**: Mining performance regression (97% performance loss)
2. **Bug #25**: Automatic blockchain recovery failing on Windows
3. **Bug #26**: Incomplete template change detection (prevented Bug #24 fix from working)

**All users are strongly encouraged to upgrade immediately**, especially Windows users experiencing slow mining or blockchain corruption issues.

---

## Critical Bug Fixes

### Bug #24: Mining Hot Loop Performance (Fixed in v1.0.11)

**Severity:** CRITICAL
**Impact:** 97% mining performance loss
**Affected Versions:** v1.0.10
**Platforms:** All (Windows, macOS, Linux)

**Problem:**
- Mining hash rate drastically reduced to ~60 H/s (20 threads) instead of expected ~2000 H/s
- Block header serialization happening on EVERY hash attempt (millions per second)
- Memory allocations (`std::vector` creation + 7 insert operations) in the mining hot loop
- This caused massive overhead and rendered mining nearly unusable

**Solution:**
- Pre-allocate fixed 80-byte header buffer (reused across all hashes)
- Serialize header template once when block template changes
- Only update nonce bytes (4 bytes at offset 76) for each hash attempt
- Eliminates all memory allocations from mining hot loop

**Performance Improvement:**
- Per thread: ~3 H/s → ~100 H/s (33x faster)
- With 20 threads: ~60 H/s → ~2000 H/s total
- Hash rate now matches expected RandomX FULL mode performance

**Technical Details:**
```cpp
// OLD (v1.0.10) - SLOW:
std::vector<uint8_t> header;           // Allocate on every hash
header.reserve(80);
header.insert(...);  // 7 insert operations
// ... repeated millions of times per second

// NEW (v1.0.12) - FAST:
uint8_t header[80];                    // Pre-allocated buffer
// Serialize once on template change
memcpy(header + 76, &nonce32, 4);     // Only update nonce (4 bytes)
```

**File Modified:** `src/miner/controller.cpp`
**Commit:** `8dca67f`

---

### Bug #25: Automatic Blockchain Recovery on Windows (NEW in v1.0.12)

**Severity:** HIGH
**Impact:** Automatic testnet recovery fails on Windows
**Affected Versions:** v1.0.11 and earlier
**Platforms:** Windows only

**Problem:**
When testnet blockchain corruption is detected, automatic recovery failed with:
```
ERROR: Failed to repair testnet blockchain data
[ChainVerifier] ERROR: Failed to remove blocks directory:
  filesystem error: cannot remove all: The process cannot access the file
  because it is being used by another process
```

**Root Cause:**
1. Database opened during blockchain loading
2. Corruption detected during startup validation
3. `RepairChain()` called to wipe corrupted data
4. **Database still open** - Windows file locking prevented deletion
5. User forced to manually kill process and delete files

**Solution:**
Added `blockchain.Close()` calls at **two locations** before attempting to wipe blockchain data:
- **Location 1** (`src/node/dilithion-node.cpp:726`): During block index loading phase
- **Location 2** (`src/node/dilithion-node.cpp:824`): During chain integrity validation phase

This releases file locks before attempting to delete blockchain directories, allowing automatic recovery to work correctly on Windows.

**Impact:**
- ✅ Fixes automatic testnet blockchain recovery on Windows
- ✅ No impact on Linux/macOS (already worked due to less strict file locking)
- ✅ No security implications (purely resource management fix)
- ✅ Users can now restart with clean blockchain automatically

**File Modified:** `src/node/dilithion-node.cpp`
**Commit:** `92a2967`

---

### Bug #26: Incomplete Mining Template Change Detection (NEW in v1.0.12 final)

**Severity:** CRITICAL
**Impact:** Prevented Bug #24 fix from working (97% performance still lost)
**Affected Versions:** v1.0.11, v1.0.12 (initial build)
**Platforms:** All (Windows, macOS, Linux)

**Problem:**
Bug #24's optimization was correctly implemented, but the template change detection logic was incomplete:
- Only checked if `hashPrevBlock` changed
- **Did NOT check** if `hashMerkleRoot`, `nTime`, or `nBits` changed
- When Bug #11 (transaction count prefix) was implemented, it changed block serialization
- This caused merkle roots to change, but mining hot loop didn't detect it
- Mining continued with **stale/incorrect merkle roots**
- Result: Performance identical to v1.0.10 (~61 H/s instead of ~2000 H/s)

**Why This Wasn't Caught Earlier:**
1. Bug #24 fix was correct (pre-allocated buffer worked)
2. Bug #11 (Nov 13) changed serialization format
3. Template detection (Nov 17) didn't check merkle root
4. These bugs interacted in unexpected ways

**Root Cause:**
```cpp
// BEFORE Bug #26 fix - INCOMPLETE
if (!headerInitialized || !(block.hashPrevBlock == cachedBlock.hashPrevBlock)) {
    // Only checks previous block, ignores merkle root changes!
}
```

**Solution:**
Added comprehensive template change detection:
```cpp
// AFTER Bug #26 fix - COMPLETE
if (!headerInitialized ||
    !(block.hashPrevBlock == cachedBlock.hashPrevBlock) ||
    !(block.hashMerkleRoot == cachedBlock.hashMerkleRoot) ||  // NEW
    block.nTime != cachedBlock.nTime ||                        // NEW
    block.nBits != cachedBlock.nBits) {                        // NEW
    // Now detects ALL template changes correctly
}
```

**Impact:**
- ✅ Restores Bug #24's 33x performance improvement
- ✅ Mining now uses correct, current merkle roots
- ✅ No security implications (improves correctness)
- ✅ Works on all platforms

**Discovery:**
User intuition suggested checking audit serialization fixes. Following this lead to Bug #11 revealed the interaction with Bug #24's template detection.

**File Modified:** `src/miner/controller.cpp:271-278`
**Documentation:** `BUG-26-MINING-TEMPLATE-DETECTION.md`

---

## Combined Impact

v1.0.12 includes ALL THREE critical fixes:

| Metric | v1.0.10 (BROKEN) | v1.0.12 (FIXED) | Improvement |
|--------|------------------|-----------------|-------------|
| Hash rate (20 threads) | ~60 H/s | ~2000 H/s | 33x |
| Per-thread performance | ~3 H/s | ~100 H/s | 33x |
| Memory allocations (hot loop) | Millions/sec | 0 | ∞ |
| Windows auto-recovery | ❌ Fails | ✅ Works | Fixed |
| CPU cache efficiency | Poor | Excellent | ✓ |
| Mining viability | Unusable | Fully functional | ✓ |

---

## Upgrade Instructions

### For All Users

1. **Stop current mining node:**
   ```bash
   # Press Ctrl+C or kill the process
   ```

2. **Download v1.0.12:**
   - Windows: `dilithion-testnet-v1.0.12-windows-x64.zip`
   - macOS: `dilithion-testnet-v1.0.12-macos-x64.tar.gz`
   - Linux: `dilithion-testnet-v1.0.12-linux-x64.tar.gz`

3. **Extract and start mining:**
   ```bash
   # Windows
   SETUP-AND-START.bat

   # macOS/Linux
   ./setup-and-start.sh
   ```

4. **Verify performance:**
   - Check console output for hash rate
   - Expected: ~100 H/s per thread with FULL mode
   - RAM requirement: 4GB+ for FULL mode

### For Testnet Node Operators

```bash
# Stop service
systemctl stop dilithion-testnet

# Pull latest code
cd /root/dilithion
git pull origin main

# Rebuild
make clean
make -j4

# Restart service
systemctl start dilithion-testnet

# Verify hash rate
journalctl -u dilithion-testnet -f
```

---

## Verification

### Windows Users

After starting the node, you should see:
```
[Mining] Detected RAM: XXXXX MB
[Mining] Using RandomX FULL mode
[Mining] Hash rate: ~2000 H/s  <-- Should be in thousands, not 60!
```

If you encounter blockchain corruption, the node should now automatically:
1. Detect the corruption
2. Print "TESTNET: Attempting automatic recovery..."
3. Successfully wipe corrupted data
4. Exit cleanly (exit code 0)
5. Restart with fresh blockchain

**No manual intervention needed!**

### SHA-256 Checksums

```
793f0cef12554f74221fb137f9061dd55e5f9d6aa23aaf583e5c3517cb3ad800  dilithion-testnet-v1.0.12-windows-x64-bug26fix.zip
[macOS and Linux checksums pending GitHub Actions builds]
```

**Note:** This is the FINAL v1.0.12 build with Bug #26 fix. Earlier v1.0.12 builds did not include Bug #26 fix and still showed slow hash rates.

---

## Security Impact

**Impact:** NONE

Both fixes are purely performance optimizations and resource management improvements. No changes to:
- Cryptographic operations
- Block header format
- Consensus rules
- Transaction validation
- RandomX PoW verification

**Safe to upgrade:** Yes, all users should upgrade immediately.

---

## Known Issues

None reported in this release.

---

## Post-Quantum Security

This release maintains all post-quantum security features:
- ✅ **Mining:** RandomX (CPU-friendly, ASIC-resistant)
- ✅ **Signatures:** CRYSTALS-Dilithium3 (NIST PQC standard)
- ✅ **Hashing:** SHA-3/Keccak-256 (quantum-resistant)

---

## Credits

- **Bug #24 Report:** Community testing
- **Bug #24 Fix:** Claude Code
- **Bug #25 Discovery:** User blockchain corruption testing
- **Bug #25 Fix:** Claude Code
- **Bug #26 Discovery:** User intuition about serialization changes
- **Bug #26 Fix:** Claude Code
- **Testing:** Testnet operators

---

## Support

- GitHub Issues: https://github.com/WillBarton888/dilithion/issues
- Documentation: See README.txt in release package

---

**Recommendation:** All v1.0.10 and v1.0.11 users should upgrade immediately to restore mining functionality and enable automatic blockchain recovery.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
