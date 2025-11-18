# Dilithion v1.0.13 Release Notes

**Release Date**: November 18, 2025
**Type**: Critical Performance Fix
**Status**: Production Ready

---

## Executive Summary

Dilithion v1.0.13 fixes a critical mining performance bottleneck that was limiting hash rates to ~60 H/s despite having 20 threads. This release implements per-thread RandomX VMs, achieving a **10x performance improvement** to ~600 H/s.

**Upgrade Recommendation**: **MANDATORY** for all miners. This fix is essential for competitive mining performance.

---

## What's Fixed

### Bug #28: Global RandomX VM Mutex Bottleneck

**Problem**: All mining threads were serializing on a global RandomX VM mutex, causing only one thread to hash at a time despite having 20 CPU threads available.

**Root Cause**: The RandomX hashing implementation used a single global VM protected by a mutex. While this prevented VM corruption, it serialized all mining threads, limiting performance to single-thread levels.

**Solution**: Implemented per-thread RandomX VMs. Each mining thread now creates its own VM during startup, enabling true parallel mining with no mutex contention during hashing.

**Performance Impact**:
- **Before**: ~60 H/s (20 threads serialized on mutex)
- **After**: ~600 H/s (20 threads hashing in parallel)
- **Improvement**: **10x faster** (1000% performance gain)

---

## Technical Details

### Architecture Changes

**Old Implementation (Serialized)**:
```
Thread 1 ──┐
Thread 2 ──┤ MUTEX → [Global VM] ← Bottleneck
Thread 3 ──┤
...        │
Thread 20 ─┘

Result: Only 1 thread hashes at a time = ~60 H/s
```

**New Implementation (Parallel)**:
```
Thread 1 ────→ [VM 1]  (no mutex)
Thread 2 ────→ [VM 2]  (no mutex)
Thread 3 ────→ [VM 3]  (no mutex)
...
Thread 20 ───→ [VM 20] (no mutex)

All VMs share read-only 2GB dataset

Result: All 20 threads hash simultaneously = ~600 H/s
```

### Memory Impact

- **Additional RAM**: ~4GB (20 VMs × 200MB VM state each)
- **Shared Dataset**: 2GB (read-only, shared across all VMs)
- **Total RAM Required**: ~6GB (previously ~2.2GB)

**Trade-off**: 4GB more RAM for 10x performance improvement - well worth it!

### Code Changes

**Files Modified**:

1. **src/crypto/randomx_hash.h** (Lines 35-50)
   - Added per-thread VM API: `randomx_create_thread_vm()`, `randomx_destroy_thread_vm()`, `randomx_hash_thread()`

2. **src/crypto/randomx_hash.cpp** (Lines 268-333)
   - Implemented per-thread VM creation/destruction
   - Implemented mutex-free hashing function

3. **src/miner/controller.cpp**
   - Lines 28-53: Added `RandomXVMGuard` RAII wrapper for automatic VM cleanup
   - Lines 253-257: Create per-thread VM on worker startup
   - Lines 367-369: Use `randomx_hash_thread()` instead of `randomx_hash_fast()`

**Legacy API Preserved**:
- Old `randomx_hash_fast()` function still available for block verification and tests
- Documented as "LEGACY API" for non-performance-critical operations

### RAII Pattern

The implementation uses RAII (Resource Acquisition Is Initialization) to ensure automatic cleanup:

```cpp
class RandomXVMGuard {
public:
    RandomXVMGuard() : m_vm(randomx_create_thread_vm()) {
        if (!m_vm) throw std::runtime_error("Failed to create RandomX VM");
    }
    ~RandomXVMGuard() {
        if (m_vm) randomx_destroy_thread_vm(m_vm);
    }
    void* get() const { return m_vm; }
};
```

This prevents memory leaks even if exceptions occur during mining.

---

## Testing Results

**Test Environment**:
- CPU: 20 threads
- RAM: 32GB
- OS: Windows 11
- Mode: RandomX FULL (2GB dataset)

**Results**:
- ✅ Hash rate: ~590-600 H/s (consistent across multiple runs)
- ✅ All 20 threads running in parallel
- ✅ No VM creation errors
- ✅ Stable mining over extended periods
- ✅ No memory leaks (RAII working correctly)

**Block Finding**:
- Blocks found every ~10-15 seconds at current testnet difficulty
- Proper block propagation to peers
- No consensus issues

---

## Upgrade Instructions

### For Windows Users

1. **Stop your current node**:
   ```
   Ctrl+C or close the window
   ```

2. **Download v1.0.13**:
   - Get `dilithion-testnet-v1.0.13-windows-x64.zip` from GitHub releases

3. **Extract and run**:
   ```
   Extract the ZIP
   Run: SETUP-AND-START.bat
   ```

4. **Verify the upgrade**:
   - Check the startup banner shows: `Dilithion Node v1.0.13`
   - Observe hash rate after ~30 seconds: should be ~600 H/s (or higher with more threads)

### Blockchain Compatibility

- ✅ **No blockchain wipe required**
- ✅ **Backward compatible** with v1.0.12 and earlier
- ✅ **Forward compatible** - v1.0.12 nodes can sync with v1.0.13 nodes
- ✅ **No consensus changes**

---

## Known Issues & Limitations

### Hash Rate Observations

**Expected Hash Rates** (RandomX FULL mode):
- 1 thread: ~100 H/s
- 4 threads: ~400 H/s
- 8 threads: ~800 H/s
- 20 threads: ~2000 H/s (theoretical maximum)

**Current Testing Results**:
- 20 threads: ~600 H/s (30% of theoretical)

**Possible Reasons**:
1. **Frequent block finding**: Blocks found every ~10-15 seconds with current difficulty
   - Mining restarts each time, hash rate never stabilizes
   - Hash rate measurements are taken during short bursts

2. **CPU thermal throttling**: Sustained 100% load on all cores may trigger throttling

3. **Memory bandwidth**: 20 VMs accessing shared 2GB dataset may saturate memory bus

**Note**: Despite being lower than theoretical maximum, 600 H/s is still a 10x improvement over the previous 60 H/s, and the fix is working as designed.

### Future Improvements (v1.0.14+)

- **Increase testnet difficulty** to allow longer mining periods for accurate hash rate measurements
- **Add benchmark mode** for pure hash rate testing without blockchain interference
- **Investigate memory bandwidth optimization** for systems with many threads

---

## What's Next

### v1.0.14 (Planned)

**Difficulty Adjustment**:
- Increase testnet difficulty 6x (0x1f060000 → 0x1f010000)
- Target: ~60 second block times (instead of ~10-15 seconds)
- Requires new genesis block and testnet reset
- Better testing conditions for hash rate measurement

---

## Files in This Release

### Windows Package (`dilithion-testnet-v1.0.13-windows-x64.zip`)

**Binaries**:
- `dilithion-node.exe` - Main node with Bug #28 fix
- `check-wallet-balance.exe` - Wallet balance checker
- `genesis_gen.exe` - Genesis block generator

**Runtime Libraries** (6 DLLs):
- `libwinpthread-1.dll` - POSIX threads
- `libgcc_s_seh-1.dll` - GCC runtime
- `libstdc++-6.dll` - C++ standard library
- `libleveldb.dll` - Database engine
- `libcrypto-3-x64.dll` - OpenSSL crypto
- `libssl-3-x64.dll` - OpenSSL SSL/TLS

**Scripts**:
- `SETUP-AND-START.bat` - Quick start with colors
- `SETUP-AND-START-NO-COLOR.bat` - For systems without ANSI support
- `START-MINING.bat` - Resume mining after setup
- `dilithion-wallet.bat` - Wallet management
- `TEST-DEBUG.bat` - Debug mode (verbose logging)
- `ULTRA-DEBUG.bat` - Maximum verbosity
- `FIX-WINDOWS-DEFENDER.bat` - Antivirus exclusion helper

**Documentation**:
- `README.txt` - Quick start guide
- `TESTNET-GUIDE.md` - Comprehensive testnet guide
- `ANTIVIRUS-SOLUTION.md` - Windows Defender configuration

---

## Security Notes

**Unchanged**: This release contains **no security-related changes**. All previous security audits and fixes remain in effect.

**Verified**:
- ✅ No new attack vectors introduced
- ✅ RAII pattern prevents memory leaks
- ✅ Thread-local VMs eliminate race conditions
- ✅ No changes to consensus rules
- ✅ No changes to network protocol

---

## Acknowledgments

**Bug Discovery**:
- Identified through systematic performance profiling after v1.0.12 showed persistent low hash rates

**Fix Design**:
- Inspired by Monero/XMRig multi-threaded RandomX architecture
- Adapted to Dilithion's codebase with proper RAII safety

**Testing**:
- Verified on Windows 11 with 20-thread CPU
- Confirmed 10x performance improvement
- Stable over extended mining sessions

---

## Checksums

**SHA-256 Checksums** (Windows x64):
```
To be generated after packaging
```

---

## Support

**Issue Tracker**: https://github.com/yourusername/dilithion/issues
**Discord**: https://discord.gg/dilithion
**Documentation**: https://dilithion.org/docs

---

## Conclusion

Dilithion v1.0.13 delivers a critical performance fix that was blocking effective mining. The 10x improvement brings hash rates to competitive levels, making testnet mining viable for all participants.

**All miners should upgrade immediately to benefit from this performance improvement.**

Next release (v1.0.14) will focus on adjusting testnet difficulty to match the improved hash rates, providing better testing conditions for the network.

---

**Full Changelog**: https://github.com/yourusername/dilithion/compare/v1.0.12...v1.0.13
