# Dilithion Testnet v1.0.14 Release Notes

**Release Date:** November 18, 2025
**Type:** Testnet Difficulty Adjustment

## Overview

Version 1.0.14 increases testnet mining difficulty by 6x to achieve target block times of ~60 seconds, matching the improved hash rates from the Bug #28 fix in v1.0.13.

## What's Changed

### Genesis Block Update
- **New Difficulty:** `0x1f010000` (6x harder than v1.0.13)
- **Genesis Nonce:** 15178
- **Genesis Hash:** `0000ee281e9c4a9216ed662146da376ff20fd2b3cc516bc4346cedb2a330e6d3`
- **Target Block Time:** ~60 seconds (with ~600 H/s network hash rate)

### Why This Update?

After v1.0.13's Bug #28 fix (per-thread RandomX VMs), mining hash rates increased from ~60 H/s to ~600 H/s (10x improvement). With the previous difficulty of `0x1f060000`, blocks were being found every ~10 seconds, which is too fast for realistic testnet operation.

**v1.0.14 adjusts difficulty to restore proper block timing:**
- Old difficulty (v1.0.13): `0x1f060000` → ~10 second blocks @ 600 H/s
- New difficulty (v1.0.14): `0x1f010000` → ~60 second blocks @ 600 H/s

## Technical Details

### Difficulty Calculation
```
Old target: 0x060000... (difficulty = 0x1f060000)
New target: 0x010000... (difficulty = 0x1f010000)
Increase: 6x harder (0x06 → 0x01)
```

### Genesis Mining
- Mining Time: ~26 minutes on 2-core server
- Hashes Tried: 15,178
- Verification: Passed all consensus rules

### Chain Parameters (Testnet)
```cpp
params.genesisTime = 1730000000;   // October 27, 2025
params.genesisNonce = 15178;
params.genesisNBits = 0x1f010000;
params.genesisHash = "0000ee281e9c4a9216ed662146da376ff20fd2b3cc516bc4346cedb2a330e6d3";
```

## Files Included

This release includes:
- `dilithion-node.exe` - Main node executable (v1.0.14)
- Required DLLs (libcrypto, libssl, libwinpthread, etc.)
- Batch scripts for easy startup:
  - `SETUP-AND-START.bat` - Interactive setup wizard
  - `START-MINING.bat` - Quick start mining
- Documentation:
  - `README-WINDOWS.txt` - Setup instructions
  - `TESTNET-GUIDE.md` - Comprehensive testnet guide

## Upgrade Instructions

### Important: Fresh Start Required

v1.0.14 uses a completely new genesis block. You **must** wipe existing blockchain data:

**Method 1: Automatic (Recommended)**
1. Run `SETUP-AND-START.bat`
2. On first run, it will detect incompatible blockchain and wipe automatically
3. **Note:** You must run the batch file **twice** (see Known Issues)
4. Second run will start mining normally

**Method 2: Manual**
1. Delete `%USERPROFILE%\.dilithion-testnet\blocks` directory
2. Delete `%USERPROFILE%\.dilithion-testnet\chainstate` directory
3. Keep wallet.dat and dilithion.conf intact
4. Run `SETUP-AND-START.bat`

### Wallet Preservation

Your wallet is **safe** during upgrades:
- Located at: `%USERPROFILE%\.dilithion-testnet\wallet.dat`
- Blockchain wipe does NOT affect wallet
- Your mnemonic phrase remains valid

## Known Issues

### Bug #29: Windows Double-Run Requirement
**Issue:** First launch after upgrade exits with "Please restart the node" message
**Workaround:** Simply run `SETUP-AND-START.bat` a second time
**Status:** Fix planned for v1.0.15
**Technical Cause:** Blockchain wipe code exits immediately (designed for systemd auto-restart on Linux) instead of reopening databases

## Compatibility

- **Compatible with:** v1.0.14 only
- **NOT compatible with:** v1.0.13, v1.0.12, or earlier versions
- **Network:** Fresh testnet chain starts at block 0

## Performance

With v1.0.13's Bug #28 fix + v1.0.14 difficulty:
- **Hash Rate:** ~600 H/s (20 threads on modern CPU)
- **Block Time:** ~60 seconds average
- **RandomX Dataset:** 2GB RAM in FULL mode
- **Dataset Init:** ~15-20 seconds (20 threads)

## Security Notes

This is a **TESTNET** release:
- For testing and development only
- Coins have NO monetary value
- Network may be wiped or reset without notice
- Use for learning, testing, and experimentation

## Verification

**SHA-256 Checksums:**
See `dilithion-testnet-v1.0.14-SHA256SUMS.txt` for file verification.

## Changes Since v1.0.13

- Updated genesis block difficulty (6x harder)
- Mined new genesis block
- Version strings updated to v1.0.14
- No code changes (same bug fixes and features as v1.0.13)

## Previous Release Context

v1.0.13 introduced:
- **Bug #28 Fix:** Per-thread RandomX VMs (10x hash rate improvement)
- Hash rate: 60 H/s → 600 H/s
- This necessitated the difficulty increase in v1.0.14

## Questions or Issues?

- GitHub Issues: https://github.com/WillBarton888/dilithion/issues
- Documentation: See included guides and README files

---

**Full Changelog:** [v1.0.13...v1.0.14](https://github.com/WillBarton888/dilithion/compare/v1.0.13...v1.0.14)
