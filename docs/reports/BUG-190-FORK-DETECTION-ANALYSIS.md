# Bug #190 Analysis Report - Fork Chain Not Updating Best Chain

## Summary

**Status: VERIFIED WORKING** - Bug #190 is NOT a bug. The chainWork calculation and comparison are functioning correctly.

## Background

The concern was that fork headers were not updating the best chain even when they appeared to have more work. Testing was performed using:
- **NYC node**: Source chain at height 56028+
- **London node**: Target chain at height 23033 (from backup)
- Fork point detected around height 11925-11926

## Key Findings

### 1. ChainWork Calculation is Correct

Debug logging showed chainWork is stored correctly in bytes 1-8 of uint256:
- byte[8] = Most Significant Byte of work
- byte[7-1] = Lower order bytes
- byte[0] = Always 0

Work accumulation was traced from the fork point:
```
height=11926: byte8=0x17, byte7=0xd0 (fork start)
height=16926: byte8=0x19 (incremented after ~5000 blocks)
height=26641: byte8=0x1b
height=30640: byte8=0x1c, byte7=0x83
height=32641: byte8=0x1d, byte7=0xac (fork overtakes)
```

### 2. ChainWorkGreaterThan Comparison is Correct

The comparison correctly evaluates bytes from most significant (byte[31]) to least significant (byte[0]). When fork chain reached:
- Fork: bytes[8-1] = 1da094b7f26b850a
- London: bytes[8-1] = 1da0348aa1110fcb

Fork correctly identified as having more work (0x94 > 0x34 at byte[6]).

### 3. nBestHeight Updated Successfully

When fork chain exceeded London's work:
```
[UpdateBestHeader] UPDATING: 32621 -> 32622
...
[UpdateBestHeader] UPDATING: 32640 -> 32641

[GetLocator] chainstateHeight=23033 headersHeight=32641 nBestHeight=32641
```

nBestHeight correctly changed from 23033 to 32641.

### 4. Fork Detection Triggered Correctly

After header chain updated, fork detection identified the chain mismatch:
```
[FORK-DETECT] CHAIN MISMATCH DETECTED (Layer 1 - Proactive)
[FORK-DETECT] Our chain tip at height 23033:
[FORK-DETECT]   Local:  000117cb394a4b94...
[FORK-DETECT]   Header: 0001f36f62438d96...
[FORK-DETECT] Finding fork point...
```

## Why Fork Chain Appeared to Have Less Work Initially

The fork chain at height 28000+ had less work than London at height 23033 because:

1. Both chains share history until the fork point (~11925)
2. At height 11925, both chains have identical work (byte8=0x17)
3. Each block adds ~0x00000040000000 to work (incrementing byte[7])
4. byte[8] increments when byte[7] wraps from 0xff to 0x00

**Calculation:**
- Fork at 11925 → 28000 = 16075 blocks = ~5 byte[8] increments
- London at 11925 → 23033 = 11108 blocks = ~4 byte[8] increments

But London's chain at 23033 already had byte8=0x1c, meaning London's work accumulated faster OR had a head start. The fork needed to reach height ~32000+ to exceed London's work.

## Technical Details

### Debug Logging Added
1. `DEBUG-STORE`: Shows byte[8] and byte[7] for stored headers
2. `DEBUG-CMP`: Shows full bytes[8-1] comparison in ChainWorkGreaterThan
3. `DEBUG-CKPT`: Shows checkpoint optimization path
4. `DEBUG-ACTIVATE`: Shows chainWork at OnBlockActivated

### Files Modified (Debug Only)
- `src/net/headers_manager.cpp`: Added DEBUG-STORE, DEBUG-CKPT logging
- `src/consensus/pow.cpp`: Added DEBUG-CMP logging

## Conclusion

**Bug #190 is NOT a bug.** The system is working as designed:

1. ChainWork calculation correctly accumulates work from parent
2. ChainWorkGreaterThan correctly compares from MSB to LSB
3. UpdateBestHeader correctly updates when fork has more work
4. Fork detection correctly identifies chain mismatch

The apparent "bug" was that the fork chain needed significant time (reaching height ~32000) to accumulate enough work to exceed the existing chain's work, due to both chains starting from the same fork point.

## Remaining Issue

After header-level fork detection succeeded, there appears to be a separate issue with block-level reorganization that needs investigation. This is a different bug from #190.

---
*Analysis performed: January 7, 2026*
*Test duration: ~2 hours*
