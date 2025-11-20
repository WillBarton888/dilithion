# Bug #38 Deployment Status
**Date:** 2025-11-20
**Session:** IBD Fix Deployment

---

## Summary

**Bug #38 Fix:** ✅ COMMITTED & DEPLOYED
**Commit:** a854055
**Message:** "fix: Bug #38 - First header assigned wrong height during IBD"

### Fix Details
- **File:** `src/net/headers_manager.cpp:94`
- **Change:** `int height = pprev ? (pprev->height + 1) : 0;` → `int height = pprev ? (pprev->height + 1) : 1;`
- **Root Cause:** Fresh nodes received first header with height=0 instead of height=1, breaking IBD loop
- **Impact:** Blocks were never downloaded during Initial Block Download

---

## Deployment Status

### ✅ Completed Tasks
1. Bug #38 fix committed (commit a854055)
2. Fix pushed to GitHub main branch
3. Deployed to all three seed nodes:
   - NYC (134.122.4.164)
   - Singapore (188.166.255.63)
   - London (209.97.177.197)
4. Blockchain data wiped on all seed nodes (clean genesis restart)
5. All nodes restarted with Bug #38 fix

### 🔴 Issues Discovered

#### NYC Node (134.122.4.164) - Memory Thrashing
- **Problem:** Using 2.4GB RAM on 2GB droplet
- **Symptom:** 193% CPU usage, heavily swapping
- **Cause:** RandomX FULL mode requires >2GB memory
- **Impact:** RPC not responding, node unresponsive
- **Status:** RUNNING but THRASHING
- **Resolution Needed:** Force LIGHT mode or upgrade to 4GB droplet

#### Singapore Node (188.166.255.63) - Working
- **Memory:** 275MB (LIGHT mode)
- **CPU:** 98.5% (mining)
- **Status:** HEALTHY
- **Mining:** Started via RPC

#### London Node (209.97.177.197) - Working
- **Memory:** 274MB (LIGHT mode)
- **CPU:** 99.1% (mining)
- **Status:** HEALTHY
- **Mining:** Running

---

## Current Network State

| Node | Status | Memory | CPU | Mode | Mining | Blocks |
|------|--------|--------|-----|------|--------|--------|
| NYC | THRASHING | 2.4GB/2GB | 193% | FULL | Yes | 0 (stuck) |
| Singapore | HEALTHY | 275MB/1GB | 98.5% | LIGHT | Yes | 0 |
| London | HEALTHY | 274MB/1GB | 99.1% | LIGHT | Yes | 0 |
| Local (Windows) | HEALTHY | N/A | ~580 H/s | FULL | Yes | 1 |

### Observations
1. No blocks have been mined yet on seed network (all at height 0)
2. NYC is memory-constrained and unresponsive
3. Singapore/London are healthy but haven't found blocks yet (difficulty is high, takes time)
4. Local node has block height 1 (from previous session?) and is mining

---

## IBD Testing Status

### Test Plan
1. One seed node mines blocks
2. Other seed nodes sync via IBD (test Bug #38 fix)
3. Local Windows node syncs from seed network

### Current Status
- ⏸️ **BLOCKED**: NYC unresponsive due to memory thrashing
- ⏸️ **WAITING**: Singapore/London mining but no blocks found yet
- ✅ **LOCAL NODE**: Running and mining (~580 H/s)

### Next Steps
1. **Fix NYC memory issue:**
   - Option A: Force LIGHT mode (faster, uses <300MB)
   - Option B: Upgrade to 4GB droplet (costs more)
   - **Recommendation:** Force LIGHT mode for testnet

2. **Wait for first block:** Mining difficulty is high (~60s blocks), need patience

3. **Test IBD:** Once blocks are mined, verify other nodes sync correctly

---

## Pending Tasks

### Code Cleanup
- [ ] Remove debug logging (23 occurrences in 3 files):
  - `src/net/net.cpp`
  - `src/net/block_fetcher.cpp`
  - `src/node/dilithion-node.cpp`
- [ ] Update version string from v1.0.15 → v1.0.16
- [ ] Remove `[IBD-DEBUG]`, `[DEBUG-RECV]`, `[DEBUG-SELECT]`, etc.

### Release v1.0.16
- [ ] Create comprehensive release notes
- [ ] Build release binaries (Windows, Linux, macOS)
- [ ] Generate SHA-256 checksums
- [ ] Publish GitHub release
- [ ] Update website

---

## Technical Notes

### RandomX Memory Requirements
- **FULL Mode:** ~2.08GB (high performance, ~100 H/s per core)
- **LIGHT Mode:** ~256MB (lower performance, ~10-20 H/s per core)

### Droplet Specifications
- **NYC:** 2GB RAM (FULL mode causes swapping)
- **Singapore:** 1GB RAM (must use LIGHT mode)
- **London:** 1GB RAM (must use LIGHT mode)

### Recommendation
For testnet with limited resources, use LIGHT mode on all seed nodes:
- Reduces memory from 2.4GB → 275MB
- Maintains network functionality
- Acceptable performance for testnet mining
- Eliminates swapping/thrashing issues

---

## Decision Required

**Should we:**
1. **Force LIGHT mode on NYC** (quick fix, reduces hash rate)
2. **Upgrade NYC to 4GB droplet** (costs ~$6/month more)

**Recommendation:** Force LIGHT mode for now (testnet doesn't need maximum hash rate)

---

## Logs

### Local Node Status
```
Height: 1
Hash rate: ~580 H/s
RandomX: FULL mode
Memory: 32GB available
Status: Mining block height 2
IBD: headerHeight=-1 (no peer headers received yet)
```

### NYC Node Issue
```
PID: 237855
Memory: 2.4GB (exceeds 2GB limit)
CPU: 193% (thrashing)
RPC: Not responding
```

---

**Next Action:** Fix NYC memory issue, then resume IBD testing
