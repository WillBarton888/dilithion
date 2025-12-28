# DILITHION PROJECT STATE
**Last Updated:** December 29, 2025
**Purpose:** Persistent memory for AI assistants across conversation sessions

---

## CRITICAL ARCHITECTURE DECISIONS

### 1. Single-Peer IBD Design
**Decision Date:** December 2025
**Status:** CURRENT

- Headers sync from SINGLE peer (Bitcoin Core style)
- Block download from SINGLE peer (not multiple!)
- MAX_BLOCKS_IN_TRANSIT_PER_PEER = 32 (increased from 16)
- Maximum throughput: 32 blocks in-flight at once

**Why Single Peer:**
- Simpler coordination
- Avoids block ordering issues
- Matches Bitcoin Core headers-first approach

**Known Limitation:**
- Throughput limited by single peer's network speed
- "All peers at capacity" warnings when that peer is slow

### 2. Headers-First Sync
**Status:** IMPLEMENTED

- Headers downloaded first (batches of 2000)
- Block hash computed during header validation (NOT on block arrival)
- Headers stored in mapHeaders with RandomX hash as key
- Blocks requested only after headers validated

### 3. Seed Nodes
**Status:** OPERATIONAL

| Node | IP | Role |
|------|-----|------|
| NYC | 134.122.4.164 | Primary seed, relay-only |
| SGP | 188.166.255.63 | Secondary seed |
| LDN | 209.97.177.197 | Secondary seed |

**CRITICAL:** Seed nodes run as relay-only (NO --mine flag)

### 4. Checkpoint System
**Status:** IMPLEMENTED

- Checkpoint at height 3000
- Below checkpoint: skipPoWCheck=yes (fast sync)
- Above checkpoint: Full RandomX PoW verification

### 5. Fork Detection
**Status:** FIXED (Dec 29, 2025)

- Fork detection disabled during bulk IBD
- Only enabled within 100 blocks of header tip
- Prevents cs_main lock contention from FindForkPoint()

---

## CURRENT IBD ISSUES (Dec 29, 2025)

### Issue 1: Stall at Headers Batch Boundaries (~2000, ~4000)
**Status:** ACTIVE

**Symptom:** 24-second stall when block download catches up to validated headers

**Root Cause:**
- Block download reaches header tip (e.g., height 2000)
- Next headers batch (2000-4000) still being validated
- No blocks can be requested beyond validated headers
- Must wait for headers validation to complete

**Investigation Needed:**
- Why does headers validation take so long?
- Can we request blocks up to received (not just validated) headers?

### Issue 2: "All Peers at Capacity" During Block Download
**Status:** ACTIVE

**Symptom:** Multiple warnings about peers at capacity, blocks arrive slowly

**Root Cause:**
- Single peer used for block download
- 16/16 blocks in-flight limit
- Network latency causes slow delivery
- Can't request more until responses arrive

**Potential Fixes:**
- Use multiple peers for block download
- Increase MAX_BLOCKS_IN_TRANSIT_PER_PEER
- Optimize peer response time

### Issue 3: Slow Sync After Checkpoint 3000
**Status:** ACTIVE

**Symptom:** Block rate drops significantly above checkpoint

**Root Cause:** NOT RandomX (per user confirmation)
- Peer capacity saturation
- Headers batch boundary effects

---

## KEY FILES

### IBD Coordinator
- `src/node/ibd_coordinator.cpp` - Main IBD logic
- `src/node/ibd_coordinator.h` - State and constants

### Block Management
- `src/net/block_fetcher.cpp` - Block request logic
- `src/net/block_tracker.h` - In-flight tracking
- `src/net/headers_manager.cpp` - Headers processing

### Configuration
- `src/core/chainparams.cpp` - Network parameters
- Checkpoint at height 3000

---

## RECENT FIXES (Dec 28-29, 2025)

### Fix 1: Fork Detection During IBD
**Commit:** 0da323e
- Changed from "disable below checkpoint" to "disable during bulk IBD"
- Fork detection only enabled within 100 blocks of header tip
- Eliminated cs_main lock contention

### Fix 2: Capacity Re-Check
**Commit:** 0da323e
- Re-check peer capacity before each block request
- Prevents exceeding 16/16 limit in request loop

---

## DEBUGGING COMMANDS

### Check NYC Node Status
```bash
ssh root@134.122.4.164 "pgrep dilithion && tail -50 /root/node.log | grep -E '(chain|headers|peer|IBD|ERROR)' | tail -20"
```

### Check Sync Progress
```bash
ssh root@134.122.4.164 "grep 'chainHeight=' /root/node.log | tail -1"
```

### Check for Stalls
```bash
ssh root@134.122.4.164 "grep PIPELINE /root/node.log | tail -10"
```

### Restart NYC Node (Fresh Sync Test)
```bash
ssh root@134.122.4.164 "pkill -9 dilithion; rm -rf /root/.dilithion-testnet/blocks /root/.dilithion-testnet/chainstate; rm -f /root/node.log; cd /root/dilithion && nohup ./dilithion-node --testnet > /root/node.log 2>&1 &"
```

---

## PERFORMANCE TARGETS

- **Block download rate:** 20 blocks/second consistent
- **Full sync time:** < 5 minutes for 4600 blocks
- **Stalls:** Zero stalls of > 5 seconds

---

## DO NOT ASSUME

1. **RandomX is NOT the bottleneck** - User has confirmed this multiple times
2. **Single peer for IBD** - Not multi-peer like older discussions suggested
3. **Headers validation can block** - Batch processing takes time

---

## COMMUNICATION NOTES

- User prefers direct, technical communication
- No emoticons
- Focus on root causes, not symptoms
- Follow debugging protocol in CLAUDE.md

---

*This file should be read at the start of each new conversation session.*
