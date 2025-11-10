# Dilithion Network Capacity Analysis

**Analysis Date**: October 28, 2025
**Purpose**: Determine maximum concurrent miners for testnet

---

## Network Parameters (From Code)

```cpp
// From src/net/peers.h
MAX_OUTBOUND_CONNECTIONS = 8
MAX_INBOUND_CONNECTIONS = 117
MAX_TOTAL_CONNECTIONS = 125

// From src/consensus/pow.h
BLOCK_TARGET_SPACING = 240 seconds (4 minutes)
DIFFICULTY_ADJUSTMENT_INTERVAL = 2016 blocks
```

---

## Theoretical Maximum Concurrent Miners

### Scenario 1: Fully Connected Network (Ideal)

**Assumption**: Every node connects to every other node (full mesh)

**Calculation**:
- Each node can have up to 125 connections (peers)
- If every miner connects to every other miner
- Maximum miners = MAX_TOTAL_CONNECTIONS + 1 = **126 miners**

**Reality**: Not practical due to connection overhead

### Scenario 2: Hub-and-Spoke with Seed Nodes

**Assumption**: Miners connect to seed nodes, seed nodes interconnect

**Setup**:
- 5-10 seed nodes (high uptime, good bandwidth)
- Each seed node: 125 connections
- Miners connect to seed nodes

**Calculation**:
- 5 seed nodes × 117 inbound each = **585 miners**
- 10 seed nodes × 117 inbound each = **1,170 miners**

**Practical limit**: **500-1,000 concurrent miners** with 5-10 seed nodes

### Scenario 3: Real-World Network (Expected)

**Mixed topology**: Some miners connect peer-to-peer, some via seeds

**Expected capacity**:
- Small testnet (weeks 1-4): **50-100 miners**
- Growing testnet (months 2-3): **100-500 miners**
- Mature testnet (month 4+): **500-1,000 miners**

---

## Block Production Analysis

### Block Time: 4 Minutes (240 seconds)

**Question**: How many miners can compete for blocks?

**Answer**: Theoretically unlimited, practically limited by:

1. **Network Propagation Time**
   - Block must propagate to all peers before next block
   - Ethernet/Internet: ~0.1-2 seconds per hop
   - With 125 peers: ~5-10 seconds total propagation
   - **Safe margin**: 240 seconds ÷ 10 seconds = **24 block propagation cycles**

2. **Orphan Block Rate**
   - More miners = more simultaneous block solutions
   - Target orphan rate: <1% (industry standard)
   - Current block time (4 min) supports high miner count
   - **Estimated safe**: **1,000+ miners** at 4-minute block time

3. **Hash Rate Distribution**
   - RandomX: ~65 H/s per CPU core
   - Difficulty adjusts every 2,016 blocks (~5.6 days)
   - Network can handle any hash rate (that's the point of PoW)

---

## Network Bandwidth Requirements

### Per-Node Bandwidth

**Outbound**:
- Block announcements: ~50 KB per block
- Transaction relay: ~10 KB/min average
- Peer discovery: ~1 KB/min
- **Total outbound**: ~60 KB per 4 minutes = **0.25 KB/s**

**Inbound**:
- Same as outbound × number of peers
- For 125 peers: 0.25 KB/s × 125 = **31 KB/s** = **0.25 Mbps**

**Conclusion**: Very low bandwidth requirements ✅

---

## Stress Test Factors

### What Can Go Wrong with Many Miners?

1. **Peer Connection Overload**
   - Each node has 125 connection limit
   - Solution: Seed nodes

2. **Block Propagation Delays**
   - More peers = longer propagation
   - Current 4-minute block time is generous

3. **Mempool Synchronization**
   - Transactions must propagate before mining
   - Current implementation should handle this

4. **Database I/O Contention**
   - Multiple blocks arriving simultaneously
   - LevelDB should handle concurrent reads

5. **Difficulty Adjustment Lag**
   - 2016 blocks between adjustments
   - Rapid hash rate changes can cause issues
   - **Time to adjust**: 2016 × 4 min = ~5.6 days

---

## Practical Limits by Deployment Stage

### Testnet (Current)

**Without seed nodes:**
- **Conservative**: 10-20 concurrent miners
- **Optimistic**: 50-100 concurrent miners
- **Risk**: Peer discovery issues, connection limits

**With 1 VPS seed node:**
- **Safe**: 100 miners
- **Maximum**: 117 miners (seed node limit)
- **Recommended**: Set up seed node by week 2

**With 5-10 VPS seed nodes:**
- **Safe**: 500 miners
- **Maximum**: 1,000+ miners
- **Recommended**: For mature testnet (month 2+)

### Mainnet (Future)

**With distributed seed nodes:**
- **Expected**: 10,000+ miners
- **Network capacity**: Effectively unlimited
- **Bottleneck**: Unlikely to be connections (more likely hash rate concentration)

---

## Stress Test Plan (3 Nodes, 15 Minutes)

### Test Objectives

1. **Peer Discovery**: Do all 3 nodes connect?
2. **Block Propagation**: Do blocks propagate quickly?
3. **Mining Competition**: Who finds blocks?
4. **Stability**: Any crashes or hangs?
5. **Resource Usage**: CPU, memory, disk I/O

### Test Setup

**3 Nodes:**
- Node 1: Port 8444 (seed)
- Node 2: Port 9444 (connects to Node 1)
- Node 3: Port 10444 (connects to Node 1)

**All mining with:**
- 4 threads each
- 12 total CPU cores mining
- Combined hash rate: ~260 H/s (4 cores × 65 H/s × 3)

**Expected blocks in 15 minutes:**
- Block time: 4 minutes
- 15 minutes ÷ 4 minutes = **~3.75 blocks expected**
- With initial low difficulty: **5-10 blocks possible**

### Success Criteria

✅ **PASS**:
- All 3 nodes connect to each other
- Blocks propagate within 10 seconds
- No crashes or hangs
- Memory usage stable
- Blocks found and accepted

❌ **FAIL**:
- Nodes can't connect
- Blocks don't propagate
- Crashes or hangs
- Memory leaks
- Consensus failures

---

## Expected Stress Test Results

### Predictions (Before Test)

1. **Connection Success**: 95% - nodes should connect
2. **Block Propagation**: <5 seconds - network is local
3. **Blocks Mined**: 5-10 blocks in 15 minutes
4. **Orphans**: 0-1 blocks (if 2+ nodes find simultaneously)
5. **Crashes**: 0 expected
6. **Memory**: Stable at 500-700 MB per node

### What We'll Learn

- Real-world mining stability
- Peer connection reliability
- Block propagation performance
- Resource usage under load
- Any edge cases or bugs

---

## Maximum Concurrent Miners - Final Answer

### Conservative Estimate (High Confidence)

**Current Setup (No Dedicated Seed Nodes):**
- **Weeks 1-2**: 20-30 miners safely
- **Risk**: Connection limits without seeds

**With 1 VPS Seed Node (Recommended Week 2):**
- **Months 1-2**: 100 miners safely
- **Maximum**: 117 miners (connection limit)

**With 5 VPS Seed Nodes (Mature Testnet):**
- **Months 3-6**: 500 miners safely
- **Maximum**: 1,000+ miners

**With 10+ Community Seed Nodes (Mainnet):**
- **Mainnet**: 10,000+ miners
- **Network capacity**: Effectively unlimited
- **Real limit**: Hash rate distribution (51% attack prevention)

### Aggressive Estimate (Medium Confidence)

**Testnet could handle**:
- **Without seeds**: 50-100 miners (risky)
- **With 1 seed**: 200-300 miners (pushing limits)
- **With 5 seeds**: 1,000-2,000 miners (stress testing territory)

---

## Recommendations

### Week 1-2 (Current)

1. **Expect**: 10-30 miners
2. **Monitor**: Connection counts, peer lists
3. **Action**: Set up 1 VPS seed node by end of week 2

### Week 3-4

1. **Target**: 50-100 miners
2. **Requirement**: 1 VPS seed node operational
3. **Monitor**: Block propagation times, orphan rate

### Month 2-3

1. **Target**: 100-500 miners
2. **Requirement**: 3-5 VPS seed nodes
3. **Monitor**: Network stability, difficulty adjustment

### Month 4+ (Pre-Mainnet)

1. **Target**: 500-1,000+ miners
2. **Requirement**: 10+ community seed nodes
3. **Monitor**: Prepare for mainnet launch

---

## Technical Bottlenecks (Ranked)

### 1. Peer Connections (Most Likely)
- **Limit**: 125 per node
- **Solution**: Seed nodes
- **Priority**: HIGH

### 2. Block Propagation (Low Risk)
- **Current**: 4-minute block time (generous)
- **Solution**: Already solved
- **Priority**: LOW

### 3. Difficulty Adjustment Lag (Medium Risk)
- **Adjustment**: Every 2016 blocks (~5.6 days)
- **Risk**: Rapid hash rate changes
- **Solution**: May need shorter adjustment interval for testnet
- **Priority**: MEDIUM

### 4. Database I/O (Low Risk)
- **Current**: LevelDB handles concurrent access
- **Solution**: Already solved
- **Priority**: LOW

---

## Conclusion

**Maximum Concurrent Miners (Testnet):**

| Scenario | Conservative | Optimistic | Max Theoretical |
|----------|--------------|------------|-----------------|
| No seeds (Week 1) | 20 | 50 | 100 |
| 1 seed (Week 2+) | 100 | 200 | 300 |
| 5 seeds (Month 2+) | 500 | 1,000 | 2,000 |
| 10+ seeds (Mainnet) | 10,000 | 50,000 | Unlimited* |

\* *Limited by hash rate distribution, not network capacity*

**Recommended Path:**
1. **Week 1**: No seeds, expect 10-30 miners ✅
2. **Week 2**: Set up 1 VPS seed ($5/month) → support 100 miners
3. **Month 2**: Add 4 more seeds → support 500 miners
4. **Month 3+**: Community seeds → support 1,000+ miners
5. **Mainnet**: 20+ distributed seeds → support 10,000+ miners

---

**Next**: Run 3-node stress test to validate these predictions! 🧪

🤖 Generated with [Claude Code](https://claude.com/claude-code)
