# Testnet Implementation Plan - Dilithion

**Status:** In Progress
**Created:** October 26, 2025
**Timeline:** 1 week implementation + 3-5 days testing
**Goal:** Safe testing environment before mainnet Jan 1, 2026 launch

---

## Executive Summary

Implement a fully functional testnet for Dilithion to validate:
- 4 critical bug fixes discovered Oct 26
- Multi-node peer-to-peer networking
- Blockchain synchronization
- Mining and consensus rules
- Wallet functionality
- Release process

**Why This Matters:**
- Industry standard (Bitcoin, Ethereum, Monero all have testnets)
- Found 4 CRITICAL bugs today - need to verify fixes work
- Zero real-world network testing done yet
- Reduces mainnet launch risk dramatically

---

## Phase 1: Code Architecture (Day 1 - 4 hours)

### 1.1 Create ChainParams System

**File:** `src/core/chainparams.h` (NEW)
```cpp
#ifndef DILITHION_CHAINPARAMS_H
#define DILITHION_CHAINPARAMS_H

#include <cstdint>
#include <string>

enum Network {
    MAINNET,
    TESTNET
};

class ChainParams {
public:
    Network network;

    // Network identification
    uint32_t networkMagic;          // Message start bytes

    // Genesis block
    uint32_t genesisTime;
    uint32_t genesisNonce;
    uint32_t genesisNBits;
    std::string genesisHash;
    std::string genesisCoinbaseMsg;

    // Network ports
    uint16_t p2pPort;
    uint16_t rpcPort;

    // Data directory
    std::string dataDir;

    // Consensus
    uint32_t blockTime;             // Target seconds per block
    uint64_t halvingInterval;       // Blocks between halvings
    uint64_t difficultyAdjustment;  // Blocks between difficulty adjustments

    // Mining
    uint64_t initialReward;         // Initial block reward in ions

    static ChainParams Mainnet();
    static ChainParams Testnet();
};

// Global chain parameters
extern ChainParams* g_chainParams;

#endif // DILITHION_CHAINPARAMS_H
```

**File:** `src/core/chainparams.cpp` (NEW)
```cpp
#include "chainparams.h"

ChainParams* g_chainParams = nullptr;

ChainParams ChainParams::Mainnet() {
    ChainParams params;
    params.network = MAINNET;

    // Network identification
    params.networkMagic = 0xD1711710;  // DIL = Dilithion

    // Genesis (TO BE MINED)
    params.genesisTime = 1767225600;   // Jan 1, 2026 00:00:00 UTC
    params.genesisNonce = 0;           // TO BE UPDATED after mining
    params.genesisNBits = 0x1d00ffff;  // Difficulty target
    params.genesisHash = "";           // TO BE UPDATED after mining
    params.genesisCoinbaseMsg = "The Guardian 01/Jan/2026: Quantum computing advances threaten cryptocurrency security - Dilithion launches with post-quantum protection for The People's Coin";

    // Network ports
    params.p2pPort = 8444;
    params.rpcPort = 8332;

    // Data directory
    params.dataDir = ".dilithion";

    // Consensus
    params.blockTime = 240;            // 4 minutes
    params.halvingInterval = 210000;   // ~1.6 years
    params.difficultyAdjustment = 2016; // ~5.6 days

    // Mining
    params.initialReward = 50 * 100000000;  // 50 DIL

    return params;
}

ChainParams ChainParams::Testnet() {
    ChainParams params;
    params.network = TESTNET;

    // Network identification
    params.networkMagic = 0xDAB5BFFA;  // Different from mainnet

    // Genesis (TO BE MINED - EASY)
    params.genesisTime = 1730000000;   // Oct 27, 2025 (testnet start)
    params.genesisNonce = 0;           // TO BE UPDATED after mining
    params.genesisNBits = 0x1e00ffff;  // EASIER difficulty (256x easier than mainnet)
    params.genesisHash = "";           // TO BE UPDATED after mining
    params.genesisCoinbaseMsg = "Dilithion Testnet Genesis - Testing post-quantum cryptocurrency before mainnet launch";

    // Network ports (different from mainnet)
    params.p2pPort = 18444;
    params.rpcPort = 18332;

    // Data directory (separate from mainnet)
    params.dataDir = ".dilithion-testnet";

    // Consensus (faster for testing)
    params.blockTime = 240;            // Same 4 minutes
    params.halvingInterval = 210000;   // Same as mainnet
    params.difficultyAdjustment = 2016; // Same as mainnet

    // Mining (same as mainnet)
    params.initialReward = 50 * 100000000;  // 50 DIL

    return params;
}
```

### 1.2 Update Genesis Code to Use ChainParams

**File:** `src/node/genesis.h` (MODIFY)
Add parameter:
```cpp
bool MineGenesisBlock(Network network = MAINNET);
```

**File:** `src/node/genesis.cpp` (MODIFY)
- Add `#include "core/chainparams.h"`
- Use `g_chainParams->genesisTime`, `g_chainParams->genesisNBits`, etc.
- Remove hardcoded values

### 1.3 Add Command-Line Argument Parsing

**File:** `src/main.cpp` (MODIFY)
```cpp
bool testnet = false;

// Parse arguments
for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--testnet") {
        testnet = true;
    } else if (arg == "--help") {
        // ... help text
    }
}

// Initialize chain parameters
if (testnet) {
    g_chainParams = new ChainParams(ChainParams::Testnet());
    std::cout << "Running on TESTNET" << std::endl;
} else {
    g_chainParams = new ChainParams(ChainParams::Mainnet());
    std::cout << "Running on MAINNET" << std::endl;
}
```

---

## Phase 2: Mine Testnet Genesis (Day 1 - 30 minutes)

### 2.1 Build with Testnet Support
```bash
cd /mnt/c/Users/will/dilithion
make clean
make genesis_gen
```

### 2.2 Mine Testnet Genesis Block
```bash
./genesis_gen --mine --testnet 2>&1 | tee testnet_genesis_mining.txt
```

**Expected time:** 5-15 minutes (0x1e00ffff is 256x easier than mainnet 0x1d00ffff)

### 2.3 Update ChainParams with Mined Values
After mining completes, extract:
- Testnet nonce
- Testnet hash

Update `src/core/chainparams.cpp`:
```cpp
params.genesisNonce = [TESTNET_NONCE];
params.genesisHash = "[TESTNET_HASH]";
```

### 2.4 Rebuild and Verify
```bash
make clean
make dilithion-node
./dilithion-node --testnet --version
```

---

## Phase 3: Local Multi-Node Testing (Day 2 - 4 hours)

### 3.1 Set Up 3 Test Nodes

**Node 1 (Miner):**
```bash
./dilithion-node --testnet --datadir=testnode1 --p2pport=18444 --rpcport=18332
```

**Node 2 (Sync Test):**
```bash
./dilithion-node --testnet --datadir=testnode2 --p2pport=18445 --rpcport=18333 --addnode=127.0.0.1:18444
```

**Node 3 (Sync Test):**
```bash
./dilithion-node --testnet --datadir=testnode3 --p2pport=18446 --rpcport=18334 --addnode=127.0.0.1:18444
```

### 3.2 Test Scenarios

**Test 1: Genesis Block Loading**
- All 3 nodes should load same genesis hash
- Verify: `curl http://localhost:18332 -d '{"method":"getblockcount"}'`

**Test 2: Mining**
- Start mining on Node 1
- Mine 10 blocks
- Verify blocks appear

**Test 3: Block Propagation**
- Node 1 mines blocks
- Verify Node 2 and Node 3 receive and validate blocks
- Check all nodes have same chain height

**Test 4: Wallet Functionality**
- Create wallet on Node 2
- Generate address
- Mine blocks to that address on Node 1
- Verify balance appears on Node 2

**Test 5: Transaction Broadcasting**
- Send transaction from Node 2
- Verify Node 1 and Node 3 receive it
- Mine transaction into block
- Verify balance updates

**Test 6: Fork Resolution**
- Disconnect Node 3
- Mine 5 blocks on Node 1
- Mine 3 blocks on Node 3 (disconnected)
- Reconnect Node 3
- Verify Node 3 reorganizes to Node 1's longer chain

---

## Phase 4: Extended Testing (Days 3-7)

### 4.1 Stress Tests

**Long-Running Stability:**
- Run 3 nodes for 24+ hours
- Mine continuously
- Check for memory leaks
- Monitor CPU usage

**Large Chain Sync:**
- Mine 1000+ blocks
- Start fresh Node 4
- Time full sync
- Verify all blocks validate

**Network Partition:**
- Split network into 2 groups
- Mine on both sides
- Reconnect
- Verify reorganization works

### 4.2 Bug Verification

**Verify Oct 26 Bug Fixes:**
1. Hash comparison byte order (genesis.cpp:87)
2. Target calculation consistency (genesis_test.cpp:75)
3. Post-mining verification (genesis.cpp:95)
4. Missing include (server.h:10)

Run specific tests for each fixed bug.

### 4.3 Release Process Testing

**Build Release Package:**
```bash
./build-release.sh v0.1.0-testnet
```

**Test on Clean System:**
- Extract release package
- Run on machine without dev environment
- Verify binaries work
- Test wallet creation
- Test mining

---

## Phase 5: Documentation (Day 3 - 2 hours)

### 5.1 Create Testnet Guide

**File:** `TESTNET-GUIDE.md`
- How to run testnet node
- How to mine testnet coins
- How to get testnet coins (faucet instructions)
- Testnet block explorer (if available)
- Known testnet limitations

### 5.2 Update README

Add testnet section:
```markdown
## Testnet

Dilithion testnet is available for testing before mainnet launch.

**Quick Start:**
```bash
./dilithion-node --testnet
```

See [TESTNET-GUIDE.md](TESTNET-GUIDE.md) for details.
```

### 5.3 Update Release Notes

Add testnet information to RELEASE-NOTES-v1.0.0.md

---

## Phase 6: Public Testnet (Optional - Days 4-7)

### 6.1 Deploy Testnet Seed Nodes

**Option A: Use Same VPS Plan**
- Deploy 1-2 testnet seed nodes
- Cheaper than mainnet (can use smaller VPS)
- Public DNS: testnet-seed1.dilithion.org

**Option B: Local Testing Only**
- Skip public testnet
- Keep testing internal
- Launch mainnet after validation

### 6.2 Community Testing

If public testnet:
- Announce on GitHub
- Let early adopters test
- Gather feedback
- Fix any reported issues

---

## Success Criteria

Testnet is ready when:
- ✅ 3+ nodes sync correctly
- ✅ Mining produces valid blocks
- ✅ Blocks propagate across network
- ✅ Transactions broadcast and confirm
- ✅ Forks resolve correctly
- ✅ No crashes for 24+ hours
- ✅ All 4 Oct 26 bug fixes verified
- ✅ Release packages work on clean systems
- ✅ Documentation is complete

---

## Mainnet Preparation (After Testnet Validation)

Once testnet proves stable:

### 1. Mine Mainnet Genesis
```bash
./genesis_gen --mine 2>&1 | tee mainnet_genesis_mining.txt
```
Expected: 10-60 minutes (probabilistic)

### 2. Update Mainnet ChainParams
Update `chainparams.cpp` with mined mainnet nonce/hash

### 3. Final Mainnet Build
```bash
./build-release.sh v1.0.0
```

### 4. Deploy Mainnet Infrastructure
- 3 seed nodes (per INFRASTRUCTURE-SETUP-GUIDE.md)
- Website deployment
- Documentation finalization

### 5. Launch Jan 1, 2026
With confidence, knowing testnet validated everything.

---

## Timeline Summary

| Phase | Duration | Completion Date |
|-------|----------|-----------------|
| 1. Code Architecture | 4 hours | Oct 27 |
| 2. Mine Testnet Genesis | 30 min | Oct 27 |
| 3. Local Multi-Node Test | 4 hours | Oct 28 |
| 4. Extended Testing | 3-5 days | Oct 31 - Nov 2 |
| 5. Documentation | 2 hours | Nov 2 |
| 6. Public Testnet (optional) | 2-3 days | Nov 3-5 |
| **TOTAL** | **~1 week** | **Nov 2-5** |

**Mainnet preparation:** Nov 5-30
**Buffer time:** 4 weeks before Jan 1 launch
**Launch date:** Jan 1, 2026 ✅

---

## Risk Mitigation

**What if testnet reveals major bugs?**
- Still have 9 weeks to fix before mainnet
- Better to find now than after launch
- Can reset testnet anytime

**What if testing takes longer?**
- Still on track for Jan 1 launch
- 4-week buffer built in
- Can extend testnet validation if needed

**What if we skip testnet?**
- HIGH RISK: Network may fail at launch
- Would damage reputation
- Could lose user funds
- Industry standard requires testnet

---

## Next Steps

1. ✅ Create this plan (DONE)
2. ⏳ Implement ChainParams system
3. ⏳ Add --testnet flag support
4. ⏳ Mine testnet genesis
5. ⏳ Run multi-node tests
6. ⏳ Validate for 3-5 days
7. ⏳ Mine mainnet genesis
8. ⏳ Launch Jan 1, 2026

---

**This is the professional path forward. Let's build it right.**
