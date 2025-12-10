# Bug #43: Block Relay Missing - CONFIRMED

## Date
2025-11-22

## Summary
Confirmed that nodes do NOT relay received blocks to other peers. When a node receives a block via P2P (not locally mined), it processes the block but does not propagate it to other connected peers.

## Evidence

### Test Scenario (Clean Testnet - Started 10:11 UTC)
- **NYC Node** (134.122.4.164): PID 261581, mining since 10:11
- **Singapore Node** (188.166.255.63): PID 403779, mining since 10:11
- **London Node** (209.97.177.197): PID 342780, mining since 10:11

All nodes configured with `--addnode` to connect to each other.

### Timeline
1. **10:11** - All 3 testnet nodes started from genesis
2. **Unknown time** - Local machine (116.91.223.151) mined block 1
3. **Unknown time** - Local machine connected to NYC as peer 4
4. **Unknown time** - Local machine sent block 1 to NYC
5. **NYC processed block 1 successfully:**
   ```
   [P2P] Received block from peer 4: 0000ea889137e5c5...
   [P2P] Block saved to database
   [P2P] Block index created (height 1)
   [Chain] Block extends current tip: height 1
   [HeadersManager] Added header at height 1, total headers: 2, best height: 1
   [P2P] Updated best block to height 1
   ```
6. **NO RELAY OCCURRED** - No broadcast/relay messages in logs
7. **11:42 (87 minutes later)** - Blockchain state:
   - NYC: **height 1** (has block)
   - Singapore: **height 0** (never received block)
   - London: **height 0** (never received block)

### Key Log Evidence (NYC)

**Block Reception:**
```
[P2P] Received block from peer 4: 0000ea889137e5c5...
[CONVERGENCE-DIAG] BLOCK message received from peer 4
[CONVERGENCE-DIAG]   Block hash: 0000ea889137e5c5...
[P2P] Block saved to database
[P2P] Block index created (height 1)
[Chain] Block extends current tip: height 1
```

**NO Relay Messages:**
- No "Queued block broadcast" message
- No "Relaying block to X peers" message
- No "Broadcasting block" message

**Peer 4 Identity:**
```
[HANDSHAKE-DIAG] Accepted routable inbound peer: 116.91.223.151 (0x745bdf97)
[HANDSHAKE-DIAG] AddPeer called for 116.91.223.151:35045
[HANDSHAKE-DIAG] ✅ Peer 4 added successfully
```

### Current Blockchain State (11:42 UTC)
```bash
$ ssh root@134.122.4.164 "curl -s ... getblockcount"
{"jsonrpc":"2.0","result":1,"id":1}

$ ssh root@188.166.255.63 "curl -s ... getblockcount"
{"jsonrpc":"2.0","result":0,"id":1}

$ ssh root@209.97.177.197 "curl -s ... getblockcount"
{"jsonrpc":"2.0","result":0,"id":1}
```

## Root Cause

In `src/node/dilithion-node.cpp`, when a block is received via P2P (around line 1340), the code:
1. ✅ Saves block to database
2. ✅ Activates block as new tip
3. ❌ **Does NOT relay block to other peers**

The block relay logic only exists for **locally mined blocks** (around line 1250), but NOT for **received blocks**.

## Impact

**Critical Network Propagation Failure:**
- Blocks only propagate one hop from the miner
- Nodes that don't directly connect to the miner never receive blocks
- Network cannot achieve consensus beyond 1-hop connections
- Makes the network effectively unusable for decentralized operation

## Fix Implemented (Not Yet Deployed)

Added block relay logic in `src/node/dilithion-node.cpp` at line 1354:

```cpp
// BUG #43 FIX: Relay received blocks to other peers (Bitcoin Core standard behavior)
// When we receive a block that becomes the new tip, relay it to all connected peers
// (except the peer that sent it to us) to propagate blocks network-wide
if (g_peer_manager && g_async_broadcaster) {
    auto connected_peers = g_peer_manager->GetConnectedPeers();
    std::vector<int> relay_peer_ids;

    // Collect peers with completed handshakes, excluding the sender
    for (const auto& peer : connected_peers) {
        if (peer && peer->IsHandshakeComplete() && peer->id != peer_id) {
            relay_peer_ids.push_back(peer->id);
        }
    }

    if (!relay_peer_ids.empty()) {
        // Queue block relay asynchronously (non-blocking!)
        if (g_async_broadcaster->BroadcastBlock(blockHash, relay_peer_ids)) {
            std::cout << "[P2P] Relaying block to " << relay_peer_ids.size()
                      << " peer(s) (excluding sender peer " << peer_id << ")" << std::endl;
        } else {
            std::cerr << "[P2P] ERROR: Failed to queue block relay" << std::endl;
        }
    }
}
```

## Next Steps

1. Deploy Bug #43 fix to testnet nodes
2. Clear ban lists (local IP was banned for sending old block headers)
3. Wipe blockchains and restart fresh
4. Test block propagation across all 3 nodes
5. Verify blocks relay network-wide
6. Commit Bug #43 fix

## Related Issues

- **Bug #42**: IPv4 parsing - FIXED and committed (479e68d)
- **Bug #40/41**: IBD convergence issues - FIXED (v1.0.16)
- **IP Ban Issue**: Local IP (116.91.223.151) was banned by Singapore/London because it sent block headers from an old/different chain. This is expected behavior, not a bug. Fix: Wipe local blockchain before testing.
