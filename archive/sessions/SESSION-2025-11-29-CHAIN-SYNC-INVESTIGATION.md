# Chain Sync Investigation Session - 2025-11-29

## Summary

A significant P2P networking bug has been discovered during chain synchronization testing. The testnet nodes are unable to sync to the longer local chain due to connection/handshake failures.

## Chain Status

| Node | Height | Best Block Hash | Status |
|------|--------|-----------------|--------|
| **Local (Windows)** | 172 | `0000c791781f3f82...` | Mining, 1 peer connected |
| NYC (134.122.4.164) | 83 | `0000d7176f72f03b...` | Headers=171, stuck |
| Singapore (188.166.255.63) | 83 | `0000d7176f72f03b...` | Headers unknown |
| London (209.97.177.197) | 83 | `0000d7176f72f03b...` | Headers unknown |

## Fork Point Analysis

The chains share the same genesis and blocks 0-7. They diverged at block 8:

| Block | Local Chain | Testnet Chain |
|-------|-------------|---------------|
| 0 (genesis) | `411c351d903c4bcc...` | `411c351d903c4bcc...` SAME |
| 7 | `00001e8df9c3dc32...` | `00001e8df9c3dc32...` SAME |
| 8 | `0000360f3564f6a7...` | `0000b906a4fd1792...` DIFFERENT |
| 83 | `000058372b4fefe0...` | `0000d7176f72f03b...` DIFFERENT |

## Bug Analysis

### Symptom 1: NYC Receives Headers But Cannot Download Blocks

From NYC node log (`/root/dilithion/node.log`):
```
[IBD] Headers ahead of chain - downloading blocks (header=171 chain=84)
[IBD] Queueing 87 blocks for download...
[IBD] Fetching 0 blocks (max 16 in-flight)...
...
[BlockFetcher] Peer 1 stalled (total stalls: 5197)
[P2P] ERROR: No valid socket for peer 1
```

NYC node:
1. Received headers from local Windows node (knows chain is 171 blocks)
2. Advanced its chain to height 84 (downloaded 1 block from local)
3. Connection to local node died
4. Keeps trying to download from Singapore/London who don't have the blocks
5. Results in 5000+ stalls and timeouts

### Symptom 2: Handshake Failures

NYC has 120+ connections but ALL have:
- `lastrecv=0` - No data received
- `version=0` - No VERSION message received
- `startingheight=0` - Handshake never completed

This indicates the P2P handshake is failing systematically.

### Symptom 3: Local Node Losing Peers

Local Windows node:
- Initially connected to all 3 testnet nodes
- Sent headers, started serving blocks
- Connections got "forcibly closed by remote host"
- Now only 1 peer connected (Singapore)

## Root Cause Hypothesis

1. **Block Download From Wrong Peers**: When NYC receives headers announcing a longer chain, it should download blocks from the peer that sent those headers. Instead, it appears to be trying to download from ANY peer, including peers that don't have those blocks.

2. **Connection Stability**: The connections between local Windows node and testnet nodes are unstable, possibly due to:
   - Timeout issues with RandomX mining consuming CPU
   - Socket handling bugs on connection errors
   - Peer management not properly cleaning up failed connections

3. **Handshake Bug**: The massive number of failed handshakes (120+ with version=0) suggests a fundamental issue in the connection establishment flow.

## Impact

- **Chain reorg is impossible** - Even though local has the longer chain (172 vs 83), testnet cannot sync because:
  1. Local node can't maintain stable connections
  2. NYC knows about local's headers but can't download blocks
  3. Singapore/London never even received the headers

## Recommended Fixes

### Immediate (BUG #64)
1. Add logic to prefer downloading blocks from the peer that announced the headers
2. Track which peer sent headers and prioritize that peer for block downloads
3. Add connection health monitoring and reconnection logic

### Short-term
1. Investigate handshake failures - why are 120+ connections failing to complete VERSION exchange
2. Add better error recovery when block downloads fail
3. Clean up stale peer entries (version=0 peers should be removed)

### Long-term
1. Port Bitcoin Core's more robust peer management
2. Implement proper connection pooling with health checks

## Test Results

- Local mining: Working (block 172)
- Header propagation: Partially working (NYC received headers)
- Block propagation: BROKEN (connections dying, blocks not downloading)
- Chain reorg: NOT POSSIBLE until block propagation fixed

## Next Steps for User

1. This is a known P2P issue that needs code fixes
2. For immediate testing, can manually sync by:
   - Stopping testnet nodes
   - Wiping their blockchain data
   - Letting them IBD from local (if connection stays stable)
3. Bug #64 should be filed to track this issue

## Additional Bug Discovered: Mining Stalls After Block Found

During monitoring, another issue was observed:

1. Mining was running normally at ~11 H/s
2. `[OK] BLOCK FOUND!` was logged
3. `[Mining] New block found, updating template...`
4. Hash rate dropped to 1 H/s, hashes frozen at 61778
5. Mining status changed to `"mining":false`
6. **Block count remained at 172** - the found block was NOT committed

This indicates:
- Either the block failed validation after being found
- Or the block template update failed and mining stopped
- This is a potential **BUG #65: Mining stalls after finding block**

## Session Summary

| Status | Description |
|--------|-------------|
| Local Chain | 172 blocks, mining stalled |
| Testnet Chain | 83 blocks, stuck waiting for blocks |
| P2P Issue | BUG #64 - Handshake failures, block download from wrong peers |
| Mining Issue | BUG #65 - Mining stalls after finding block |
| Chain Reorg | NOT POSSIBLE until bugs fixed |

## Files Created This Session

1. `SESSION-2025-11-29-CHAIN-SYNC-STATUS.md` - Initial status document
2. `SESSION-2025-11-29-CHAIN-SYNC-INVESTIGATION.md` - This comprehensive investigation

---
*Generated by Claude Code - 2025-11-29*
