# DFMP IBD Identity Registration Fix

## Problem Statement

During Initial Block Download (IBD), fresh nodes cannot validate blocks because:

1. **Reference blocks** require identity→pubkey lookup from `g_identityDb`
2. **Identity registration** only happens in `BlockConnectCallback` (AFTER validation)
3. **Result**: Block N fails validation because block N-1's registration hasn't been stored yet

## Root Cause

```
Current Flow (BROKEN):
1. Block 2 arrives (reference block, identity=X)
2. Validation: lookup identity X → NOT FOUND → REJECT
3. Block 1 arrives (registration block, identity=X, includes pubkey)
4. Validation: OK (pubkey embedded)
5. Connection: Store identity X → pubkey
6. Block 2 never retried → Node banned for sending "invalid" blocks
```

## Solution Design

### Principle: Identity DB is Chain-Derived State

The identity database is an INDEX of blockchain data, not independent state. Every identity exists in a registration block. During IBD, we rebuild this index from the chain.

### Part 1: Pre-Register Identity During Validation

**File**: `src/consensus/pow.cpp` (CheckDFMPProofOfWork)

When validating a registration block (`isRegistration=true`), the pubkey is embedded and self-verifying. We can safely store it BEFORE the block is connected:

```cpp
if (mikData.isRegistration) {
    pubkey = mikData.pubkey;

    // Verify identity = SHA3-256(pubkey)[:20]
    DFMP::Identity derivedIdentity = DFMP::DeriveIdentityFromMIK(pubkey);
    if (derivedIdentity != mikData.identity) {
        return false;  // Mismatch
    }

    identity = mikData.identity;

    // PRE-REGISTER: Store identity during validation (not just on connection)
    // This allows subsequent blocks in the same IBD batch to find this identity.
    // Safe because: registration blocks are self-validating (pubkey is embedded,
    // identity is derived from pubkey, signature is verified against pubkey).
    if (DFMP::g_identityDb && !DFMP::g_identityDb->HasMIKPubKey(identity)) {
        DFMP::g_identityDb->SetMIKPubKey(identity, pubkey);
        // Note: If block validation later fails, the identity remains registered.
        // This is acceptable because:
        // 1. The identity derivation was verified (identity = SHA3(pubkey))
        // 2. Only the penalty calculation might be wrong, not the identity itself
        // 3. A reorg would naturally rebuild the correct state
    }
}
```

**Why this is safe**:
- Registration blocks contain the full pubkey
- We verify `identity = SHA3-256(pubkey)[:20]` before storing
- We verify the signature before accepting the block
- An attacker cannot pollute the DB with fake identities

### Part 2: Add --assumevalid Parameter (Bitcoin Core Pattern)

**Files**:
- `src/node/dilithion-node.cpp` (CLI parsing)
- `src/consensus/pow.cpp` (validation logic)
- `src/chainparams.h` (default assumevalid hash)

Add `--assumevalid=<blockhash>` CLI parameter:

```cpp
// In chainparams.h - updated with each release
static const char* DEFAULT_ASSUMEVALID_MAINNET = "0000000123...";  // Block at height 10000

// In CheckDFMPProofOfWork
bool CheckDFMPProofOfWork(..., bool skipDFMPPenalty = false) {
    // ... existing validation ...

    if (skipDFMPPenalty) {
        // Below assumevalid: verify signature exists but skip penalty calculation
        // This is Bitcoin Core's approach - trust the chain below a known-good point
        return VerifyMIKSignatureExists(mikData);  // Lightweight check
    }

    // Full DFMP validation for blocks above assumevalid
    // ... existing penalty calculation ...
}
```

**What assumevalid does**:
- Below assumevalid hash: Verify PoW, verify signature structure, skip penalty math
- Above assumevalid hash: Full validation
- Updated with each release (like Bitcoin Core)

**Security model**:
- Nodes still download and verify PoW for all blocks
- Assumevalid is a performance optimization, not a trust shortcut
- Any full node can validate from genesis by setting `--assumevalid=0`

### Part 3: Ensure Strict Block Ordering in IBD

**File**: `src/node/ibd_coordinator.cpp`

Ensure blocks are processed in height order during IBD:

```cpp
// In ProcessIncomingBlock or equivalent
bool CIbdCoordinator::ProcessBlock(const CBlock& block, int height) {
    // Verify previous block is connected before validating this one
    if (height > 0) {
        int chainHeight = m_chainstate.GetHeight();
        if (chainHeight < height - 1) {
            // Previous block not connected yet - queue for later
            m_pendingBlocks[height] = block;
            return true;  // Not an error, just deferred
        }
    }

    // Now safe to validate - all dependencies are connected
    return ValidateAndConnectBlock(block, height);
}
```

### Part 4: Keep Existing BlockConnectCallback (Redundancy)

The existing callback in `dilithion-node.cpp` remains as a safety net:
- Handles blocks received via normal relay (not IBD)
- Ensures identity is registered even if Part 1 somehow misses it
- No code changes needed here

## Implementation Order

1. **Part 1 (Critical)**: Pre-register identity during validation
   - Fixes the immediate IBD failure
   - Simple, low-risk change
   - Test: Fresh node syncs from genesis

2. **Part 3 (Important)**: Strict block ordering
   - Ensures Part 1 works correctly
   - Prevents race conditions
   - Test: IBD with multiple peers

3. **Part 2 (Optimization)**: Add assumevalid
   - Major speedup for IBD
   - Industry-standard approach
   - Test: IBD with assumevalid vs without

## Testing Plan

1. **Fresh node sync**: Start node with empty datadir, sync from network
2. **Identity verification**: Check `g_identityDb` contains all expected identities
3. **Reorg handling**: Verify identities remain valid after reorg
4. **Performance**: Measure IBD time with/without assumevalid

## Security Considerations

1. **No identity pollution**: Registration blocks are self-validating (pubkey embedded)
2. **No trust assumptions**: All blocks still have PoW verified
3. **Assumevalid is optional**: Can be disabled for full validation from genesis
4. **Consistent with Bitcoin**: This is the same approach used by Bitcoin Core

## Files to Modify

| File | Changes |
|------|---------|
| `src/consensus/pow.cpp` | Pre-register identity in validation |
| `src/node/ibd_coordinator.cpp` | Strict block ordering |
| `src/chainparams.h` | Default assumevalid hash |
| `src/node/dilithion-node.cpp` | --assumevalid CLI parameter |

## Estimated Effort

- Part 1: ~30 lines, low complexity
- Part 2: ~100 lines, medium complexity
- Part 3: ~50 lines, medium complexity
- Testing: Comprehensive IBD testing required

## Conclusion

This solution follows Bitcoin Core's proven patterns:
- Identity DB is chain-derived state (like UTXO set)
- Pre-register during validation (like UTXO creation)
- Assumevalid for fast sync (exactly like Bitcoin Core)
- Strict ordering for correctness (like block connection)

The fix is professional, robust, and permanent because it addresses the architectural issue rather than adding workarounds.
