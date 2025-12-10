# BUG #55 - Monero-Style Dual-Mode RandomX Architecture

## Date: 2025-11-26

## Summary

Implemented Monero-style dual-mode RandomX architecture to fix the NYC node startup hang issue. High-RAM nodes (>=3GB) now start instantly with LIGHT mode for validation, while FULL mode for mining initializes asynchronously in the background.

## Problem

NYC node (3.9GB RAM) was hanging for 30-60+ seconds during RandomX FULL mode initialization before accepting connections or processing any blocks. This blocked:
- Block validation
- P2P connections
- RPC server startup
- Everything else

**Root Cause:** Nodes with >=3GB RAM used FULL mode (2GB dataset) for ALL operations, blocking startup until the dataset was fully initialized.

## Solution: Monero-Style Dual-Mode Architecture

Following Monero's proven pattern:
- **LIGHT mode (256MB)**: Used for ALL block validation - instant startup (1-2 seconds)
- **FULL mode (2GB)**: Used ONLY for mining - async background initialization (30-60 seconds)

### New API Functions

```cpp
// Block validation (always available after init)
void randomx_init_validation_mode(const void* key, size_t key_len);
void randomx_hash_for_validation(const void* input, size_t input_len, void* output);

// Mining (async background init)
void randomx_init_mining_mode_async(const void* key, size_t key_len);
int randomx_is_mining_mode_ready();
void randomx_wait_for_mining_mode();
int randomx_hash_for_mining(const void* input, size_t input_len, void* output);
```

### Node Startup Sequence

```
START
  ↓
Initialize LIGHT mode (1-2 seconds)
  ↓
Load/verify genesis block (instant)
  ↓
Start P2P connections
  ↓
Start RPC server
  ↓
IF mining enabled AND RAM >= 3GB:
  └─ Start FULL mode init in background thread
  ↓
Enter main loop (immediately responsive)
  ↓
Mining uses FULL mode when ready, LIGHT mode fallback
```

## Files Changed

| File | Changes |
|------|---------|
| `src/crypto/randomx_hash.h` | Added dual-mode API declarations |
| `src/crypto/randomx_hash.cpp` | Implemented dual-mode architecture (~200 lines) |
| `src/node/dilithion-node.cpp` | Updated startup to use validation mode first |
| `src/miner/controller.cpp` | Updated to use appropriate mode for mining |
| `src/node/blockchain_storage.cpp` | Reduced disk space requirement from 10GB to 5GB |

## Implementation Details

### Separate Global State

```cpp
// Validation mode (LIGHT) - always available after init
randomx_cache* g_validation_cache;
randomx_vm* g_validation_vm;
std::atomic<bool> g_validation_ready{false};

// Mining mode (FULL) - async background initialization
randomx_cache* g_mining_cache;
randomx_dataset* g_mining_dataset;
randomx_vm* g_mining_vm;
std::atomic<bool> g_mining_ready{false};
std::atomic<bool> g_mining_initializing{false};
std::thread g_mining_init_thread;
```

### Mining Mode Selection

Mining threads use FULL mode when ready, with automatic fallback to LIGHT mode:
```cpp
void* randomx_create_thread_vm() {
    if (g_mining_ready.load()) {
        // Use FULL mode (~100 H/s)
        return randomx_create_vm(flags, g_mining_cache, g_mining_dataset);
    } else if (g_validation_ready.load()) {
        // Fallback to LIGHT mode (~3-10 H/s)
        return randomx_create_vm(flags, g_validation_cache, nullptr);
    }
}
```

## Testing Results

### Deployment Verification

All 3 nodes deployed with fresh blockchain data:

| Node | Location | RAM | Mode | Memory Usage | Hashrate |
|------|----------|-----|------|--------------|----------|
| 134.122.4.164 | NYC | 3.9GB | FULL | 1.67 GB | 1 H/s* |
| 188.166.255.63 | Singapore | 2GB | LIGHT | 268 MB | 2 H/s |
| 209.97.177.197 | London | 2GB | LIGHT | 268 MB | 4 H/s |

*NYC hashrate increasing as FULL mode dataset completes initialization

### Startup Time

- **Before fix:** NYC hung for 30-60+ seconds at 99% CPU
- **After fix:** All nodes start in <5 seconds

### Memory Usage Verification

- **LIGHT mode:** ~268 MB (validation cache only)
- **FULL mode:** ~1.67 GB growing to 2GB (full dataset)

## Commits

```
611e135 fix: BUG #55 - Monero-style dual-mode RandomX for instant node startup
08c1508 fix: Reduce disk space requirement from 10GB to 5GB for testnet
```

## Verification Commands

Check block count:
```bash
curl -s -X POST -H 'Content-Type: application/json' -H 'X-Dilithion-RPC: 1' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
  http://127.0.0.1:18332/
```

Check mining status:
```bash
curl -s -X POST -H 'Content-Type: application/json' -H 'X-Dilithion-RPC: 1' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getmininginfo","params":[]}' \
  http://127.0.0.1:18332/
```

Check memory usage:
```bash
ps aux | grep dilithion-node
```

## Benefits

1. **Instant startup** - Nodes ready for validation in 1-2 seconds
2. **No blocking** - Mining begins immediately with LIGHT mode
3. **Automatic upgrade** - Mining upgrades to FULL mode when ready
4. **Memory efficient** - Low-RAM nodes stay in LIGHT mode
5. **Follows proven patterns** - Matches Monero's architecture

## References

- Monero RandomX: LIGHT mode for validation, FULL mode for mining
- XMRig: Dual-mode initialization pattern
- Bitcoin Core: Async initialization patterns
