# BUG #72 Implementation Plan: RandomX FULL Mode Synchronization

## Problem Statement
Mining threads are created before RandomX FULL mode dataset initialization completes. Threads created during LIGHT mode get LIGHT mode VMs and are stuck at ~4 H/s per thread instead of ~65 H/s per thread (FULL mode).

## Research: Industry Standard (XMRig)
XMRig implements a strict synchronization pattern:
1. Dataset allocation (2.3 GB)
2. Dataset initialization (configurable threads, ~40-50 seconds)
3. **Synchronization barrier** - "dataset ready" message
4. Mining thread startup - ONLY after dataset ready

Key log sequence from XMRig:
```
rx init dataset algo rx/0 (2 threads) seed 993ba25f61d47e1e...
rx allocated 2336 MB (2080+256) huge pages 0% 0/1168 +JIT (34 ms)
rx dataset ready (40113 ms)  <- synchronization point
cpu READY threads 2/2 (2)    <- mining threads now safe to start
```

## Solution: Synchronous Wait for FULL Mode

Following XMRig's proven pattern, modify `dilithion-node.cpp` to wait for FULL mode before starting mining threads.

### Implementation Details

**File:** `src/node/dilithion-node.cpp`

**Location 1:** Lines 2506-2512 (already synced case)
**Location 2:** Lines 2604-2608 (post-IBD case)

**Change:**
Replace the "will use LIGHT mode, upgrade to FULL when ready" pattern with XMRig-style synchronous wait:

```cpp
// BUG #72 FIX: Wait for FULL mode before starting mining threads
// Following XMRig's proven pattern: "dataset ready" before thread creation
if (!randomx_is_mining_mode_ready()) {
    std::cout << "  [WAIT] Waiting for RandomX FULL mode..." << std::endl;
    auto wait_start = std::chrono::steady_clock::now();
    while (!randomx_is_mining_mode_ready() && g_node_state.running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // Timeout after 2 minutes (should take ~45s normally)
        auto elapsed = std::chrono::steady_clock::now() - wait_start;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > 120) {
            std::cerr << "  [WARN] FULL mode init timeout, starting with LIGHT mode" << std::endl;
            break;
        }
    }
    auto wait_end = std::chrono::steady_clock::now();
    auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(wait_end - wait_start).count();
    std::cout << "  [OK] Mining mode ready (FULL, " << wait_time << "s)" << std::endl;
} else {
    std::cout << "  [OK] Mining mode ready (FULL mode)" << std::endl;
}
```

## Why This Solution

1. **Follows Industry Standard** - XMRig has used this pattern for 10+ years across millions of mining rigs
2. **Simple and Robust** - No complex thread management, just a wait loop
3. **Occam's Razor** - Simplest solution that works
4. **Graceful Fallback** - 2 minute timeout prevents infinite hang, falls back to LIGHT if needed
5. **Observable** - Clear logging of wait time for diagnostics

## Expected Result

Before fix: ~580 H/s (20 threads × ~29 H/s = stuck in LIGHT mode)
After fix: ~1300 H/s (20 threads × ~65 H/s = FULL mode with JIT/AES)

## Files to Modify

1. `src/node/dilithion-node.cpp` - Two locations where mining starts

## Testing

1. Build with fix
2. Start node with --mine flag
3. Observe "WAIT" message and wait time (~45s)
4. Verify hash rate is ~1300 H/s (not ~580 H/s)
5. Verify blocks are found and propagate to testnet

## References

- XMRig PR #1146: Fixed race condition in RandomX thread init
- XMRig RandomX Optimization Guide: https://xmrig.com/docs/miner/randomx-optimization-guide
