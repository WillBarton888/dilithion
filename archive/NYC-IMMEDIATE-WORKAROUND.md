# NYC Node Stuck Issue - IMMEDIATE WORKAROUND

## Quick Fix (Test Immediately)

Try forcing the node to use LIGHT mode (which doesn't trigger multi-threaded initialization):

```bash
# On NYC server, set environment variable to force LIGHT mode
export DILITHION_FORCE_LIGHT_MODE=1

# Or start with limited memory to trigger LIGHT mode
ulimit -m 2097152  # Limit to 2GB RAM
./dilithion-node --testnet
```

## Alternative: CPU Affinity Fix

Force the process to use only 1 CPU core:

```bash
# Start node with CPU affinity set to single core
taskset -c 0 ./dilithion-node --testnet

# Or using numactl
numactl --cpunodebind=0 --physcpubind=0 ./dilithion-node --testnet
```

## Root Cause

The NYC node (2 CPUs, 3.8GB RAM) gets stuck during RandomX FULL mode initialization because:

1. It detects 3.8GB RAM and chooses FULL mode (requires 2.5GB dataset)
2. It detects 2 CPUs and spawns 2 threads for parallel dataset initialization
3. The multi-threaded `randomx_init_dataset()` call hangs indefinitely

Singapore/London nodes (1 CPU, 1.9GB RAM) work because:
1. They use LIGHT mode (< 3GB RAM)
2. Even if they used FULL mode, single-threaded init wouldn't trigger the bug

## Permanent Fix

Apply this patch to `src/crypto/randomx_hash.cpp` line 101:

```cpp
// Force single-threaded RandomX dataset initialization
unsigned int num_threads = 1;  // Was: std::thread::hardware_concurrency();
```

## Testing the Fix

1. **Immediate Test**: Force LIGHT mode with environment variable
2. **CPU Affinity Test**: Limit to 1 CPU core with taskset
3. **Code Fix Test**: Apply the patch and recompile

The issue is a race condition or deadlock in RandomX's multi-threaded dataset initialization that only triggers with 2+ CPU cores.