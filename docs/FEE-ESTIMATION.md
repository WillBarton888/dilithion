# Fee Estimation -- Operator Runbook

## Overview

Dilithion's adaptive fee estimator is a port of Bitcoin Core v28.0's
`CBlockPolicyEstimator` (`src/policy/fees.{h,cpp}`). It watches mempool
admission events vs block-confirmation latency, builds rolling
histograms per-confirmation-target, and -- once accumulation is
sufficient -- can answer "what fee rate confirms within N blocks at
X% confidence?" via the `estimatesmartfee` RPC.

This document covers the operator surface: lifecycle, on-disk schema,
log lines, configuration flags, and recovery from corruption.

PR-EF-2 (this document) wires the estimator to the live mempool +
chainstate. PR-EF-3 (separate sub-PR) adds the `estimatesmartfee`,
`estimaterawfee`, and `savefeeestimates` RPCs. Until PR-EF-3 lands the
estimator accumulates silently; no external query surface is exposed.

## Lifecycle

### Startup

The fee estimator is allocated and brought online during node start,
between chainstate load and P2P listen activation:

1. Chainstate loaded.
2. `g_tx_index` initialized (if `-txindex=1`).
3. **Fee estimator allocated** (if `-feeestimates=1`, default).
   `LoadFeeEstimates(<datadir>)` reads `fee_estimates.dat` and
   restores tracked-tx + bucket histogram state if the file is valid;
   otherwise cold-starts.
4. Block-connect callback registered on the chainstate. Each
   `ConnectTip` will deserialize the block's transactions, filter out
   the coinbase, and feed the non-coinbase txid list to
   `processBlock`.
5. Mempool persistence loads (`mempool.dat`). Replayed admits flow
   through `CTxMemPool::AddTx` with `bypass_fee_check=true`; the
   estimator's `processTx` hook treats `bypass_fee_check==true` as
   `valid_fee_estimate=false` and ignores them, matching Bitcoin
   Core's `validFeeEstimate` semantics.
6. P2P listen starts.

### Live operation

- `CTxMemPool::AddTx` (public, lock-acquiring): on successful admit,
  releases the mempool lock then calls `g_fee_estimator->processTx`.
  Lock-order discipline: estimator's internal mutex is independent of
  mempool's `cs`; we never hold both.
- `CTxMemPool::ReplaceTransaction` (RBF): evicted conflicts are
  reported to the estimator as `removeTx(in_block=false)`; the
  replacement tx is reported as a fresh `processTx` admit.
- `CTxMemPool::CleanupExpiredTransactions` and `EvictTransactions`:
  removed txs are reported as `removeTx(in_block=false)`.
- `CChainState::ConnectTip`: the block-connect callback walks
  non-coinbase txs in the block and calls `processBlock(height,
  confirmed_txhashes)`. The estimator records confirmation latency
  for each tracked tx that confirmed in this block, then ages out
  unconfirmed-tx ring buffer slots.
- `CTxMemPool::RemoveConfirmedTxs`: purely a mempool hygiene path;
  the estimator already saw the confirmations via the connect
  callback and does not need to be re-notified.

  Ordering note: at `consensus/chain.cpp:1287->1311` the connect
  callback fires FIRST, then `RemoveConfirmedTxs` cleans the
  mempool. This ordering is significant for clarity. Reordering
  would not break the estimator -- `processBlock` only inspects
  its own tracked-set, not the mempool, so the confirms are
  independent of mempool state at the time of the call -- but is
  worth noting so future refactors don't trip over it.

### Shutdown

Mirrors Bitcoin Core's `init.cpp Shutdown()` ordering exactly:

1. Stop mining.
2. Stop P2P (`CConnman::Stop`) -- no new tx relay arrives.
3. Stop RPC server -- no new `sendrawtransaction` arrives.
4. `DumpMempool(<datadir>)` -- writes `mempool.dat`.
5. **`DumpFeeEstimates(<datadir>)`** -- writes `fee_estimates.dat`.
   Runs AFTER mempool dump so the estimator never references a tx
   that the mempool has already forgotten about.
6. Trust scores save, NodeContext shutdown, blockchain close.

## Configuration

### `-feeestimates=<0|1>` (default 1)

When `0`:
- The estimator is not allocated; `g_fee_estimator` stays null.
- All mempool / chainstate hooks early-return (null-safe).
- `LoadFeeEstimates` is not called at startup.
- `DumpFeeEstimates` is not called at shutdown.
- Existing `fee_estimates.dat` (if any) is left untouched on disk.
- Once PR-EF-3 lands, `estimatesmartfee` will return an
  insufficient-data error.

When `1` (default), all of the above are active.

Use `-feeestimates=0` only if the disk-write cost is unacceptable
(unusual; the estimator's working set is well under 1 MB and the
dump is sub-ms). The estimator costs <1% CPU on a busy node.

## On-disk schema

File: `<datadir>/fee_estimates.dat`

```
+0     u8       version_byte = 0x01
+1     u8[32]   xor_key                 (cleartext)
+33    ...      scrambled body
+N     u8[8]    sha3_256_truncated      (scrambled)
```

Body (logical fields, XOR-scrambled with the key):
```
u32   best_seen_height
u32   historical_first
u32   historical_best
u32   bucket_count
for each bucket:
    i64   bucket_upper_bound_milli_ions
for each horizon (short, med, long):
    u32   confirm_periods
    u32   bucket_count
    u32   unconf_depth
    [...]conf_avg, fail_avg, tx_ct_avg, unconf_txs, old_unconf
u64   tracked_tx_count
for each tracked tx:
    u8[32] txhash
    u32    height
    u32    bucket_index
    u8     horizon_mask
```

Atomic write: `fee_estimates.dat.new` is fsync'd, then renamed. Torn
writes leave the prior file intact.

## Log lines

### Startup

- `[fee_estimator] LoadFeeEstimates: restored N tracked txs` -- success.
- `[fee_estimator] LoadFeeEstimates: <reason> -- starting fresh` --
  cold-start (file missing, version mismatch, footer mismatch,
  malformed body, bucket-ladder mismatch). Estimator is functional;
  it just resets accumulation.
- `[fee_estimator] LoadFeeEstimates hard error: <message>` -- the
  datadir was unreadable. The node continues with a fresh estimator.
- `  [OK] Fee estimator initialized` -- callback registered, ready.

### Block connect

- `[fee_estimator] block-connect: DeserializeBlockTransactions failed
  at height N: <error> -- estimator skips this block` -- block was
  malformed at the deserialization layer. Should be impossible for a
  block already accepted into the chain; if it ever fires, the chain
  has bigger problems than fee estimation.

### Shutdown

- `[fee_estimator] DumpFeeEstimates: wrote N bytes (M tracked txs)`
  -- success.
- `[fee_estimator] DumpFeeEstimates failed: <message> -- prior
  fee_estimates.dat retained` -- transient I/O failure (disk full,
  permission denied, etc.). The prior file is untouched, so on next
  start the operator will load slightly stale state but no data is
  lost.

## Failure modes and recovery

| Symptom                                         | Cause                              | Action                                                                 |
|-------------------------------------------------|------------------------------------|------------------------------------------------------------------------|
| Cold-start log every restart                    | `fee_estimates.dat` missing        | Normal on first run; suppresses after one clean shutdown.              |
| "version mismatch -- starting fresh"            | Schema bump in a release           | Expected on upgrade. State will rebuild over ~25 blocks.               |
| "footer mismatch -- starting fresh"             | File corruption or mid-write power loss | Delete the file, restart. State will rebuild over ~25 blocks.     |
| "bucket-ladder mismatch -- starting fresh"      | Internal constants changed         | Same as version mismatch. Expected only on a release upgrade.          |
| `DumpFeeEstimates failed` on shutdown           | Disk full / permission denied       | Free space / fix permissions. Prior file is intact; loss is at most one session of accumulation. |
| Persistent absence of restored txs after a clean restart | Operator changed datadir          | Confirm `<datadir>/fee_estimates.dat` exists and is non-empty.         |

## Accumulation period

Bitcoin Core's algorithm requires `ACCUMULATION_BLOCKS_MIN = 25`
blocks of observation before any estimate is returned. Until that
many blocks have flowed through `processBlock`, the estimator
returns "insufficient data". After the threshold is crossed:

- Short horizon (12-block window): adapts within ~25 blocks of a
  fee-rate change.
- Medium horizon (24-block window): adapts within ~200 blocks.
- Long horizon (42-block window): adapts within ~1500 blocks.

This means: fresh-genesis nodes will show "insufficient data" for
the first ~25 blocks after sync. Restarting from a non-corrupt
`fee_estimates.dat` skips this warm-up.

## Disabling for testing

To run a node without the estimator (e.g. while reproducing a
mempool-only bug):

```
./dilithion-node --feeestimates=0
```

The mempool admit / RBF / eviction paths early-return on the null
`g_fee_estimator` pointer. No state is written to or read from
disk. To re-enable, drop the flag (default ON) or pass
`--feeestimates=1`.

## See also

- `src/policy/fees.{h,cpp}` -- estimator core (PR-EF-1).
- `src/policy/fee_persist.{h,cpp}` -- on-disk schema (PR-EF-1).
- `src/node/mempool_persist.{h,cpp}` -- pattern this module mirrors.
- `.claude/contracts/contract_estimatesmartfee.md` -- full project
  contract.
- Bitcoin Core v28.0 `src/policy/fees.{h,cpp}` -- upstream reference.
