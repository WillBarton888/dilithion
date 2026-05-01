# COINSTATSINDEX (UTXO-set Statistics Index)

This document describes Dilithion's `CCoinStatsIndex` subsystem: an opt-in,
separately-stored leveldb index that tracks per-block UTXO-set statistics
(chain-path commitment, count, total amount, per-block additions/removals/
totals, coinbase subsidy + fees). It is a port of Bitcoin Core v28.0's
`CoinStatsIndex` adapted to Dilithion's storage layout and idioms.

> **IMPORTANT:** `hashChainCommitment` (this PR) is **NOT** equivalent to
> BC v28.0's `hash_serialized`. BC's value is a STATE hash; ours is a
> CHAIN-PATH commitment. See [`hashChainCommitment` vs `hash_serialized`](#hashchaincommitment-vs-bcs-hash_serialized)
> below before using the field for any consumer-side check.

The index is **default OFF**. Operators who do not set `-coinstatsindex=1`
see zero behavioural change versus pre-port; the `gettxoutsetinfo` RPC
still falls back to the legacy walk path (PR-BA-3 will add the fast-path
when the index is synced).

## Purpose

Without an index, computing UTXO-set statistics requires walking the entire
UTXO set on every call to `gettxoutsetinfo` -- many seconds on a populated
chain. `CCoinStatsIndex` precomputes those statistics per height, so a
future `gettxoutsetinfo` (PR-BA-3) and `getblockstats` will read in
microseconds instead of seconds.

This PR-BA-2 ships only the index module. The RPC fast-path is in PR-BA-3.

## Architecture / schema

The index lives in its own leveldb instance at:

```
<datadir>/indexes/coinstats/
```

This is **separate** from the txindex's leveldb (`<datadir>/indexes/txindex/`),
the block-store (`<datadir>/blocks/`), and the chainstate. The separate-DB
choice mirrors the txindex layout and lets the index be deleted independently
of any other state.

### Per-height record (one per indexed height)

* Key: `'h'` (1 byte) + 4-byte big-endian height = **5 bytes**.
  Big-endian height ensures lex-order matches numeric order; an iterator
  scan returns blocks in height-ascending order without sorting.
* Value: 89 bytes laid out as:
  * byte 0: schema version (`0x01`).
  * bytes 1..32: `hashChainCommitment` -- raw SHA3-256 chain-path
    commitment (fold of `parent_chain_commitment || delta_record`). NOT a
    UTXO-set state hash; see caveat section below.
  * bytes 33..40: `coinsCount` (`uint64_t` LE).
  * bytes 41..48: `totalAmount` (`uint64_t` LE; sum of UTXO output values).
  * bytes 49..56: `blockAdditions` (`uint64_t` LE).
  * bytes 57..64: `blockRemovals` (`uint64_t` LE).
  * bytes 65..72: `blockTotalOut` (`uint64_t` LE).
  * bytes 73..80: `blockTotalIn` (`uint64_t` LE).
  * bytes 81..88: `blockSubsidyFees` (`uint64_t` LE; coinbase output total).

### Metadata record (single, fixed)

* Key: `"\x00meta"` (5 bytes). The leading null byte sorts before any
  printable-ASCII prefix, so an `it->Seek("h")` scan can never observe
  the meta record. Identical key choice to txindex.
* Value: 13 bytes:
  * byte 0: schema version (`0x01`).
  * bytes 1..4: last-indexed height (`int32_t` LE; `-1` sentinel = nothing
    indexed).
  * bytes 5..12: last-indexed block hash, truncated to 8 bytes (full hash
    recoverable from `mapBlockIndex`; truncation is a sanity check on
    resume).

The version byte lets a future migration detect schema rev 2 cheaply
without rewriting every record on first read.

## `hashChainCommitment` vs BC's `hash_serialized`

This is a load-bearing distinction. The two values look superficially
similar (both 32-byte hashes that "summarise UTXO-set state at height H")
but they implement DIFFERENT INVARIANTS and are NOT interchangeable.

### What `hashChainCommitment` (this PR) actually is

* A **chain-path commitment**: `running_hash := SHA3-256(running_hash ||
  delta_record)`, folded one delta at a time across each block.
* Path-dependent: two chains that converge on the same final UTXO set via
  different orderings produce DIFFERENT `hashChainCommitment` values.
* Intra-block-spend-leaky: a UTXO created and spent inside the same block
  leaves residual contributions in the running hash even though it never
  appears in the final UTXO set.
* Useful for: persistent reorg detection at restart; agreement check with
  another node that took the EXACT SAME chain ordering;
  `BaseIndex` monotonicity.
* NOT useful for: cross-validation against `gettxoutsetinfo` from a
  from-scratch UTXO walk; BC `hash_serialized` cross-check.

### What BC's `hash_serialized` is (NOT IMPLEMENTED HERE)

* A **state hash**: a canonical-traversal SHA-256 over every UTXO
  currently in the set.
* State-equivalent: two chains that converge on the same final UTXO set
  produce the SAME `hash_serialized`, regardless of how they got there.
* Not implemented in Dilithion. PR-BA-3's `gettxoutsetinfo` fast-path
  needs this property and will require a separate design (canonical UTXO
  traversal at query time, or a different multiset accumulator that is
  PQ-secure -- design decision deferred).

### Operator implications

* DO use `hashChainCommitment` for sanity-checking against another
  Dilithion node that has indexed the SAME chain ordering.
* DO NOT compare `hashChainCommitment` against BC's `hash_serialized`,
  against any independently-computed UTXO traversal hash, or against
  any value claiming to be a "UTXO-set state" check.

### SHA-3 substitution

The fold uses SHA-3 (FIPS 202, 256-bit output) per the project-wide
post-quantum hash convention. Module-local; documented in both
`src/kernel/coinstats.h` and `src/index/coinstatsindex.h`.

Per-block fold layout (caller-private; not exposed on disk; only consumed
inside SHA3-256):

```
uint8_t   tag             (0=ADD, 1=REMOVE)
uint8_t   fCoinBase       (0 or 1)
uint32_t  height          little-endian
uint32_t  vout_n          little-endian
uint8_t[32] outpoint_hash raw
uint64_t  nValue          little-endian
uint32_t  spk_len         little-endian
uint8_t[]  scriptPubKey   raw bytes
```

The fold is `running_hash := SHA3-256(running_hash || record)`.
Removals are folded first (writer order from `CBlockUndo::vSpent`); then
additions in canonical (txid_lex_order, vout_index_ascending) order.

## Threading model

Three call sites touch `CCoinStatsIndex`. The pattern mirrors txindex
verbatim (PR-7G R1); see `docs/TX-INDEX.md` for the upstream rationale.

1. **Connect callback thread** (chain validator). Fires from
   `CChainState::ActivateBestChain` after each block connect. Calls
   `WriteBlock(block, height, hash)` **only when `IsSynced()` is true**
   (PR-7G R1: live callbacks gated until reindex caught up). **Holds
   `cs_main`** when the callback fires.
2. **Disconnect callback thread** (chain validator). Calls
   `EraseBlock(block, height, hash)` only when `IsSynced()` is true. Does
   NOT hold `cs_main`.
3. **Reindex thread** (`CCoinStatsIndex::m_sync_thread`). Spawned by
   `StartBackgroundSync()`; runs `SyncLoop`, which wraps an outer loop
   around `WalkBlockRange`. The outer loop walks heights from
   `m_last_height + 1` to a snapshotted tip, then re-reads
   `g_chainstate.GetTip()->nHeight`. If the tip advanced during the walk,
   walks the newly-visible range. `m_synced` flips to `true` ONLY when
   the tip is stable across a full pass.

### `m_running` cache

`CCoinStatsIndex` keeps an in-memory `m_running` (the after-tip stats)
under `m_mutex`. `WriteBlock(H)` folds the block's deltas into
`m_running` to compute the after-`H` snapshot, persists it under key
`'h'+H`, then commits `m_running := after`. `EraseBlock(H)` reads the
parent record (`'h'+(H-1)`) from leveldb and rolls back `m_running` to
that snapshot before deleting the H record.

The on-disk per-height record is the authoritative source; `m_running` is
a hot-path cache that can always be repopulated by re-reading the
last-indexed height on Init.

## Lifecycle

### Cold start (`-coinstatsindex=1` first time on warm chain)

`-reindex` is REQUIRED to acknowledge the multi-hour rebuild. Without
`-reindex`, the node aborts with:

```
[coinstatsindex] -coinstatsindex=1 on a non-empty chain requires -reindex
to acknowledge a multi-hour rebuild. Aborting.
```

This mirrors the txindex N2 cold-acknowledgement gate.

### Warm restart

The on-disk meta records the last-indexed height. On restart:

1. `Init` re-opens leveldb at `<datadir>/indexes/coinstats/`.
2. The meta byte gates schema-version compatibility; mismatch -> close.
3. R5 bound-check rejects pathological INT_MAX heights.
4. The last-indexed record is re-read into `m_running` so the live
   callback can fold incrementally.
5. C7 startup integrity check: if chainstate has a different block at
   the recorded height, wipe and reset to -1. The live callback then
   returns `false` for non-contiguous heights (gating on `IsSynced`
   keeps callbacks inert until the reindex thread catches up).
6. `StartBackgroundSync()` spawns the reindex thread to walk
   `[m_last_height+1, tip]`. Once stable, `m_synced` flips to `true`
   and live callbacks become active.

### Shutdown

`g_coin_stats_index.reset()` runs BEFORE `blockchain.Close()` in
`dilithion-node.cpp` / `dilv-node.cpp` (mirrors txindex N4). The
destructor joins the reindex thread before releasing the leveldb handle.
The reset call also fires from both `catch (const std::exception&)` and
`catch (...)` paths to ensure the thread is joined before chainParams
teardown.

## Expected log lines

Success:

* `[coinstatsindex] indexed N/total blocks`
* `[coinstatsindex] indexed N/total blocks (sync complete)`
* `[coinstatsindex] resuming from height N (chain tip M, gap=K blocks)`
* `[coinstatsindex] shutting down`

Recoverable failure (operator action recommended):

* `[coinstatsindex] reindex: no main-chain block at height H (mid-reorg, K
  candidates) -- bailing walk; outer loop will revisit when the reorg
  settles` -- temporary; the outer loop will re-walk after the reorg
  settles. No action needed.
* `[coinstatsindex] WriteBlock failed at height H ... -- index now lagging
  chain` -- disk error during a live callback. Action: check `IsCorrupted()`
  via `getindexinfo`; if persistent, restart with `-reindex`.

Hard failure (operator action REQUIRED):

* `[coinstatsindex] EraseBlock failed at height H ... -- index may contain
  stale entries` -- sets sticky `m_corrupted` flag. Action: restart with
  `-reindex`.
* `[coinstatsindex] startup integrity check failed at height H -- wiping
  index and resetting to -1` -- C7 integrity check tripped. The wipe is
  automatic; the index will rebuild on the next reindex pass.
* `[coinstatsindex] meta height N is out of bounds ... -- treating as
  corrupt and wiping` -- R5 bound check. Auto-recoverable.
* `[coinstatsindex] failed to open index database (likely stale LOCK file
  from previous unclean shutdown -- remove <path>/LOCK and retry)` --
  Action: remove the LOCK file. **Never** remove other files in the
  index directory; only the LOCK file.

## RPC visibility

`getindexinfo` registers `coinstatsindex` alongside `txindex`:

```json
{
  "txindex": { "synced": true, "best_block_height": 12345 },
  "coinstatsindex": { "synced": true, "best_block_height": 12345 }
}
```

Both keys appear only when the corresponding index is enabled at runtime.
A node started without any index flag returns `{}`.

`best_block_height = -1` is a valid response: the index has been opened
but no rows written yet (cold-start window after `-coinstatsindex=1
-reindex` startup, before SyncLoop emits its first row).

## Recovery / disaster runbook

| Symptom | Action |
|---------|--------|
| `IsCorrupted() == true` (sticky) | Restart with `-reindex` |
| Stale LOCK file blocks startup | Remove `<datadir>/indexes/coinstats/LOCK` |
| Schema version mismatch on Init | Close index; allow C7 wipe on next start |
| Index lagging chain (live callback failure) | Check disk space; restart with `-reindex` if persistent |
| Reorg-during-rebuild | Wait for outer loop to revisit; no manual action |
| `m_synced` stuck at `false` | Check logs for `bailing walk`; let outer loop drive |

## Testing

Unit tests live in `src/test/coinstatsindex_tests.cpp` (default state,
schema-version rejection, R5 INT_MAX bound, stale LOCK error, stop
idempotency, monotonicity, double-disconnect no-op, EraseBlock rollback,
sticky m_corrupted via test hook, C7 wipe, reindex happy path,
round-trip on reopen, live-callback gate).

Integration tests live in `src/test/coinstatsindex_integration_tests.cpp`
(getindexinfo schema-lock with both indexes registered; outer-loop catches
tip advance during walk -- mirrors tx_index E.2; reorg-during-rebuild bail
-- mirrors tx_index E.6).

Run all index tests:

```
./test_dilithion --run_test='coinstatsindex_tests:coinstatsindex_integration_tests'
```

## Bounds / limits

* Maximum reasonable height: 100,000,000 (R5 cap; rejected at Init).
* Per-record write: ~89 bytes plus leveldb framing (~200 bytes/height
  amortised).
* For a 1M-block chain: roughly 200 MB on disk.
* Memory footprint (process-resident): the in-memory `m_running` cache is
  ~64 bytes; leveldb's block cache and write buffer dominate (8 MB by
  default).

## Out of scope for PR-BA-2

* `gettxoutsetinfo` fast-path (PR-BA-3).
* `getblockstats` RPC (PR-BA-3).
* Muhash/`hash_serialized_3` alternate hash algorithms (KISS: ship one).
* `gettxoutsetinfo` `start_height` parameter (BC v25+ feature).
* Snapshot import/export (`assumeutxo` family) -- separate strategic
  workstream.

## Cross-references

* `docs/TX-INDEX.md` -- sister-index pattern; identical BaseIndex
  machinery, separate leveldb.
* Bitcoin Core v28.0 `src/index/coinstatsindex.{h,cpp}` --
  upstream port source.
* Bitcoin Core v28.0 `src/kernel/coinstats.{h,cpp}` --
  upstream primitives source.
