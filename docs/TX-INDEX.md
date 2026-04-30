# TX-INDEX (Transaction Index)

This document describes Dilithion's `CTxIndex` subsystem: an opt-in,
separately-stored leveldb index that maps a transaction id (`txid`) to the
`(block_hash, position_in_block)` pair where the transaction was confirmed.
The index is a port of Bitcoin Core v28.0's `TxIndex` adapted to Dilithion's
storage layout (block bodies live in leveldb keyed by hash, not in flat
files), simplified for KISS (no `BaseIndex` abstraction), and integrated
behind two CLI flags: `-txindex=1` enables the subsystem, `-reindex` is a
one-shot acknowledgement required to consent to a multi-hour cold rebuild.

The index is **default OFF**. Operators who do not set `-txindex=1` see
zero behavioural change versus pre-port: every JSON-RPC `getrawtransaction`
or `gettransaction` call falls through to the legacy tip-walk.

## Purpose

Without an index, `getrawtransaction(txid)` walks the chain tip-to-genesis
reading every block until the transaction is found. On a synced node with
hundreds of thousands of blocks, that is many seconds per call -- effectively
unusable for an explorer, wallet backend, or any RPC consumer.

`CTxIndex` reduces a typical `getrawtransaction` lookup to a single leveldb
read followed by one `ReadBlock` against the block store. On a healthy
index this is millisecond-class.

The fast path is **surgical**: it is inserted before the legacy tip-walk in
`RPC_GetRawTransaction` and `RPC_GetTransaction`, and on any anomaly
(missing block, hash mismatch, deserialization failure) it logs a WARN and
falls through to the legacy code path. Existing behaviour is preserved on
every error branch.

## Architecture / schema

The index lives in its own leveldb instance at:

```
<datadir>/indexes/txindex/
```

This is **separate** from the block-store leveldb (`<datadir>/blocks/`)
and from `chainstate`. The separate-DB choice was a Rev 2 plan revision
(see `port_txindex_implementation_plan.md` Rev 2 changes table) made to
eliminate prefix-collision risk against the block store, mirror Bitcoin
Core's directory convention, and let the index be deleted independently
of the chain.

Two key types live in this DB:

### Per-tx record (one per transaction)

* Key: `"t"` (1 byte) + raw 32-byte txid = **33 bytes**.
* Value: 40 bytes laid out as:
  * byte 0: schema version (`0x01`).
  * bytes 1..32: block hash (raw `uint256`).
  * bytes 33..36: tx position within block (`uint32_t` little-endian).
  * bytes 37..39: reserved zeros (room for future flags).

### Metadata record (single, fixed)

* Key: `"\x00meta"` (5 bytes). The leading null byte sorts before any
  printable-ASCII prefix, so a future `it->Seek("t")` scan can never
  observe the meta record.
* Value: 13 bytes laid out as:
  * byte 0: schema version (`0x01`).
  * bytes 1..4: last-indexed height (`int32_t` LE; `-1` sentinel = nothing
    indexed).
  * bytes 5..12: last-indexed block hash, truncated to 8 bytes
    (full hash recoverable from `mapBlockIndex`; truncation is a sanity
    check on resume).

The version byte lets a future migration detect schema rev 2 cheaply
without rewriting every record on first read.

We do not serialise a file/offset (Bitcoin Core's `CDiskTxPos`) because
Dilithion stores blocks keyed by hash in leveldb, not in flat files --
`m_blockchain->ReadBlock(block_hash)` is already an O(1) leveldb read.

## Threading model

`CTxIndex` is touched from three threads:

1. **Connect callback thread** (chain validator). Fires from
   `CChainState::ActivateBestChain` after each successful block connect.
   Calls `g_tx_index->WriteBlock(block, height, hash)`. **Holds `cs_main`**
   when the callback fires (verified at `src/consensus/chain.cpp:1289`,
   contract reference line 1474). The recursive nature of `cs_main` means
   the callback's thread already owns the lock; `WriteBlock` therefore must
   not call any function that re-enters `CChainState`.
2. **Disconnect callback thread** (chain validator). Fires from
   `CChainState::DisconnectTip` after a successful disconnect. Calls
   `g_tx_index->EraseBlock(block, height, hash)`. **Does NOT hold `cs_main`**
   when the callback fires (verified at `src/consensus/chain.cpp:1465`,
   contract reference line 1656; the in-tree comment at chain.cpp lines
   1283-1285 and 1460-1462 claiming "We don't hold cs_main during callbacks"
   is correct ONLY for the disconnect path).
3. **Reindex thread** (owned by `CTxIndex::m_sync_thread`). Spawned by
   `StartBackgroundSync()`; iterates heights from `last_indexed + 1` to
   the tip-height snapshot taken once at thread entry, resolving each
   height to a block hash via `g_chainstate.GetBlocksAtHeight(h)` (and
   preferring the on-main-chain block via `IsOnMainChain()` when more
   than one block exists at that height), reads each block from the
   block store, and writes the corresponding tx records. Holds `m_mutex`
   only inside `WriteBlock` (never while calling into `CChainState`).
   Honors `m_interrupt` between blocks.

### The `cs_main` asymmetry

The connect/disconnect lock asymmetry is real and load-bearing for the
correctness of every callback consumer (wallet, identity DB, DNA registry,
VDF cooldown, txindex). The plan documents the constraint truthfully
(`port_txindex_implementation_plan.md` section 4); txindex is implemented
within it:

* `WriteBlock` and `EraseBlock` use `m_db` (leveldb internal mutex), the
  block-store DB (separate `cs_db` mutex), and pure deserialization. Neither
  reaches into `CChainState`.
* `m_mutex` is **never** held while calling into `CChainState`. The reindex
  thread reads `chain.GetTip()->nHeight` once at thread start (atomic
  pointer load), then resolves each height to a block hash via
  `GetBlocksAtHeight` / `GetBlockIndex` (both of which acquire `cs_main`
  internally) without acquiring `m_mutex` in the read path. Mid-walk
  reorgs are tolerated by the live-callback gating below.
* `FindTx` (called from RPC) takes `m_mutex` only. It does not touch
  `CChainState`. The RPC caller takes any chain locks separately, after
  `FindTx` returns.

### Live-vs-reindex gating

Without gating, the reindex thread and the live callback could race on the
same block (reindex catching up while IBD progresses). The fix is in
`CTxIndex::WriteBlock`: under `m_mutex`, it short-circuits if
`height <= m_last_height`. Strict monotonic meta. This makes both writers
safe regardless of arrival order and makes the operation idempotent under
the legitimate retry case (e.g., disconnect-reconnect cycle).

## Lifecycle

Startup (one-shot, single-threaded, on the main init thread):

1. Operator passes `-txindex=1` (and `-reindex` if cold-starting on a
   non-empty chain).
2. `g_tx_index = std::make_unique<CTxIndex>()`.
3. `g_tx_index->Init(<datadir>/indexes/txindex, &g_blockchain_db)` opens
   the leveldb, loads metadata, performs the C7 startup integrity check
   (described below). Returns `false` on disk error or schema mismatch
   (operator must investigate).
4. The N2 cold-acknowledgement gate runs: if `LastIndexedHeight() == -1`
   AND `tip > 0` AND `!reindex_flag`, the node aborts with a clear error
   message (see Operator surface).
5. Connect/disconnect callbacks are registered against `g_chainstate`.
6. `g_tx_index->StartBackgroundSync()` spawns the reindex thread (no
   parameter -- the thread reads `g_chainstate` directly via the
   process-wide singleton).

Runtime: the reindex thread walks to tip, sets `m_synced = true`, exits.
Live callbacks continue to update the index for every new block.

Shutdown:

1. `g_tx_index.reset()` is called BEFORE chain shutdown. This calls
   `~CTxIndex()` which calls `Stop()` (sets `m_interrupt`, joins the
   reindex thread, idempotent), takes `m_mutex`, and closes the leveldb.
2. Callback lambdas guard with `if (g_tx_index)` so any post-reset
   callback is a no-op.

Mirrors Bitcoin Core's `init.cpp` ordering for `g_txindex.reset()`.

## Startup integrity check (C7)

`Init` validates the persisted state against the live chain:

1. Reads the meta record. If `last_indexed >= 0`, looks up the block at
   that height in `mapBlockIndex` and compares the truncated 8-byte hash.
2. On mismatch (chain reorged below `last_indexed` while txindex was off),
   wipes ALL `t`-prefix entries plus the meta record in a SINGLE leveldb
   `WriteBatch`, resets `m_last_height = -1`, and forces a full rebuild.
3. Logs a WARN with the mismatch details so the operator sees the cause.

The wipe is atomic: leveldb applies a `WriteBatch` either fully or not at
all. A kill mid-iteration (between the `Delete()` accumulation and the
`Write()` commit) leaves the on-disk state untouched. A kill after
`Write()` returns leaves the fully-wiped state. There is no partial-wipe
state visible across restarts. The single-batch invariant is observable
in tests via `tx_index_test_hooks::g_wipe_write_count`, which increments
exactly once per `WipeIndex()` call regardless of how many keys were
deleted.

## Operator surface

### Flags

* `-txindex=1`: enables the subsystem. Default OFF.
* `-reindex`: one-shot acknowledgement required when starting `-txindex=1`
  on a non-empty chain with no prior index (`LastIndexedHeight() == -1`
  AND `tip > 0`). Without this flag, the node aborts with:

  ```
  [txindex] -txindex=1 on a non-empty chain requires -reindex to acknowledge a multi-hour rebuild. Aborting.
  ```

  This gate prevents an operator who flips `-txindex=1` on a long-running
  node from silently triggering an hours-long rebuild they didn't expect.
  The flag is consumed once: subsequent restarts without `-reindex` are
  fine because the index now has a non-sentinel `LastIndexedHeight()`.

### Expected log lines

Progress (every 1000 blocks during reindex):

```
[txindex] indexed N/M blocks
```

Resume (warm-stale case: meta says last_indexed=N, tip is M>N):

```
[txindex] resuming from height N (chain tip M, gap=K blocks)
```

Sync complete:

```
[txindex] indexed M/M blocks (sync complete)
```

Cold-acknowledgement abort (operator must add `-reindex`):

```
[txindex] -txindex=1 on a non-empty chain requires -reindex to acknowledge a multi-hour rebuild. Aborting.
```

Paranoia mismatch (RPC fast-path saw a tx-record whose indexed block did
not actually contain the txid; falls through to legacy scan; counter
increments via `IncrementMismatches`):

```
[txindex] WARN paranoia mismatch txid=<16hex>... indexed_block=<16hex>... -- falling through to scan
```

The WARN literal uses ASCII double-hyphen (`--`) per `feedback_no_unicode_in_logs.md`;
PR-7b made the swap in `src/rpc/server.cpp` and PR-7d completed it across
`src/index/tx_index.cpp`.

Shutdown:

```
[txindex] shutting down
```

### Rollback

Stop the node, `rm -rf <datadir>/indexes/txindex/`, restart with
`-txindex=0`. The `chainstate` and `blocks` databases are untouched. On
the next startup with `-txindex=1` the operator must pass `-reindex` to
re-acknowledge the rebuild.

## Source references

* `src/index/tx_index.h` -- `CTxIndex` declaration; thread/lock contract
  comments; `tx_index_test_hooks` namespace declaration.
* `src/index/tx_index.cpp` -- implementation: leveldb open/close, meta
  read/write, ser/de, `WriteBlock` / `EraseBlock` / `FindTx`, sync loop,
  C7 wipe.
* `src/node/dilithion-node.cpp` -- DIL chain integration: parses
  `-txindex` and `-reindex`, instantiates `g_tx_index`, runs the N2
  cold-acknowledgement gate, registers callbacks, starts background sync.
* `src/node/dilv-node.cpp` -- DilV chain integration; mirrors
  dilithion-node.cpp for the parallel chain.
* `src/rpc/server.cpp` -- surgical fast-path branch in
  `RPC_GetRawTransaction` and `RPC_GetTransaction`: `FindTx`, `ReadBlock`,
  paranoia check, fall-through to legacy tip-walk on any anomaly.
* `src/consensus/chain.cpp` -- callback hook sites at lines 1289 (connect)
  and 1465 (disconnect); the `cs_main` asymmetry documented in the
  Threading model section above.
* `src/test/tx_index_tests.cpp` -- 26 unit cases covering Init, schema
  versioning, monotonicity, reindex happy path, reindex resume across
  destruct, C7 wipe atomicity, stale-LOCK error path, stop-mid-walk
  promptness, concurrent reader/writer stress, and the SEC-MD-1/2/3
  invariant gates.
* `src/test/tx_index_integration_tests.cpp` -- 7 integration cases
  exercising the full RPC layer end-to-end: byte-for-byte JSON parity
  between fast-path and tip-walk (TC1), paranoia mismatch fall-through
  (TC2), reorg-no-negative-confirmations (TC3, SEC-MD-1), reindex
  persistence across destruct/reopen (TC4), default-flag-OFF behaviour
  (TC5), N2 cold-reindex acknowledgement (TC6), and mempool-first
  ordering (TC7).
* `.claude/contracts/port_txindex_implementation_plan.md` -- the
  authoritative plan; section 9 carries the PR-by-PR commit history and
  totals.

## Known follow-ups

* **TC2 fall-through-success path** (red-team CONCERN PR6-C1, addressed
  in PR-7a): the original TC2 covered the WARN substring and counter delta
  but did not exercise the success-via-fall-through path. PR-7a adds the
  third assertion block: forge a record `genuine_block2_txid -> (block_1,
  pos=0)`, query `genuine_block2_txid`, assert WARN fires, MismatchCount
  delta == 1, and the RPC envelope contains the genuine txid hex (proving
  the legacy tip-walk found it on the real chain).
* **TC4 deterministic mid-walk capture** (red-team CONCERN PR6-C3,
  addressed in PR-7a): on fast hardware, `Interrupt+Stop` immediately
  after `StartBackgroundSync` may capture `K = kN-1` (full sync). The
  test was renamed to `tc4_reindex_persistence_across_destruct` to
  reflect that the load-bearing property is the persistence guarantee
  across reopen, not mid-walk timing. True mid-walk-determinism would
  require an injectable interrupt point in `StartBackgroundSync`, which
  is out of scope for the LOW-risk PR-7a.
* **TC6 production-startup integration** (red-team CONCERN PR6-C2,
  addressed in PR-7a): TC6 cannot invoke a real subprocess (no harness
  infrastructure). PR-7a adds a build/test-time grep that reads both
  production source files (`src/node/dilithion-node.cpp` and
  `src/node/dilv-node.cpp`) and asserts the literal abort substring is
  present. A future "deploy verification" step or larger refactor can
  add subprocess-based startup tests.
* **`stop_mid_walk_completes_promptly` non-vacuity** (red-team CONCERN
  PR4-C4, addressed in PR-7a): the test was raised to `kN = 5000` blocks
  AND a load-bearing assertion `LastIndexedHeight() < kN-1` was added
  immediately after `Stop()` to prove the thread was interrupted
  mid-walk on the test runner's hardware (not naturally completed).

For the full red-team CONCERN trail, see
`.claude/autonomous/txindex/active/redteam_pr4_diff.md` and
`.claude/autonomous/txindex/active/redteam_pr6_diff.md`.
