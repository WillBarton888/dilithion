# TX-INDEX — Operator Runbook

This is the operator-facing runbook for Dilithion's transaction index
(`-txindex`). Audience: node operators deploying or troubleshooting the
feature on testnet, regtest, or mainnet seeds. For architecture and code
references, see [`TX-INDEX.md`](TX-INDEX.md).

---

## When to enable `-txindex`

Enable only if you need fast `getrawtransaction` / `gettransaction` RPC
lookups for transactions outside the mempool. Common reasons:

- Running a public-facing block explorer or wallet API
- Bridge relayer that scans historical txs by hash
- Forensic / audit tooling that hashes-to-tx many times per second

Do NOT enable on:

- Headless mining nodes (no RPC tx lookups → no benefit)
- Resource-constrained boxes (the index roughly doubles leveldb working
  set size and adds a one-time multi-hour reindex on cold start)
- Production seeds without a soak run on a single seed first (see §Soak)

The index is **default-OFF**. With `-txindex=0` (the default) the binary
behaves byte-for-byte identically to the pre-port version.

---

## First-time enablement on a populated chain

`-txindex=1` on a node whose datadir already has block history requires
explicit acknowledgement of the multi-hour rebuild cost. The binary
will refuse to start otherwise.

### Cold-start procedure

1. **Stop the node cleanly.** Use the wrapper's stop signal or `SIGINT`
   to the binary. Do NOT kill -9 (could leave a stale leveldb LOCK).

2. **Take a backup of the datadir** (chainstate, blocks, indexes, plus
   wallet.dat if applicable). The reindex itself does not modify the
   chainstate or blocks — but a backup is cheap insurance.

3. **First run with both flags:**

   ```
   ./dilithion-node --txindex --reindex
   ```

   The `--reindex` is mandatory on first enablement. Without it, you
   will see:

   ```
   [txindex] -txindex=1 on a non-empty chain requires -reindex to
   acknowledge a multi-hour rebuild. Aborting.
   ```

   and the process exits non-zero.

4. **Watch the reindex progress.** Expect log lines every 1000 blocks:

   ```
   [txindex] indexed 1000/47406 blocks
   [txindex] indexed 2000/47406 blocks
   ...
   [txindex] indexed 47406/47406 blocks (sync complete)
   ```

   Reference timing (47K blocks on a current mainnet seed): roughly
   30 minutes wall clock. Linear in chain depth; mostly CPU + disk-bound.

5. **After "(sync complete)" appears, the index is ready.** RPC calls
   to `getrawtransaction` / `gettransaction` will hit the fast path.

### Subsequent restarts

After the first cold rebuild, restart the node with `--txindex` only —
no `--reindex`. The index resumes from `last_indexed_height + 1` and
catches up incrementally:

```
[txindex] resuming from height 47406 (chain tip 47410, gap=4 blocks)
[txindex] indexed 47410/47410 blocks (sync complete)
```

If you forget `--txindex` on restart, the index goes inert (callbacks
don't fire). Re-enabling later silently catches up the gap — but
operators usually want consistent behavior, so pick one and stick with it.

---

## Verifying the fast path is working

Once the index is built, the next time a fast-path tx lookup happens you
will see (operator-visible info log):

```
[RPC] Found transaction <txid> at block <blockhash> [txindex]
```

The `[txindex]` suffix indicates the response came from the fast path
instead of the legacy tip-walk. If you don't see the suffix on confirmed
non-mempool tx lookups, the index isn't being consulted — see §Troubleshooting.

To benchmark the speedup, time a `getrawtransaction` call against a tx
deep in the chain (e.g., > 10000 blocks back). With the fast path the
response should return in single-digit milliseconds; the legacy tip-walk
takes seconds-to-tens-of-seconds proportional to chain depth.

---

## Soak procedure (recommended before mainnet enablement)

Before enabling `--txindex` on a mainnet seed serving public traffic,
run a soak on a single non-public seed for ≥24 hours under realistic
load:

1. Pick a seed that is currently caught up to tip and has been stable
   for the last 24h (no recent restarts, no checkpoint adjustments).
2. Stop it, back up the datadir, restart with `--txindex --reindex`.
3. Wait for "(sync complete)".
4. Replay realistic RPC traffic against it (mirror traffic from a
   public seed via socat, or use a synthetic load generator hitting
   `getrawtransaction`).
5. Watch the operator log for ≥24h. Specifically check for:
   - Any `[txindex] WARN paranoia mismatch` lines (should be zero
     under normal operation; non-zero indicates a real issue —
     see §Troubleshooting)
   - Any `[txindex] WriteBlock failed` or `EraseBlock failed` lines
     (should be zero unless disk filled up)
   - leveldb directory size growth at `<datadir>/indexes/txindex/`
     (steady linear growth tracking chain growth; sudden jumps are
     suspicious)
   - System resource use: CPU, RSS, disk I/O, file descriptor count
6. After 24h clean, the seed is a candidate for promotion to public-
   serving with `--txindex`. Promote one seed at a time, never all at
   once.

---

## Disk and resource sizing

Per record on disk: ~73 bytes (33-byte key + 40-byte value). Per-block
overhead: roughly `tx_count_in_block * 73` bytes plus leveldb
amplification (typically 2-3×).

Reference numbers at 47K blocks (current mainnet):

| Metric | Approximate value |
|---|---|
| Index leveldb size on disk | ~50-100 MB |
| Cold reindex wall time | ~30 min |
| Steady-state index update per block | <1 ms |
| RPC fast-path query wall time | <10 ms |
| LevelDB block cache RAM at runtime | ~10-30 MB |

These scale linearly with chain depth; expect roughly 2× the values at
~94K blocks, etc.

---

## Disabling `-txindex` cleanly

To roll back:

1. Stop the node cleanly.
2. Restart without `--txindex` (just remove the flag).
3. The binary runs in default mode; the index leveldb at
   `<datadir>/indexes/txindex/` is left in place but inert (no callbacks
   fire, no reads happen).
4. To reclaim the disk space, after the node is stopped:

   ```
   rm -rf <datadir>/indexes/txindex/
   ```

   This is safe — the index is a derived artifact; it can always be
   rebuilt from the canonical chainstate via `--txindex --reindex`.

5. Re-enabling later (`--txindex` again, no `--reindex` if the leveldb
   directory still exists): on startup, the C7 integrity check
   validates that the meta record's truncated 8-byte hash matches the
   current main-chain block at `last_indexed_height`. If the chain
   reorged below `last_indexed_height` while the index was off, the
   integrity check wipes the index atomically and forces a full rebuild
   — you'll see:

   ```
   [txindex] startup integrity check failed at height N -- wiping
   index and resetting to -1
   ```

   followed by a normal reindex from genesis.

---

## Troubleshooting

### `Aborting.` on startup with no further info

You're starting `--txindex=1` on a chain with `tip > 0` and meta says
`last_indexed=-1` (cold) without `--reindex`. Add `--reindex` and try
again.

### `[txindex] failed to open index database (likely stale LOCK file …)`

Another process holds the leveldb at `<datadir>/indexes/txindex/`, OR a
prior unclean shutdown left a stale LOCK file. Resolution:

```
ls -la <datadir>/indexes/txindex/
# If you see LOCK and no other process is running:
rm <datadir>/indexes/txindex/LOCK
./dilithion-node --txindex
```

If another process IS running on that datadir, you have a real conflict;
stop the duplicate first.

### `[txindex] could not create <path>: <reason>`

Filesystem-level error during directory creation. Check parent dir
permissions, free disk space, and SELinux/AppArmor labels if applicable.
Common causes:

- Wrong owner on `<datadir>/indexes/`
- Disk full
- Symlink in the path with restrictive target permissions

### `[txindex] WriteBlock failed at height H` (during normal operation)

The connect callback ran but the leveldb write failed. Check:

- Free disk space at `<datadir>/indexes/txindex/`
- Filesystem health (`dmesg | grep -i error`)
- File descriptor limit (`ulimit -n` ≥ 65536; per `feedback_seed_node_ulimit.md`)

The chain is unaffected — only the index is lagging. Once the disk issue
is resolved, restart the node and let the catchup run. If the gap is
>1000 blocks, run with `--reindex` to rebuild from scratch (faster than
gap-fill at large gaps).

### `[txindex] WARN paranoia mismatch txid=… indexed_block=…`

The fast path found an index entry for a txid, read the indicated block,
deserialized it, and the tx at the indicated position has a DIFFERENT
hash than the queried txid. The handler falls through to tip-walk and
returns the correct answer to the client — the operator just sees this
log.

A small number of these (single digits over hours) is normal during
reorgs. A growing rate over time (10s/minute steady-state) indicates
real index corruption. Resolution:

```
# Stop the node
# Wipe the index and rebuild from canonical chainstate
rm -rf <datadir>/indexes/txindex/
./dilithion-node --txindex --reindex
```

### Index isn't being used (no `[txindex]` suffix on RPC log lines)

Check:

1. The binary you're running has `--txindex` in its argv (`ps -ef | grep
   dilithion-node`)
2. The startup log includes `[OK] Transaction index initialized`
3. `<datadir>/indexes/txindex/` exists and contains files
4. The tx you're querying is NOT in the mempool (mempool path takes
   precedence over the fast path; that's by design)

### Slow reindex (>2× the reference timing)

Diagnostics:

- `iostat -x 5` — high `await` = disk-bound; SSD recommended
- `top` — high CPU on the node binary = CPU-bound; expected on weaker
  CPUs
- Chain depth / mainnet vs testnet: testnet's much higher block density
  in some windows can take longer

Cancel and restart is safe — the meta is updated per block, so the
next run resumes where the prior one left off (no work lost).

---

## What the index does NOT do

- Index mempool transactions (mempool already has its own lookup)
- Survive a chain reset / hard fork that rewrites history below
  `last_indexed_height` (the C7 integrity check will wipe and rebuild
  on next start — operator just sees a wipe log line)
- Provide a stable cross-version on-disk format (the schema version
  byte is `0x01`; if a future Dilithion changes it, expect another
  reindex)
- Replicate to other nodes (each node maintains its own index from
  its own chainstate)

---

## References

- Architecture: [`TX-INDEX.md`](TX-INDEX.md)
- Source: `src/index/tx_index.{h,cpp}`, `src/rpc/server.cpp` (fast-path
  hooks), `src/node/dilithion-node.cpp` (flag plumbing + callbacks)
- Plan + audit chain (engineering reference, not operator surface):
  `.claude/contracts/port_txindex_implementation_plan.md`,
  `.claude/contracts/txindex_port_close_brief.md`
- Related operator rules: `feedback_seed_node_ulimit.md` (fd limits),
  `feedback_no_unicode_in_logs.md` (ASCII-only log lines — applied
  throughout this code path)
