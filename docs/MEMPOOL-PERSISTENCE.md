# Mempool persistence

This document describes Dilithion's mempool persistence subsystem: a port of
Bitcoin Core v28.0's `src/kernel/mempool_persist.{h,cpp}` adapted to
Dilithion's mempool API and conventions. The mempool is saved to
`<datadir>/mempool.dat` on shutdown and restored on startup, eliminating the
"every restart drops the mempool" UX hit.

The subsystem is **default ON**. Operators who explicitly do not want it
restored across restarts pass `-persistmempool=0` on startup.

## Purpose

Without persistence, every node restart drops the unconfirmed mempool. The
visible consequences:

- Pending wallet transactions disappear from the user's "unconfirmed" view,
  requiring manual rebroadcast.
- The fee estimator's data accumulation resets on every restart, distorting
  the historical signal it depends on.
- During planned restarts the brief mempool-empty window can fool fee bumpers
  and exchanges into thinking the chain is in a low-fee environment.

Mempool persistence closes all three with no client-side change.

## Architecture / schema

The persisted file lives at:

```
<datadir>/mempool.dat
```

Schema:

```
+0       u8       version_byte = 0x01      [in the clear]
+1       u8[32]   xor_key                  [in the clear]
+33..N   ...      tx_records               [XOR-scrambled]
+N..end  u8[8]    sha3_256_truncated       [XOR-scrambled]
```

Each tx_record:

```
+0     u32    serialized_size (LE)
+4     u8[]   serialized_tx (length = serialized_size)
+X     i64    entry_time (LE, unix seconds; matches CTxMemPoolEntry::GetTime())
+X+8   i64    fee_paid (LE, CAmount; matches CTxMemPoolEntry::GetFee())
```

### XOR scrambling

The body and footer are XOR-scrambled with a per-dump random 32-byte key
written in the clear at the head of the file. This protects against
antivirus interference -- serialized transaction script bytes can match
malware signatures, causing AV software to silently delete `mempool.dat`.
This mirrors Bitcoin Core v27+ ([PR #28207](https://github.com/bitcoin/bitcoin/pull/28207)).

The integrity footer is computed over the **unscrambled** bytes. Load
unscrambles first, then verifies, then parses.

### Atomicity

`DumpMempool` writes to `<datadir>/mempool.dat.new`, fsyncs the file,
renames to `mempool.dat`, and fsyncs the parent directory. On POSIX the
rename is atomic on every common filesystem. The parent-directory fsync
is required for rename durability across power loss on XFS and btrfs;
ext4 with default options auto-commits via `auto_da_alloc` but we don't
rely on that. Windows uses `std::filesystem::rename` which is atomic on
NTFS for same-volume moves.

Failure handling: if any step fails (disk full, write error, fsync
failure, rename failure), the `.new` file is removed and the prior
`mempool.dat` is left intact. The node logs a warning and continues
shutdown -- mempool persistence is best-effort, never blocks shutdown.

## Lifecycle

### Startup

`LoadMempool` runs after chainstate has loaded but before P2P starts
listening. The order is:

1. Datadir + chainstate + UTXO load.
2. Mempool object construction.
3. (optional) Transaction index init.
4. **`LoadMempool` runs here.** Reads `<datadir>/mempool.dat` if present;
   parses the schema; calls `mempool.AddTx(...)` for each tx with
   `bypass_fee_check=true` (restored txs already passed `Consensus::CheckFee`
   when first admitted, so re-checking is redundant and would reject txs
   whose chain context has shifted in subtle ways).
5. P2P stack starts listening for inbound connections.

If `mempool.dat` is missing, corrupt, oversized, or has an unknown schema
version, `LoadMempool` logs a warning and the node starts with an empty
mempool. The node never aborts on a load failure.

### Shutdown

`DumpMempool` runs after P2P stops accepting new transactions but before
the chainstate / UTXO databases close. The order is:

1. Resource monitor stops.
2. **P2P server stops** (`CConnman::Stop` blocks until peer threads are
   joined; no further txs can be admitted to the mempool after this).
3. **`DumpMempool` runs here.** Snapshots the mempool under its lock,
   serializes each entry's tx + fee + entry_time, scrambles, writes
   atomically.
4. UPnP unmap, signature verifier shutdown, trust-score save.
5. NodeContext shutdown.
6. RPC server stops.
7. UTXO database close.
8. Transaction index reset.
9. Blockchain database close.

## Failure modes that operators need to know

| Symptom | Cause | Action |
|---|---|---|
| `[mempool] LoadMempool: ... not found` | First boot, or `mempool.dat` was deleted. | None -- this is the normal cold-start path. |
| `[mempool] LoadMempool: integrity footer mismatch` | File was corrupted on disk (or by an antivirus that scanned past the XOR scrambling). | Investigate AV. Node continues with empty mempool. |
| `[mempool] LoadMempool: file size N exceeds MAX_FILE_SIZE` | `mempool.dat` is >512 MB (well above any plausible live mempool). | Investigate filesystem corruption. Node continues with empty mempool. Delete `mempool.dat` to confirm cold-start path. |
| `[mempool] DumpMempool failed: <reason>` at shutdown | Disk full, permission denied, transient I/O error. | Check disk space + permissions. Prior `mempool.dat` retained. Mempool persistence is best-effort -- shutdown proceeds. |
| `[mempool] LoadMempool: ... (dropped K with invalid inputs or schema)` | K txs in the saved mempool failed `CTxMemPool::AddTx` admission for reasons other than UTXO conflicts (e.g. tx fails to deserialize, mempool already contains a conflicting input via `mapSpentOutpoints`, time-skew exceeds 2h, height==0 sentinel, mempool full). Note: AddTx does NOT consult the live UTXO set, so a tx whose inputs were spent in blocks while the node was offline is silently re-admitted; it gets removed by the next block-connect's `RemoveConfirmedTxs` sweep, not by load itself. | Normal. Drops are silent and counted; the rest of the mempool loads. Stale-UTXO txs flush automatically as blocks confirm. |

## Operator surface

### Flags

* `-persistmempool=1` (default): enable mempool persistence.
* `-persistmempool=0`: disable. Mempool starts empty on every boot; no
  `mempool.dat` is written at shutdown.
* The flag accepts `--persistmempool` (bare, equivalent to `=1`),
  `--persistmempool=true`, and `--persistmempool=false` as aliases.

### Expected log lines

Startup (file present, all txs loaded):

```
[mempool] LoadMempool: loaded N transactions from <datadir>/mempool.dat
```

Startup (file present, K txs were no longer admissible against current chain
state and were dropped):

```
[mempool] LoadMempool: loaded N transactions from <datadir>/mempool.dat (dropped K with invalid inputs or schema)
```

Startup (cold start -- file missing):

```
[mempool] LoadMempool: <datadir>/mempool.dat not found, starting with empty mempool
```

Startup (cold start -- file corrupted):

```
[mempool] LoadMempool: <reason> -- starting with empty mempool
```

Where `<reason>` is one of: `file too small`, `unknown schema version N`,
`integrity footer mismatch`, `tx_count N exceeds bound`, `malformed tx_size
N at index I`, `file size N exceeds MAX_FILE_SIZE`, `stream error: ...`.

Shutdown (success -- single line from the persist module):

```
[mempool] DumpMempool: wrote N transactions to <datadir>/mempool.dat
```

Shutdown (failure -- best-effort, does not block shutdown):

```
[mempool] DumpMempool failed: <reason> -- prior mempool.dat retained
```

### `savemempool` JSON-RPC

Bitcoin Core port (`src/rpc/mempool.cpp::savemempool` v28.0). Triggers an
immediate `mempool.dat` write while the node is running, without waiting
for shutdown. Useful for: pre-restart drain + verification, migrating a
mempool snapshot to another datadir, sanity-checking the persistence
subsystem is healthy.

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"savemempool","params":{}}' \
  http://127.0.0.1:8332/
```

Response (matches Bitcoin Core v28.0's `savemempool` response schema):

```json
{ "filename": "/root/.dilithion/mempool.dat" }
```

Errors as JSON-RPC error responses if the mempool is not registered, the
data directory is unset, or `DumpMempool` fails (disk full, permissions).

The handler is safe to call repeatedly; each call atomically rewrites
`mempool.dat`. Concurrent calls serialize on the dispatcher's
`m_handlersMutex` (every RPC handler dispatch is mutex-serialized);
the mempool lock itself only covers the snapshot phase inside
`DumpMempool`, not the file write or rename. The handler is
restricted to the `ADMIN_SERVER` permission tier so a read-only
client (e.g. a light-wallet or explorer credential on a
`--public-api` seed) cannot trigger it.

### Recovery

If the operator wants to start with an empty mempool (e.g. they suspect
`mempool.dat` is corrupted in a way that passes the integrity check but
contains harmful txs):

```
# Stop the node (graceful or kill -9 are both fine).
rm <datadir>/mempool.dat
# Restart the node.
```

If the operator wants to disable persistence permanently for a node:

```
# Add to the wrapper / systemd unit / launch script:
./dilithion-node --persistmempool=0 ...
```

`--reset-chain` automatically removes `mempool.dat` along with the rest of
the chain-derived state (see `src/util/chain_reset.cpp`). After
`--reset-chain` the next startup cold-starts the mempool; no manual
`rm mempool.dat` is needed.

## File format details

### Why per-dump random XOR keys

Bitcoin Core PR #28207 introduced XOR scrambling specifically because some
antivirus products had begun scanning serialized tx bodies in `mempool.dat`
for malware signatures (script bytes look arbitrary; some byte sequences
matched AV signatures), and silently deleting the file when they found
matches. A static or fixed key would itself become a recognizable
signature; per-dump randomization prevents that.

The key is 32 bytes of cryptographic randomness from `std::random_device`
(POSIX `/dev/urandom`-equivalent on Linux, `BCryptGenRandom` on Windows).
The key is written in the clear at the head of the file -- there's no
secrecy claim, only obfuscation against AV signature matching.

### Why SHA3-256 instead of SHA-256

Dilithion uses SHA-3 throughout for project-wide post-quantum hash
consistency (see `src/crypto/sha3.h`). SHA-256 would also work for
collision detection at the truncation length, but SHA-3 keeps the
crypto stack uniform.

### Why 8-byte truncation

The footer protects against accidental disk corruption; 64-bit detection
strength is more than sufficient (probability of collision under random
corruption is 1 in 2^64). The threat model assumes any adversary with
filesystem write access can simply overwrite `mempool.dat` with a valid
file -- so investing in a longer footer wouldn't change the security
posture.

## Bounds and limits

| Bound | Value | Rationale |
|---|---|---|
| `MAX_TX_COUNT` | 200,000 | 2x `DEFAULT_MAX_MEMPOOL_COUNT` (100,000). Defensive bound; legitimate mempools never come close. |
| `MAX_TX_SIZE` | 4 MB | Per-tx serialized size. Higher than any realistic tx. |
| `MAX_FILE_SIZE` | 512 MB | Hard cap on `mempool.dat` file size. Above any plausible 300 MB live mempool. Files exceeding this are rejected at load. |

`LoadMempool` checks the file size **before** allocating memory, so a
malicious or corrupted oversized file cannot trigger a memory-exhaustion
DoS at startup.

## Source references

* `src/node/mempool_persist.h` -- public API, schema documentation,
  test-hook seam declarations.
* `src/node/mempool_persist.cpp` -- implementation: XOR scramble, atomic
  write, footer compute/verify, parse loop.
* `src/node/mempool.h` -- `CTxMemPool::GetAllEntries()` accessor used by
  `DumpMempool` to snapshot the full mempool.
* `src/node/dilithion-node.cpp` and `src/node/dilv-node.cpp` -- startup
  `LoadMempool` and shutdown `DumpMempool` call sites + `--persistmempool`
  flag parsing.
* `src/test/mempool_persist_tests.cpp` -- 20 Boost test cases covering
  round-trip, atomicity, all cold-start branches, schema lock, and the
  savemempool RPC handler (positive + negative paths).

## Bitcoin Core lineage

Direct port of Bitcoin Core v28.0 `src/kernel/mempool_persist.{h,cpp}`
with three deliberate adaptations:

1. **SHA3-256 instead of SHA-256** for the integrity footer (project hash
   convention).
2. **Bounded file-size read** (512 MB hard cap) explicitly added; Bitcoin
   Core relies on schema-level bounds during parse but Dilithion's startup
   behaviour is more conservative.
3. **No `mapDeltas` and no `unbroadcast_txids` set** -- these are Bitcoin
   Core features Dilithion does not yet have. When (or if) they land,
   schema version bumps to 0x02 and the additional records append after
   the per-tx records.
