# Small RPCs Cluster

Read-only / blocking RPCs ported from Bitcoin Core v28.0 (`src/rpc/blockchain.cpp`, `src/rpc/rawtransaction.cpp`, `src/rpc/mempool.cpp`).

Cluster: `waitfornewblock`, `waitforblock`, `waitforblockheight`, `gettxoutproof`, `verifytxoutproof`, `testmempoolaccept` (6 RPCs). All six are part of T1.B (Bitcoin Core port roadmap).

`getblockstats` is intentionally NOT in this cluster -- it requires per-tx fee fields that depend on undo-data exposure, and lands in a separate workstream alongside the `coinstatsindex` port.

All examples below use object-style params (Dilithion convention; not array-style as in Bitcoin Core's CLI).

---


## waitfornewblock / waitforblock / waitforblockheight

Long-poll for a tip-change condition. All three block until the predicate is met OR `timeout_ms` elapses, then return the current tip.

### Threading model

A single process-wide `std::condition_variable` is signaled from the chainstate's existing block-connect callback. Each handler grabs an internal mutex, evaluates its predicate, and `wait_until`s on the CV. Default timeout 30000 ms (30 s); cap 300000 ms (5 min). The cap prevents a malicious caller from tying up RPC worker threads (the server has ~8 worker slots).

### waitfornewblock

```
{"timeout_ms": <int>?}
```

Returns when the tip hash changes from whatever it was at the moment of the call.

### waitforblock

```
{"hash": "<64-hex>", "timeout_ms": <int>?}
```

Returns when the tip hash matches `hash`. Times out otherwise.

### waitforblockheight

```
{"height": <int>, "timeout_ms": <int>?}
```

Returns when the tip's height is `>= height`. Returns immediately if the predicate is already true.

### Response shape (all three)

```json
{"hash": "<current-tip-hash>", "height": <current-tip-height>}
```

Note: timeout is NOT signaled by an error response. The caller must compare the returned hash/height against the precondition to determine whether the predicate was met.

### Example

```bash
# Wait up to 60s for a new block:
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"waitfornewblock","params":{"timeout_ms":60000}}' \
  http://127.0.0.1:8332/
```

```bash
# Wait up to 30s (default) for the chain to reach height 100000:
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"waitforblockheight","params":{"height":100000}}' \
  http://127.0.0.1:8332/
```

---

## gettxoutproof

Returns a hex-encoded partial-merkle-tree proof witnessing inclusion of one or more txids in a block.

### Param

```
{"txids": ["<txid-hex>", ...], "blockhash": "<block-hex>"?}
```

`blockhash` is optional iff `-txindex` is enabled AND all txids resolve to the same block.

### Response

A JSON-string-encoded hex blob with the BIP-37-shaped layout:

```
[block_hash : 32]
[num_transactions : uint32 LE]
[hashes : compact-size + 32 each]
[flag_bits : compact-size + packed bytes]
```

Inner-node combiner is SHA3-256 (Dilithion's merkle hash, NOT Bitcoin's double-SHA256).

### Example

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"gettxoutproof","params":{"txids":["<txid>"],"blockhash":"<bh>"}}' \
  http://127.0.0.1:8332/
```

---

## verifytxoutproof

Decodes a `gettxoutproof` blob and returns the witnessed txids plus reconstructed merkle root.

### Param

```
{"proof": "<hex>"}
```

### Response

```json
{
  "merkleroot": "<reconstructed-root-hex>",
  "blockhash":  "<block-hex-from-proof>",
  "txids":      ["<txid>", ...]
}
```

### Caller-side verification

`verifytxoutproof` does NOT confirm that the reconstructed merkle root matches any block on the active chain -- it returns the root for the caller to compare. Standard SPV pattern:

1. Call `verifytxoutproof` to get the reconstructed root.
2. Independently fetch the block at `blockhash` (e.g. via `getblockheader`).
3. Compare `merkleroot` from (1) against the block header's merkle root.
4. The proof is valid iff the roots match AND the witnessed txids are non-empty.

### Example

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"verifytxoutproof","params":{"proof":"<hex>"}}' \
  http://127.0.0.1:8332/
```

---

## testmempoolaccept

Run mempool admission validation against one or more raw transactions WITHOUT broadcasting them. Returns per-tx accept/reject results matching `sendrawtransaction`'s acceptance semantics. Wallet/exchange UX preview path: callers can confirm a transaction will be accepted before paying network propagation cost.

### Param

```
{
  "rawtxs":     ["<hex>", ...],   // 1..25 hex-encoded raw transactions
  "maxfeerate": <number|string>?  // accepted for BC schema compatibility; ignored
}
```

`maxfeerate` is intentionally a no-op in Dilithion -- the node uses one fee policy via `Consensus::CheckFee` and has no separate accept-with-different-fee-cap path. We accept the parameter so clients targeting Bitcoin Core's RPC schema work unmodified.

### Response

```json
[
  {
    "txid":          "<hex>",
    "wtxid":         "<hex>",            // == txid (Dilithion has no segwit)
    "allowed":       true,
    "vsize":         <int>,              // serialized size in bytes
    "fees":          {"base": <DIL>}     // fee in DIL (numeric, 8 dp)
  },
  {
    "txid":          "<hex>",
    "wtxid":         "<hex>",
    "allowed":       false,
    "reject-reason": "<exact AddTx wording>"
  },
  ...
]
```

### Reject-reason wording

Reject-reasons are byte-for-byte equivalent to `sendrawtransaction`'s error wording for the same input. A caller running `testmempoolaccept` then `sendrawtransaction` against the same hex must see the same string in both places. Documented reject reasons (T1.B-2 contract):

| Reason | Trigger |
|--------|---------|
| `Coinbase transaction not allowed in mempool` | Coinbase tx (consensus violation) |
| `Already in mempool` | Tx with same txid is already in the mempool |
| `Transaction spends output already spent by transaction in mempool (double-spend attempt)` | Conflicts with an existing mempool tx |
| `Negative fee not allowed` | Fee is negative |
| `Transaction time must be positive` | `time <= 0` |
| `Transaction time too far in future` | `time > now + 2h` |
| `Transaction height cannot be zero` | `height == 0` |
| `Transaction exceeds maximum size` | tx > 1 MB |
| `Mempool full (transaction count limit)` | Mempool at count cap (no eviction attempted in TestAccept) |
| `Mempool full (size limit)` | Mempool at size cap |
| `Transaction validation failed: ...` | Failed `CTransactionValidator::CheckTransaction` (UTXO, signatures, etc.) |

### State integrity guarantee

`testmempoolaccept` is read-only on mempool state. After any number of calls (including 100 simultaneous calls from different clients), the following invariants hold:

- `mempool.Size()` is unchanged.
- `mapTx`, `setEntries`, `mapSpentOutpoints`, `mapDescendants` are all unchanged.
- Counter atomics (`metric_adds`, `metric_add_failures`, etc.) are unchanged.

A defence-in-depth check inside the handler logs a `STATE LEAK` warning to stderr if `mempool.Size()` changes across the call -- alarm-grade signal that should never fire.

### Permission and rate limit

- Permission tier: `READ_BLOCKCHAIN` (read-only-equivalent; no mutation).
- Rate limit: 100/min per IP. Validation is non-trivial (CTransactionValidator + mempool checks) and a request can carry up to 25 raw txs, so 100/min keeps the worst-case validation budget bounded while supporting wallet/exchange preview rates.

### Example

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"testmempoolaccept","params":{"rawtxs":["<hex>"]}}' \
  http://127.0.0.1:8332/
```

### Source mapping

| RPC | Bitcoin Core source |
|-----|---------------------|
| `testmempoolaccept` | `src/rpc/mempool.cpp` v28.0 |

Test-accept semantics adapted from BC's `MemPoolAccept::AcceptToMemoryPool` with `test_accept=true`. Dilithion implements this via `CTxMemPool::TestAccept` -- a const method that delegates to a `ValidateLocked` private helper shared with `AddTxUnlocked`'s validation phase. The shared helper guarantees that `testmempoolaccept` and `sendrawtransaction` accept/reject under identical conditions.

---

## Error handling

All seven handlers throw `std::runtime_error` (translated to a JSON-RPC error response) on:

- Missing required param.
- Malformed hex (length != 64 for 32-byte hashes; non-hex characters; truncated proof blob).
- Out-of-range height.
- Unknown block hash.
- Unknown txid in `gettxoutproof`.
- `timeout_ms <= 0`.
- Duplicate child hashes in a partial merkle tree (CVE-2012-2459 guard).

## Risk class

LOW. All read-only or blocking-only; no consensus, no P2P, no storage schema changes. Worst-case for a buggy handler is wrong RPC output -- no fund loss, no data corruption.

## Source mapping

| RPC | Bitcoin Core source |
|-----|---------------------|
| `waitfornewblock`      | `src/rpc/blockchain.cpp` v28.0 |
| `waitforblock`         | `src/rpc/blockchain.cpp` v28.0 |
| `waitforblockheight`   | `src/rpc/blockchain.cpp` v28.0 |
| `gettxoutproof`        | `src/rpc/rawtransaction.cpp` v28.0 |
| `verifytxoutproof`     | `src/rpc/rawtransaction.cpp` v28.0 |
| `testmempoolaccept`    | `src/rpc/mempool.cpp` v28.0 |
