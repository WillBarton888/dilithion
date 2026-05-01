# Small RPCs Cluster

Read-only / blocking RPCs ported from Bitcoin Core v28.0 (`src/rpc/blockchain.cpp` and `src/rpc/rawtransaction.cpp`).

Cluster: `getblockstats`, `waitfornewblock`, `waitforblock`, `waitforblockheight`, `gettxoutproof`, `verifytxoutproof`. All six were landed together in T1.B (Bitcoin Core port roadmap).

All examples below use object-style params (Dilithion convention; not array-style as in Bitcoin Core's CLI).

---

## getblockstats

Per-block analytics for explorers. Returns aggregate transaction-size, input/output counts, subsidy, and total fee.

### Param

```
{"hash_or_height": <hex|int>}
{"hash": "<64-hex>"}
{"height": <int>}
```

Either `hash_or_height` or `hash`/`height`. Supplying both `hash` and `height` is rejected.

### Response fields

- `avgtxsize`, `mediantxsize`, `maxtxsize`, `mintxsize` -- distribution of per-tx serialized sizes (bytes).
- `blockhash` -- hash of the requested block.
- `height` -- block height.
- `ins`, `outs` -- total non-coinbase inputs / outputs in the block.
- `mediantime` -- median nTime of the previous 11 blocks (chain median past time). Falls back to `time` when ancestors are unavailable.
- `subsidy` -- block subsidy in ions (DIL) or volts (DilV).
- `time` -- block header timestamp.
- `total_out` -- sum of non-coinbase outputs.
- `total_size` -- serialized tx-array byte length.
- `totalfee` -- coinbase output sum minus subsidy. Reported as 0 if coinbase under-pays subsidy (consensus violation; would be rejected at block validation).
- `txs` -- transaction count including coinbase.
- `utxo_increase` -- `outs - ins`. Net UTXO created by the block.

### Omitted vs. Bitcoin Core

The following Bitcoin Core fields are intentionally omitted:

- `swtotal_size`, `swtotal_weight`, `swtxs`, `total_weight` -- segwit-only; Dilithion is non-segwit.
- `avgfee`, `medianfee`, `maxfee`, `minfee`, `feerate_percentiles`, `avgfeerate`, `maxfeerate`, `minfeerate` -- per-tx fees require prevout lookups against an undo file. Dilithion does not currently expose undo data through the RPC layer; only the aggregate `totalfee` (coinbase-derived) is available. Adding per-tx fees would require a separate undo-data-aware port and is out of scope for this cluster.

### Example

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"getblockstats","params":{"height":1000}}' \
  http://127.0.0.1:8332/
```

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

## Error handling

All six handlers throw `std::runtime_error` (translated to a JSON-RPC error response) on:

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
| `getblockstats`        | `src/rpc/blockchain.cpp` v28.0 |
| `waitfornewblock`      | `src/rpc/blockchain.cpp` v28.0 |
| `waitforblock`         | `src/rpc/blockchain.cpp` v28.0 |
| `waitforblockheight`   | `src/rpc/blockchain.cpp` v28.0 |
| `gettxoutproof`        | `src/rpc/rawtransaction.cpp` v28.0 |
| `verifytxoutproof`     | `src/rpc/rawtransaction.cpp` v28.0 |
