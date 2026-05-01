# Dilithion Explorer API — Reference (for v0)

**Base URL:** `https://explorer.dilithion.org/api/`

> **Important:** the canonical chain-data API is hosted on `explorer.dilithion.org`, not `dilithion.org`. The `dilithion.org/api/stats.php` endpoint is a website-only convenience aggregator with a reduced field set. Everything below lives at the explorer subdomain.

**Chain selector:** every endpoint accepts a `?chain=` query param. Accepted values: `dil` (default) or `dilv` — **case-insensitive** as of 2026-04-26 (so `DIL`, `DILV`, `Dil` all work).

**CORS:** all endpoints emit `Access-Control-Allow-Origin: *` so you can fetch from any browser context.

**Caching:** every endpoint caches; cache age is exposed via `cached` (boolean) and `cacheAge` (seconds) in the response when applicable. TTLs are listed per endpoint below.

**Errors:** non-200 responses are JSON of the form `{"error": "<message>"}` — never HTML.

**Units:** all `amount`, `reward`, `fees`, `rewards`, and balance fields are returned in whole coins — DIL for `chain=dil`, DilV for `chain=dilv`. Subunits are **ions** (DIL) and **volts** (DilV); `1 DIL = 100,000,000 ions` and `1 DilV = 100,000,000 volts`. Underlying RPCs (`getblock` vouts, etc.) return subunits; the `?shape=v0` adapters convert.

---

## Endpoint index

| # | Endpoint | Purpose | Cache TTL |
|---|---|---|---|
| 1 | `GET /api/stats.php` | Hero / overview stats | **5s** (30s for `holders` sub-cache) |
| 2 | `GET /api/blocks.php` | Recent blocks list, single block by `?height=` or `?hash=` | **15s** (page 1, raw shape only) |
| 3 | `GET /api/transactions.php` | Recent transactions across latest blocks | **10s** |
| 4 | `GET /api/tx.php` | Single transaction by txid | none |
| 5 | `GET /api/address.php` | Balance + UTXOs for an address | none |
| 6 | `GET /api/search.php` | Polymorphic search (height / hash / txid / address) | none |
| 7 | `GET /api/mempool.php` | Mempool size + pending txids | none |
| 8 | `GET /api/holders.php` | Top holders ranked by balance | **30s** |
| 9 | `GET /api/nodes.php` | Per-seed status (height, peers, version) | 3s |
| 10 | `GET /api/financial.php` | Wrapped-token price + DEX liquidity (Aerodrome on Base) | **60s** |
| 11 | `GET /api/supply.php` | Plain-text supply numbers (CG/CMC compatible) | **10s** |
| 12 | `GET /api/miners.php` | MIK leaderboard for a window | 5min |
| 13 | `GET /api/charts.php` | Time-series for a metric over a range | 5min |
| 14 | `GET /api/stream.php` | **SSE push channel** — `block` + `tx` events as they arrive | n/a (live) |

**TTLs were tightened on 2026-04-26 for live-feel.** Hot endpoints now refresh within ~half a poll cycle. Expensive endpoints (`miners`, `charts`) keep their 5-minute cache because the underlying block walk is too costly to do per-request — but `stream.php` provides a sub-second push alternative for new-block events.

`?shape=v0` paths on `blocks.php` deliberately skip the cache (regenerate per request, ~150ms). The original raw-shape path still uses the 15s cache.

---

## 1. `GET /api/stats.php`

**Query params:** `?chain=dil|dilv`

**Response:**

```json
{
  "blocks": 46684,
  "bestblockhash": "a3f1...",
  "difficulty": 12345.6789,
  "networkhashps": 767683,
  "supply": 2334200,
  "connections": 8,
  "avgBlockTime": 59.4,
  "holders": 1247,
  "chain": "main",
  "chainName": "Dilithion",
  "chainVersion": "/Dilithion:4.0.18/",
  "consensusType": "RandomX",
  "unit": "DIL",
  "chainTips": [{ "height": 46684, "hash": "...", "status": "active" }],
  "activeMiners": 23,
  "activeMinersWindow": 360,
  "nodesOnline": 312,
  "uniquePeers": 312,
  "seedsResponding": 4,
  "totalTransactions": 89421,
  "nextHalving": {
    "blocksRemaining": 163316,
    "halvingInterval": 210000,
    "nextHalvingAt": 210000
  },
  "cached": true,
  "cacheAge": 12
}
```

**Notes:**

- `networkhashps` is `null` for DilV (VDF chain — hashrate concept doesn't apply).
- `consensusType` returns `"RandomX"` for DIL, `"VDF"` for DilV.
- `avgBlockTime` is the rolling average over the last 10 blocks.
- `chainVersion` is the node's `subversion` string from `getnetworkinfo`.
- **Peer fields meaning:** `connections` is the local NYC seed's peer count (one node's view); `nodesOnline` and `uniquePeers` are the same value — unique peer IPs deduplicated across all 4 seeds (this is what you want to display as "peers across the network"); `seedsResponding` is 0-4. Don't sum `connections` across seeds — most peers connect to all 4, so the naive sum overcounts ~4x.

---

## 2. `GET /api/blocks.php`

**Two modes:** list or single. List supports the **v0 camelCase shape** via `?shape=v0`.

### List mode

**Query params:**
- `chain=dil|dilv`
- `limit=10` (max 50, default 20)
- `page=1` (for pagination)
- `shape=v0` (optional — returns camelCase fields tuned for the explorer UI)

**Response (`?shape=v0`, the recommended shape for v0):**

```json
{
  "blocks": [
    {
      "height": 46684,
      "hash": "a3f1...",
      "timestamp": 1777194059,
      "size": 524288,
      "txCount": 142,
      "difficulty": 12345.6789,
      "reward": 50.0123,
      "fees": 0.0123,
      "miner": "QuantumPool" | "Dilithion Address" | "unknown",
      "minerAddress": "DJrywx4...",
      "coinbaseTxid": "0x...",
      "firstNonCoinbaseTxid": "0x..." | null,
      "mik": "<20-byte hex>" | null,
      "previousBlockHash": "0x..."
    }
  ],
  "page": 1,
  "limit": 10,
  "totalHeight": 46684,
  "tipHeight": 46684,
  "chain": "dil",
  "cached": false
}
```

**`miner` resolution:** if `minerAddress` matches a known label (Dev Fund / Bridge), `miner` returns the label. Otherwise `miner` falls back to the raw address. If no coinbase address can be extracted, `miner` is `"unknown"`.

**`fees` calculation:** `coinbase output total − halving subsidy at this height`. Subsidy is `50 / 2^(height / 210000)` for DIL, `100 / 2^(height / 210000)` for DilV. Always non-negative.

**`firstNonCoinbaseTxid`:** the txid of `block.tx[1]` if the block has any non-coinbase transactions, else `null`. Resolve to full tx detail via `/api/tx.php?txid=...`.

**Response (default — no `shape`):** raw `getblock` snake_case format (`tx_count`, `previousblockhash`, `tx[]` as full TX objects with `vout[]`, etc.). Existing consumers should keep using this shape.

### Single mode

**Query params:**
- `?hash=<64-hex>` — fetch by hash
- `?height=<int>` — fetch by height
- `shape=v0` — return v0 camelCase shape

**Response:** `{"block": <block-object>}` where `block-object` matches the shape rules above.

---

## 3. `GET /api/transactions.php`

**Walks the latest blocks (up to 50) and returns the most recent transactions.**

**Query params:**
- `chain=dil|dilv`
- `limit=12` (max 200, default 50)
- `shape=v0` (optional — returns camelCase fields)

**Response (`?shape=v0`, the recommended shape for v0):**

```json
{
  "transactions": [
    {
      "id": "0x...",
      "from": "coinbase" | null,
      "to": "DJrywx4...",
      "amount": 50.0123,
      "fee": 0.0,
      "timestamp": 1777193900,
      "blockHeight": 46684,
      "kind": "coinbase" | "transfer",
      "confirmations": 4
    }
  ],
  "total_found": 142,
  "blocks_scanned": 5,
  "tipHeight": 46684,
  "tip_height": 46684,
  "unit": "DIL",
  "chain": "dil",
  "updated_at": 1777194059
}
```

**Field semantics:**

- `id` is the txid (64-hex).
- `from` is `"coinbase"` for block-reward transactions; `null` for normal transfers. UTXO chains have no single "sender" — you'll need to resolve `vin[0]` against `getrawtransaction` if you want a candidate sender address.
- `to` is the **first non-empty output address**. For multi-output transfers this is just the first one — render as "and N more" in the UI if `outputs.length > 1`.
- `amount` is the total output value (sum of all `vout` values).
- **`fee` is currently always `0.0`.** Computing real fees requires resolving every input's previous-output value, which is too expensive for the recent-tx feed. Use `/api/tx.php?txid=...` for an authoritative single-tx breakdown if/when that becomes available.
- `kind` is `"coinbase"` or `"transfer"`. Smart-contract / agent kinds are reserved for future use.

**Response (default — no `shape`):** raw snake_case shape (`txid`, `block_height`, `block_hash`, `coinbase`, `outputs[]`, `total_output`, `confirmations`).

---

## 4. `GET /api/tx.php`

**Query params:** `?txid=<64-hex>` (required), `?chain=dil|dilv`

**Response:**

```json
{
  "transaction": {
    "txid": "...",
    "vin": [...],
    "vout": [...],
    "blockhash": "...",
    "confirmations": 4,
    "time": 1777193900
  }
}
```

Returns the raw `getrawtransaction` shape. No v0-shape adapter on this endpoint yet — let us know if you need one.

---

## 5. `GET /api/address.php`

**Query params:** `?addr=<address>` (required, must start with `D`), `?chain=dil|dilv`

**Response:**

```json
{
  "address": "DJrywx4...",
  "balance": { "balance": 7100.0, "confirmed": 7100.0, "unconfirmed": 0.0 },
  "utxos": { "utxos": [{ "txid": "...", "vout": 0, "value": 50.0 }, ...] }
}
```

**Known gap:** no transaction history per address. UTXO chains don't index TXs by address natively — adding this requires a separate index (Electrum-server pattern). Not built today; document as a future endpoint if you need it.

---

## 6. `GET /api/search.php`

**Query params:** `?q=<query>`, `?chain=dil|dilv`

Resolves the query to one of: block height, block hash, txid, full address, or address prefix.

**Response examples:**

```json
{ "type": "block",   "result": <block-object> }
{ "type": "tx",      "result": <tx-object> }
{ "type": "address", "result": { "address": "..." } }
{ "type": "address_prefix", "result": { "prefix": "DGUP", "matches": [...], "total_matches": 7 } }
{ "type": "unknown", "query": "...", "message": "..." }
```

**Routing rules:**

- Pure digits → block height
- 64 hex chars → tries block hash, then txid
- Starts with `D`, 26+ chars → full address
- Starts with `D`, 2–25 chars → prefix search via `gettopholders`

---

## 7. `GET /api/mempool.php`

**Query params:** `?chain=dil|dilv`

**Response:**

```json
{
  "size": 87,
  "bytes": 92345,
  "usage": 110000,
  "maxmempool": 300000000,
  "mempoolminfee": 0.00001,
  "txids": ["0x...", "0x...", ...]
}
```

**Note:** today this endpoint returns only txids, not full TX shapes. To resolve a txid to its details, fetch `/api/tx.php?txid=<txid>`. A `?shape=v0` mode that inlines the full TX objects can be added if the `/mempool` route ever needs it.

---

## 8. `GET /api/holders.php`

**Query params:** `?chain=dil|dilv`, `?count=100` (1–500)

**Response:**

```json
{
  "holders": 1247,
  "utxos": 8923,
  "supply": 2334200,
  "unit": "DIL",
  "chain": "dil",
  "top": [
    {
      "address": "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq",
      "balance": 1500000.0,
      "label": "Dev Fund"
    },
    {
      "address": "DTHGN3XiZ9LRxHVPUWMumX8B9q6B4BuPdp",
      "balance": 250000.0,
      "label": "Bridge"
    }
  ],
  "updated_at": 1777194059
}
```

Known labels: `Dev Fund`, `Bridge`. Other addresses have no `label` field.

---

## 9. `GET /api/nodes.php`

**Query params:** `?chain=dil|dilv`

**Response:**

```json
{
  "nodes": [
    {
      "id": "nyc",
      "ip": "138.197.68.128",
      "label": "New York",
      "flag": "US",
      "primary": true,
      "online": true,
      "height": 46684,
      "peers": 8,
      "chain": "main",
      "version": "/Dilithion:4.0.18/",
      "difficulty": 12345.6789
    },
    { "id": "ldn", "label": "London",    ... },
    { "id": "sgp", "label": "Singapore", ... },
    { "id": "syd", "label": "Sydney",    ... }
  ],
  "chain": "dil",
  "consensusHeight": 46684,
  "timestamp": 1777194059
}
```

`consensusHeight` is the max height seen across the four seeds — useful for flagging chain-tip drift.

---

## 10. `GET /api/financial.php`

**Query params:** `?chain=dil|dilv`

Returns wrapped-token (wDIL / wDilV) price and DEX liquidity from Aerodrome on Base.

**Response:**

```json
{
  "priceUSD": 0.142,
  "marketCapUSD": 331486,
  "liquidityUSD": 18742,
  "volume24hUSD": 4221,
  "priceChange24h": 1.27,
  "dex": "aerodrome",
  "pairAddress": "0x..."
}
```

---

## 11. `GET /api/supply.php`

**Query params:** `?chain=dil|dilv`, `?q=circulating|total|max`

Returns a single number as **plain text** (not JSON). Designed for CoinGecko/CMC supply feeds.

```
2334200
```

---

## 12. `GET /api/miners.php` *(new)*

**MIK leaderboard for a rolling window.** Walks the last N blocks, aggregates per-MIK statistics from coinbase data.

**Query params:**
- `chain=dil|dilv`
- `window=24h` — accepts `1h`, `6h`, `12h`, `24h`, `7d`, `30d`, or a literal number of seconds. Capped at 5000 blocks (~3.5 days at DIL block target).

**Response:**

```json
{
  "chain": "dil",
  "unit": "DIL",
  "windowSeconds": 86400,
  "windowBlocks": 1440,
  "blocksWalked": 1440,
  "tipHeight": 46684,
  "startHeight": 45245,
  "uniqueMiners": 23,
  "miners": [
    {
      "mik": "<20-byte hex>",
      "address": "DJrywx4...",
      "label": "Dev Fund" | null,
      "blocksFound": 142,
      "share": 0.0986,
      "rewards": 7100.0,
      "firstSeen": 1777107600,
      "lastSeen": 1777194000,
      "blocksInWindow": 142
    }
  ],
  "updatedAt": 1777194059,
  "cached": false,
  "cacheAge": 0
}
```

**Field semantics:**

- `share` is `blocksFound / blocksWalked` (so the entries sum to ≤ 1.0).
- `blocksInWindow` is an alias for `blocksFound` — kept for v0 spec compatibility.
- `rewards` is the sum of coinbase output values across this MIK's blocks (subsidy + fees).
- Sorted by `blocksFound` descending.

**Not yet emitted (v0 spec mentioned):** `region`, `dnaStatus`, `dfmpZone`, `dfmpPenaltyMultiplier`. Region requires GeoIP infra (we have none today). The DFMP fields require per-MIK heat / penalty queries; the existing `getdfmpinfo` RPC is wallet-scoped, not arbitrary-MIK-scoped, so those would need a new node-side RPC.

---

## 13. `GET /api/charts.php` *(new)*

**Time-series for a metric over a range.** Samples ~60 blocks across the range and computes per-metric values.

**Query params:**
- `chain=dil|dilv`
- `metric=hashrate|difficulty|blocktime|rewards|fees`
- `range=1h|6h|12h|24h|7d|30d`

**Response:**

```json
{
  "chain": "dil",
  "metric": "hashrate",
  "range": "24h",
  "rangeSeconds": 86400,
  "sampleCount": 60,
  "sampleStrideBlocks": 24,
  "tipHeight": 46684,
  "points": [
    { "t": 1777107659, "v": 752341 },
    { "t": 1777109099, "v": 781002 },
    ...
  ],
  "updatedAt": 1777194059,
  "cached": false
}
```

**Metric semantics:**

- `hashrate` — `difficulty * 2^32 / blocktime_seconds`, computed using the average block time over the sample stride.
- `difficulty` — float difficulty at the sampled block.
- `blocktime` — average seconds per block over the sample stride.
- `rewards` — coinbase output total at the sampled block (subsidy + fees).
- `fees` — `coinbase total − halving subsidy at that height` (i.e. the fee component of the reward).

**Not yet supported (returns 400):**

- `peers` — no historical peer-count snapshots are recorded today. Use `/api/nodes.php` for the current count per seed.

**Sample density:** fixed ~60 points per chart regardless of range. Stride blocks scale linearly with range. The first point in the response is timed from a block one stride before the visible window (so blocktime/hashrate have a delta to compute against on the very first visible point).

---

## 14. `GET /api/stream.php` *(new — Server-Sent Events)*

**Sub-second push channel for new blocks and mempool transactions.** Replaces `blocks.php` + `transactions.php` polling for the live forge / live tx feed when you want true real-time.

**Query params:**
- `chain=dil|dilv`
- `notxs` — present (any value) skips mempool tx events; only `block` events are emitted

**Connect from the browser:**

```js
const stream = new EventSource('https://explorer.dilithion.org/api/stream.php?chain=dil');

stream.addEventListener('ready', e => {
  const { chain, tipHeight, mempoolSize, serverTime } = JSON.parse(e.data);
  // optional: render initial state
});

stream.addEventListener('block', e => {
  const block = JSON.parse(e.data); // matches blocks.php?shape=v0 row shape
  // append to RecentBlocks, fire forge animation, update tip
});

stream.addEventListener('tx', e => {
  const tx = JSON.parse(e.data);    // matches transactions.php?shape=v0 row shape
  // append to RecentTransactions
});

stream.onerror = () => {
  // EventSource auto-reconnects; nothing to do here
};
```

**Events:**

| Event | When | Payload shape |
|---|---|---|
| `ready` | Once on connect | `{ chain, tipHeight, mempoolSize, serverTime }` |
| `block` | Each new block accepted (also fires once at connect with the current tip as a render anchor) | Same shape as a row from `blocks.php?shape=v0` |
| `tx` | Each new mempool transaction (suppressed if `?notxs`) | Same shape as a row from `transactions.php?shape=v0` |
| (comments) | Heartbeat every 15s, payload is `: hb <unix-ts>` | Ignored by `EventSource` |

**Operational details:**

- Server polls local RPC every **1.5s**. Worst-case lag from "new block exists" → "client receives `block` event" is ~1.5s.
- **Session cap: 240 seconds.** The server closes the stream cleanly after 4 minutes; `EventSource` auto-reconnects (sub-second). This keeps PHP-FPM workers turning over and prevents long-lived workers from accumulating memory.
- **No retry header** is sent — the browser default of ~3s reconnect is fine. Override with `retry: <ms>\n\n` lines if you want different behaviour.
- **Mempool-tx burst guard:** at most 20 `tx` events emitted per poll cycle. Bursts above that are still tracked (won't re-emit when polled again) but not blasted to the client.
- **Block ordering:** if multiple blocks arrived between polls (rare on a 60s chain), they're emitted in ascending height order.
- **Reconnect-loss tolerance:** EventSource doesn't replay missed events. When the client reconnects, the `ready` event tells you the current `tipHeight`; if your local height is behind, fetch the gap via `blocks.php?shape=v0` once to catch up, then resume listening.

**When to use stream.php vs polling:**

- **Use stream.php** for the live forge, real-time tip indicator, live tx ticker — anywhere you want sub-second freshness and an animation to fire exactly on block production.
- **Stick with polling** for charts, miners, holders, financial — the data either doesn't change fast enough to matter or is too expensive to push.

---

## Sample-transfer alternative

The original v0 spec asked for `sampleTransfer: { from, to }` on each block. UTXO chains don't have a single "from" without resolving previous outputs (expensive). Instead, blocks.php returns `firstNonCoinbaseTxid` — resolve that to a full TX via `/api/tx.php?txid=<id>` if you want to render a sample transfer.

---

## Common error responses

```json
{ "error": "Invalid block hash. Must be 64 hex characters." }    // 400
{ "error": "Block not found." }                                  // 404
{ "error": "Failed to connect to node." }                        // 503
{ "error": "Unsupported metric 'foo'. Supported: ..." }          // 400 (charts.php only)
```

---

## Polling cadence recommendation

| Endpoint | Suggested poll | Effective freshness |
|---|---|---|
| `stats.php` | 12s | ~12s (5s cache + poll) |
| `blocks.php?shape=v0&limit=10` | 10s | ~10s (no cache on shape=v0 path) |
| `transactions.php?shape=v0&limit=12` | 10s | ~15s (10s cache + poll) |
| `mempool.php` | 5s | live (no cache) |
| `nodes.php` | 30s | live (3s cache) |
| `miners.php?window=24h` | 5min | 5min (cache TTL matches) |
| `charts.php` | on chart-range change only | 5min (cache TTL) |
| `stream.php` | **n/a — push** | ~1.5s |

**For real-time UX**, replace `blocks.php` + `transactions.php` polling with a single `stream.php` connection. See section 14.

---

## Quick wiring checklist for the v0 hero + body

For the landing-page targets v0 specified, these are the only calls you need:

1. **Hero stats:** `GET /api/stats.php?chain=dil` — already wired.
2. **RecentBlocks + conveyor:** `GET /api/blocks.php?limit=10&shape=v0&chain=dil`.
3. **RecentTransactions:** `GET /api/transactions.php?limit=12&shape=v0&chain=dil`.

After those three, every component on the landing page is backed by live data. `?chain=dilv` mirrors return the same shapes once DilV is ready to ship.
