# Explorer API — Update for v0 (2026-04-26)

**TL;DR:** Four changes shipped today. Nothing v0 has wired up breaks. Three are zero-effort upgrades; one is a new opt-in endpoint.

1. **Cache TTLs tightened** — polled endpoints now refresh in 5–15s instead of 30–60s. Same URLs, same shapes, just fresher data.
2. **NEW: `/api/stream.php`** — Server-Sent Events. Push channel for `block` and `tx` events with ~1.5s lag.
3. **Unique peer counting clarified** — `stats.php` now exposes `uniquePeers` (alias for the existing `nodesOnline`); peer-list extraction also got more robust.
4. **Internal refactor** of the v0 shape transformers — invisible to clients.

Base URL is unchanged: `https://explorer.dilithion.org/api/`.

---

## 1. Cache TTL changes

No code change required from v0. Existing polling will just feel snappier.

| Endpoint | Old TTL | New TTL |
|---|---|---|
| `stats.php` | 30s | **5s** |
| `blocks.php` (raw shape, page 1) | 60s | **15s** |
| `blocks.php?shape=v0` | none | **none** (live, unchanged) |
| `transactions.php` | 30s | **10s** |
| `holders.php` | 60s | **30s** |
| `supply.php` | 30s | **10s** |
| `financial.php` | 120s | **60s** |
| `nodes.php` | 3s | 3s (unchanged) |
| `mempool.php` | none | none (unchanged) |
| `miners.php` | 5min | 5min (unchanged — expensive block walk) |
| `charts.php` | 5min | 5min (unchanged — expensive block walk) |

**Effective freshness on the hero:** `stats.php` is now at most 5s + your poll interval stale. With your existing 12s SWR poll, worst-case lag drops from ~42s to ~17s.

---

## 2. NEW endpoint: `GET /api/stream.php`

**Server-Sent Events** push channel. Replaces `blocks.php` + `transactions.php` polling for the live feed when you want sub-second freshness.

### Connect from the browser

```js
const stream = new EventSource(
  'https://explorer.dilithion.org/api/stream.php?chain=dil'
);

stream.addEventListener('ready', e => {
  const { chain, tipHeight, mempoolSize, serverTime } = JSON.parse(e.data);
  // optional: render initial state
});

stream.addEventListener('block', e => {
  const block = JSON.parse(e.data);   // matches blocks.php?shape=v0 row shape
  // append to RecentBlocks, fire forge animation, update tip
});

stream.addEventListener('tx', e => {
  const tx = JSON.parse(e.data);      // matches transactions.php?shape=v0 row shape
  // append to RecentTransactions
});

stream.onerror = () => {
  // EventSource auto-reconnects; nothing to do here
};
```

### Query params

- `chain=dil` or `chain=dilv` — case-insensitive
- `notxs` (optional, any value) — block events only, suppress mempool tx events

### Events

| Event | Fires | Payload |
|---|---|---|
| `ready` | Once on connect | `{ chain, tipHeight, mempoolSize, serverTime }` |
| `block` | Each new block accepted (also fires once at connect with the current tip as a render anchor) | Same shape as a row from `blocks.php?shape=v0` |
| `tx` | Each new mempool transaction (suppressed if `?notxs`) | Same shape as a row from `transactions.php?shape=v0` |
| (comments) | Heartbeat every 15s, payload `: hb <ts>` | Ignored by `EventSource` |

### Operational notes

- **Lag:** server polls local RPC every 1.5s, so worst-case "block exists → client receives event" is ~1.5s.
- **Session cap: 240s.** Server closes cleanly after 4 minutes; `EventSource` auto-reconnects in <1s. Nothing for you to do — this just keeps PHP-FPM workers turning over.
- **No replay on reconnect.** When `ready` fires, check `tipHeight`. If your local height is behind, fetch the gap once via `blocks.php?shape=v0` then resume listening.
- **Burst guard:** at most 20 `tx` events emitted per poll cycle; bursts above that are still tracked (won't re-emit) but not blasted to the client.
- **Block ordering:** if two blocks land between polls (rare on a 60s chain), they're emitted in ascending height.

### When to use stream.php vs polling

- **Use stream.php** for the live forge, real-time tip indicator, live tx ticker.
- **Stick with polling** for charts, miners, holders, financial — the data either doesn't change fast enough to matter or is too expensive to push.

---

## 3. Unique peer counting

`stats.php` exposes three peer-related fields. They mean different things — pick the right one for your UI label.

| Field | What it counts | When to use it |
|---|---|---|
| `connections` | Local NYC seed's connection count (one node's view) | Almost never — it's a one-seed snapshot, not the network |
| `nodesOnline` | Unique peer IPs deduplicated across all 4 seeds | "Network nodes online: X" |
| `uniquePeers` | Same value as `nodesOnline`, clearer name | Same as above, just easier to read in code |
| `seedsResponding` | How many of the 4 seeds answered (0–4) | Health pill: "4/4 nodes responding" |

A naive sum of each seed's `peerCount` (e.g. NYC 72 + LDN 73 + SGP 72 + SYD 73 = 290) overcounts wildly because most peers connect to all 4 seeds. The `uniquePeers` / `nodesOnline` field is what you want for "peers across the network".

**Implementation note:** the deduplication now uses a JSON-first parse with a regex fallback for the rare case where a peer's `subver` string contains unescaped quotes (a known node-side bug). Result: typical counts are ~5-10 higher than before because we no longer drop entries that the old regex-only path couldn't extract.

## 4. What did NOT change

- All endpoint URLs.
- All response shapes (both raw and `?shape=v0`).
- All field names.
- All query params.
- Auth, CORS, error format.
- Subunit handling — `amount`, `reward`, `fees`, `rewards` are still in whole DIL/DilV (not ions/volts).

If v0 already works today, it still works. The TTL changes are pure server-side; the SSE endpoint is purely additive.

---

## Recommended action for v0

**Minimum:** nothing. Polling already gets fresher data without changes.

**Better:** swap `blocks.php` + `transactions.php` polling for a single `stream.php` `EventSource` connection. ~50 lines of client code, sub-second freshness, fewer requests, and the forge animation can fire exactly when blocks land.

If you ship the SSE swap, keep `blocks.php?shape=v0` for the initial page-load render anchor — don't wait for the first `block` event from the stream to populate the page. Easy pattern:

```js
// 1. Initial render from REST
const initial = await fetch('/api/blocks.php?shape=v0&limit=10&chain=dil').then(r => r.json());
renderBlocks(initial.blocks);

// 2. Live updates from SSE
const stream = new EventSource('/api/stream.php?chain=dil');
stream.addEventListener('block', e => prependBlock(JSON.parse(e.data)));
```

That's the whole upgrade.

---

## Reference

Full endpoint spec (all 14 endpoints, all fields): [EXPLORER-API-REFERENCE.md](EXPLORER-API-REFERENCE.md).
