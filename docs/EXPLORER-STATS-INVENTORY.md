# Dilithion Stats & Metrics Inventory

**Purpose:** master list of every metric currently tracked across the Dilithion ecosystem (explorer, Prometheus/Grafana, bridge monitor, node RPC) plus a curated list of metrics worth adding for the next-generation comprehensive Explorer.

**Scope:** mainnet only unless otherwise noted. Verified against repo state on 2026-04-26 against branch `port/bitcoin-core-peer-ibd`.

**Drift caveat:** a small number of metrics are documented in config comments and panelized in the Grafana dashboard but are NOT actually emitted by the node `/metrics` endpoint today. These are flagged inline as **DOCUMENTED-NOT-EMITTED** so Explorer planning doesn't depend on them.

---

## Section 1 — Explorer (web)

Hosted at `explorer.dilithion.org`. Two-chain (DIL + DilV) via `?chain=dilv` query param. All endpoints are PHP under `explorer/api/`.

### 1.1 Primary stats — `/api/stats.php`

Cache TTL: 30 seconds (holders cached separately at 60s — expensive UTXO scan).

| Field | Meaning | Notes |
|---|---|---|
| `blocks` | Tip block height | |
| `bestblockhash` | Tip block hash | |
| `difficulty` | Current target difficulty | |
| `networkhashps` | Estimated network hashrate | DIL only (RandomX); null for DilV (VDF) |
| `supply` | Circulating supply | DilV adds 2,681,636.92 pre-fund from chain reset |
| `connections` | Local node peer count | |
| `avgBlockTime` | Mean inter-block time over last 10 blocks | seconds |
| `holders` | Unique addresses with balance > 0 | |
| `chain` | "main" / "test" | |
| `chainName` | Display name (e.g. "Dilithion") | |
| `chainTips[]` | All known chain tips | fork detection |
| `chainVersion` | Node `subversion` string | `getnetworkinfo.subversion` |
| `consensusType` | "RandomX" or "VDF" | per-chain |
| `unit` | Coin unit symbol | DIL / DilV |
| `activeMiners` | Distinct MIK identities in active window | |
| `activeMinersWindow` | Window size in blocks | DIL: 360, DilV: 200 |
| `nodesOnline` | Unique peer nodes visible across seeds | |
| `seedsResponding` | Seeds that answered (out of 4) | |
| `totalTransactions` | Cumulative TX count across full chain | |
| `nextHalving` | Blocks until next halving event | |
| `cached` | Whether result came from cache | boolean |
| `cacheAge` | Age of cached result in seconds | |

### 1.2 Other PHP endpoints

| Endpoint | Stats exposed |
|---|---|
| `/api/blocks.php?height=` or `?hash=` | Single block: hash, height, time, tx_count, miner/MIK, size |
| `/api/blocks.php?page=` | Latest N blocks (max 50/page) |
| `/api/transactions.php?limit=` | Recent TXs: txid, block_height, block_hash, time, coinbase flag, outputs, total_output, confirmations; meta: `blocks_scanned` |
| `/api/holders.php?count=` | `holders`, `utxos`, `supply`, `top[]` (address, balance, label e.g. "Dev Fund", "Bridge") |
| `/api/nodes.php` | Per-seed: `online`, `height`, `peers`, `version`, `difficulty`. Aggregate: `consensusHeight` |
| `/api/mempool.php` | `size`, `bytes`, `usage`, `maxmempool`, `mempoolminfee`, `txids` |
| `/api/address.php?addr=` | Address `balance`, `utxos[]` |
| `/api/search.php?q=` | Polymorphic resolver — height / hash / txid / address |
| `/api/financial.php` | `priceUSD`, `marketCapUSD`, `liquidityUSD`, `volume24hUSD`, `priceChange24h`, `dex`, `pairAddress` (Aerodrome on Base) |
| `/api/supply.php?q=` | Plain text: `circulating` / `total` / `max` (for CG/CMC feeds) |
| `/api/tx.php?txid=` | Single TX details |
| `/api/rpc.php` | Generic RPC proxy (auth-restricted) |

**DilV routing quirk:** use `/api/stats.php?chain=dilv`. Path-prefix `/dilv/api/stats.php` returns the HTML page, not JSON. The path-prefix DOES work for `/api/v1/info` (node REST, see §3).

### 1.3 Cache TTLs (per endpoint)

| Endpoint | TTL |
|---|---|
| `stats.php` | 30s |
| `holders.php` (also via stats.php) | 60s |
| `blocks.php` (page 1) | 60s |
| `transactions.php` | 30s |
| `nodes.php` | 3s |
| `supply.php` | 30s |
| `financial.php` | 120s |
| `metrics_helpers` (active miners) | 120s |
| `metrics_helpers` (nodes online) | 30s |
| `metrics_helpers` (total TX count) | 60s |

### 1.4 Homepage stats bar (separate from explorer)

Shown on `dilithion.org` index page, per-chain:

- Block Height
- Circulating Supply
- Active Miners
- Difficulty

Source: `website/api/stats.php` (distinct from `explorer/api/stats.php`).

---

## Section 2 — Prometheus / Grafana (operator)

Node `/metrics` endpoint exposes Prometheus-format text.

- **DIL port:** 8334
- **DilV port:** 9334
- **Scrape interval:** 15s, timeout 10s
- **Targets:** 4 mainnet seeds (NYC, London, Singapore, Sydney) × 2 chains = 8 jobs
- **Source of truth:** [src/api/metrics.h](../src/api/metrics.h)

### 2.1 Currently emitted Prometheus metrics (40 total)

All metrics include `network` label (`mainnet` / `testnet`) and `chain` label (`dil` / `dilv`).

**Node info / lifecycle**
- `dilithion_info` — node version + network metadata (gauge, value=1)
- `dilithion_uptime_seconds` — process uptime (counter)

**Blockchain state**
- `dilithion_block_height` — tip block height (gauge)
- `dilithion_headers_height` — headers chain tip (gauge; sync gap = headers − blocks)
- `dilithion_last_block_time` — Unix timestamp of last block (gauge)
- `dilithion_ibd_progress_percent` — IBD progress percentage (gauge)

**Peers / connections**
- `dilithion_peer_count` — total connected peers (gauge)
- `dilithion_inbound_peers` — inbound connections (gauge)
- `dilithion_outbound_peers` — outbound connections (gauge)
- `dilithion_connection_attempts_total` — total connection attempts (counter)
- `dilithion_connection_rejected_total` — rejected connection attempts (counter)
- `dilithion_peer_bans_total` — peers banned for misbehavior (counter)

**Mempool**
- `dilithion_mempool_size` — TX count in mempool (gauge)

**Block validation & flow**
- `dilithion_blocks_validated_total` — total blocks validated (counter)
- `dilithion_blocks_accepted_total` — total blocks accepted to chain (counter)
- `dilithion_blocks_relayed_total` — total blocks relayed to peers (counter)
- `dilithion_block_validation_ms` — last block validation time, ms (gauge)
- `dilithion_validation_queue_depth` — blocks waiting for validation (gauge)
- `dilithion_validation_processing_ms` — current block processing time, ms (gauge)
- `dilithion_validation_last_completion` — Unix timestamp of last validation (gauge)

**Reorgs / forks**
- `dilithion_reorgs_total` — total chain reorganizations (counter)
- `dilithion_fork_detected` — 0/1 fork-detected flag (gauge)
- `dilithion_fork_depth` — depth of detected fork in blocks (gauge)
- `dilithion_fork_point_height` — height where fork diverged (gauge)

**Orphan blocks & pool**
- `dilithion_orphan_blocks_total` — total orphan blocks received (counter)
- `dilithion_orphan_pool_size` — current orphan block count (gauge)
- `dilithion_orphan_pool_bytes` — memory used by orphan blocks (gauge)
- `dilithion_orphan_pool_connectable` — orphans whose parent exists (gauge)
- `dilithion_orphan_pool_unconnectable` — orphans whose parent is missing (gauge)
- `dilithion_orphan_pool_oldest_age_secs` — age of oldest orphan in seconds (gauge)

**Parent-block fetch (orphan recovery)**
- `dilithion_parent_requests_pending` — pending parent block requests (gauge)
- `dilithion_parent_requests_timeout_total` — parent requests timed out (counter)
- `dilithion_parent_requests_success_total` — parent requests succeeded (counter)

**Attack indicators**
- `dilithion_invalid_blocks_total` — invalid blocks received (counter)
- `dilithion_invalid_headers_total` — invalid headers received (counter)
- `dilithion_invalid_transactions_total` — invalid TXs received (counter)
- `dilithion_duplicate_messages_total` — duplicate messages received (counter)

**P2P traffic**
- `dilithion_messages_received_total{type=...}` — messages by type (counter); types: `block`, `tx`, `headers`, `inv`, `getdata`, `getblocks`, `getheaders`, `ping`, `pong`, `addr`, `version`
- `dilithion_bytes_received_total` — total bytes received (counter)
- `dilithion_bytes_sent_total` — total bytes sent (counter)

### 2.2 DOCUMENTED-NOT-EMITTED (config drift)

Listed in `monitoring/prometheus-mainnet.yml` comments and/or referenced by Grafana dashboard panels, but **not** present in the `/metrics` output:

| Metric | Status |
|---|---|
| `dilithion_difficulty` | Not in metrics.h HELP output |
| `dilithion_network_hashrate` | Not in metrics.h HELP output |
| `dilithion_mining_active` | Storage exists ([src/api/metrics.h:47](../src/api/metrics.h)), set in node mainloop, but no Prometheus serializer line |
| `dilithion_hashrate` | Not in metrics.h HELP output |

**Action item for Explorer redesign:** wire these four into the metrics serializer if the new dashboard depends on them. Otherwise remove them from the prometheus config comments and Grafana panel queries to eliminate dead references.

### 2.3 Grafana dashboard

File: [monitoring/grafana-dashboard-2025-11-07.json](../monitoring/grafana-dashboard-2025-11-07.json)

Confirmed panels (by Prometheus query):

- Block Height — `dilithion_block_height`
- Connected Peers — `dilithion_peer_count` (color thresholds: red <3, yellow <8, green ≥8)
- Mining Status — `dilithion_mining_active` (DOCUMENTED-NOT-EMITTED — see §2.2)
- Local Hashrate — `dilithion_hashrate` (DOCUMENTED-NOT-EMITTED — see §2.2)
- Mempool Size — `dilithion_mempool_size`
- Inbound Peers — `dilithion_inbound_peers`
- Outbound Peers — `dilithion_outbound_peers`
- Fork Detected — `dilithion_fork_detected`
- Fork Depth — `dilithion_fork_depth`
- Fork Point Height — `dilithion_fork_point_height`

### 2.4 Alert rules

**No `.rules` file exists in the repo.** Thresholds live in two disconnected places: Grafana panel JSON (color thresholds, not firing alerts) and `monitor.py` (Python-coded thresholds, see §4). A unified Prometheus alert-rules file is a known gap.

---

## Section 3 — Node REST API (`/api/v1/`)

Served by the node's HTTP server (not by the explorer PHP layer). Implemented in [src/rpc/rest_api.cpp](../src/rpc/rest_api.cpp).

| Endpoint | Method | Returns |
|---|---|---|
| `/api/v1/info` | GET | `{height, bestblockhash, chain, difficulty}` |
| `/api/v1/balance/{address}` | GET | Address balance |
| `/api/v1/utxos/{address}` | GET | Address UTXO list (DoS cap: 1000 UTXOs/response) |
| `/api/v1/tx/{txid}` | GET | Transaction details |
| `/api/v1/fee` | GET | Recommended fee rate |
| `/api/v1/broadcast` | POST | Submit raw transaction |

Rate-limited via `CRateLimiter` with per-endpoint buckets. This is what wallets and lightweight clients consume directly from a node — the explorer's PHP layer wraps RPC instead.

---

## Section 4 — Bridge Relayer Monitoring

**Deployed-only:** the alert script is at `/root/bridge-relayer/monitor/monitor.py` on the NYC mainnet node. Not present in the local repo. Source for this section is the `infrastructure_monitoring.md` operator memo, last verified 2026-04-20.

Alert channel: Discord `#alerts` via webhook. State file deduplicates: a fired alert won't re-alert until cleared, and clearing posts `[RESOLVED]`. Cron: `*/5 * * * *`.

### 4.1 Bridge

| Severity | Trigger |
|---|---|
| P0 | Relayer process down |
| P0 | Bridge paused |
| P0 | Gas balance < 0.005 ETH on Base |
| P0 | Wallet balance drop > 500 coins / cycle |
| P0 | Stuck deposit or withdrawal > 30 min |
| P1 | Gas balance < 0.01 ETH on Base |

### 4.2 Seed nodes (NYC / LDN / SGP / SYD × DIL+DilV)

| Severity | Trigger |
|---|---|
| P0 | ALL seeds of a chain unreachable |
| P1 | Individual seed SSH unreachable |
| P1 | Individual seed RPC down |
| P1 | Individual seed at 0 peers |
| P1 | Individual seed disk OR memory > 90% |
| P1 | Individual seed height diverged > 3 blocks from NYC |

### 4.3 Chain

| Severity | Trigger |
|---|---|
| P0 | Deep reorg > 20 blocks |
| P1 | Reorg 5–20 blocks |
| P1 | Chain stalled — DIL > 8 min, DilV > 5 min |
| P1 | Single miner > 40% of last 100 blocks |

### 4.4 Bridge relayer-side health logging

Logged each cycle by `_log_health()` in [bridge/relayer/relayer.py](../bridge/relayer/relayer.py):

- Gas balance (Base ETH)
- DB stats (pending TXs, sync heights)
- Chain connectivity (DIL RPC, DilV RPC, Base RPC reachable, current heights)
- Confirmation counts (DIL: 6, DilV: 3, Base: 12)
- Daily mint caps (DIL: 1000, DilV: 10,000)
- Per-deposit limits (DIL: 500, DilV: 5,000)

### 4.5 Coverage gaps acknowledged in the script

- No P2/P3 checks (pool imbalance, daily mint cap spent, admin RPC audit)
- Testnet seeds not covered
- Mining concentration walks 100 blocks per cycle (use `getdfmpinfo` if it becomes slow)
- Monitor runs only on NYC — if NYC is down, nothing alerts (single point of failure)

---

## Section 5 — RPC analytic methods (data plane)

These RPCs are the data source for everything above. Useful directly for any new dashboard or external integration.

**Chain state**
- `getblockchaininfo` — `blocks`, `difficulty`, `chain`, `bestblockhash`, etc.
- `getblockcount` — height integer
- `getbestblockhash` — tip hash
- `getblock <hash> [verbosity]` — full block (TXs, time, miner/MIK)
- `getblockhash <height>` — hash at height
- `getchaintips` — all known fork tips with status

**Network**
- `getconnectioncount` — peer count
- `getpeerinfo` — per-peer detail (addr, version, inbound flag, ping, services)
- `getnetworkinfo` — version, subversion, network name, relay fees

**Mempool**
- `getmempoolinfo` — `size`, `bytes`, `usage`, `maxmempool`, `mempoolminfee`
- `getrawmempool` — array of pending txids

**Transactions**
- `gettransaction <txid>` — TX object with confirmations
- `getrawtransaction <txid>` — hex or decoded
- `gettxout <txid> <vout>` — UTXO data

**Mining / DNA / DFMP**
- `getmininginfo` — local mining state
- `getminingaddress` — coinbase recipient
- `getdfmpinfo` — MIK identity, penalty status, consensus participation
- `getmikdistribution` — `total_supply`, per-MIK block counts, penalty status
- `getfullmikdistribution` — expanded per-MIK breakdown

**Holders / UTXOs**
- `getholdercount` — unique address count
- `gettopholders [count] [prefix]` — top N by balance, optional prefix filter (drives explorer search bar)

**Sybil / DNA / X.402**
- `getsybilrelays` — Sybil-detection relay peer info
- `getcorrelatedalerts` — network anomalies, correlated events
- `getx402info` — HTTP payment channel status

**Wallet (operator-only)**
- `getwalletinfo`, `gethdwalletinfo`, `getnewaddress`, `getaddresses`, `getbalance`

**Sync state**
- `getblocktrackerinfo` — validation checkpoint and sync state

---

## Section 6 — Stats worth adding (gap analysis for next-gen Explorer)

None of the following are wired up today. Listed in priority order within each category. Each item names the natural data source where applicable.

### 6.1 High-value, low-cost (recommended for first cut)

**Chain health**
- **Orphan / stale block rate** — orphans per 1k blocks, rolling. Source: `dilithion_orphan_blocks_total` exists; just needs a rate panel.
- **Reorg frequency histogram** — count of 1 / 2 / 3+ block reorgs per day. Source: `dilithion_reorgs_total` exists.
- **Block size & weight distribution** — P50 / P95 / max bytes per block. Source: `getblock`.
- **Validation time P50 / P95 / P99** — over last 1k blocks. Source: `dilithion_block_validation_ms` already emitted; needs histogram conversion.
- **Empty / fee-only block rate** — fraction of blocks with only the coinbase TX. Source: `getblock`.
- **Active addresses** — distinct senders + receivers per 24h / 7d. Source: full chain scan, computed offline.
- **TX throughput** — TPS rolling 1h / 24h. Source: `getblock` chain scan.

**Mining & DNA**
- **Per-MIK block share over time** — rolling 100 / 360 / 1000-block share per MIK. Source: `getfullmikdistribution`. (Memory note: `getfullmikdistribution` is canonical, NOT `getblock`-walking.)
- **Multi-MIK clustering score** — entity-level concentration. Memory note: `multi_mik_clustering.md` baseline already exists.
- **DFMP penalty trigger rate** — penalties per epoch. Source: `getdfmpinfo`.
- **DNA verification failure rate** — relevant to BUG #284 deadlock category.
- **Attestation freshness lag** — seconds since each seed last attested. Source: per-seed RPC.

**P2P (especially relevant to current Phase 1 AddrMan port)**
- **AddrMan new vs tried table fill** — `m_new_count`, `m_tried_count`, % capacity. Eclipse-defense diagnostic.
- **Peer churn rate** — connects + disconnects per minute. Source: `dilithion_connection_attempts_total` exists.
- **Ban list size + ban-reason histogram** — by misbehavior type. Source: `listbanned` RPC + `dilithion_peer_bans_total`.
- **DNS seed query rate / failure rate** — bootstrap health.
- **Peer version histogram** — % of peers on each release. Source: `getpeerinfo.subver`.
- **Inbound connection rate** — new accepts/min. Would have caught the **NYC fd-storm Apr 21 incident**.
- **Accept-failed error rate** — explicit counter for fd-exhaustion class.

### 6.2 Mempool & TX economics

- Mempool eviction reasons — fee-too-low / size / age / replaced
- Fee market depth — bytes available at each fee tier
- Average / median TX value per chain
- UTXO set size & dust count — number and value of UTXOs <1000 sats; total set memory
- Gini coefficient on holders — concentration trend (more meaningful than Top-N over time)
- Top-N concentration trended — Top 10 / 100 / 1000 share over time, not just current snapshot

### 6.3 Bridge

- Mint vs burn rates — daily DIL→wDIL vs wDIL→DIL flow
- Cross-chain liquidity ratio — pool balance vs circulating wrapped supply
- Bridge utilization — % of daily cap consumed
- OP_RETURN parse failure rate — malformed deposits trend
- Relayer retry queue length — pending retries
- Time-to-mint distribution — deposit confirmed → wDIL minted, P50 / P95
- Arb bot trades & PnL — Aerodrome pool

### 6.4 Node operational

- Log error / warning rate by component (consensus, P2P, RPC, wallet)
- RPC request rate + error rate per method
- RPC P50 / P95 latency — currently only availability is checked
- Disk usage growth rate — bytes/day per seed
- Memory RSS trend — leak detection
- File descriptor usage — direct fix for the Apr 21 fd-storm class
- Goroutine / thread count — saturation signal

### 6.5 Wallet & explorer side

- Search-bar usage — what users actually look up (privacy-aware aggregate)
- Most-viewed addresses / blocks — explorer engagement
- `gettopholders` prefix-search latency — known-expensive UTXO scan
- Cache hit rate per explorer endpoint — `cached:true` already in stats.php payload, just not aggregated

### 6.6 DilV-specific

- VDF compute time per block — DilV equivalent of `dilithion_block_validation_ms`
- VDF difficulty trend
- DilV-side network effects of penalty events
- Bridge ratio trend (wDIL ↔ wDilV pool)

### 6.7 DilV-Specific Metrics — VDF & Fairness (proposed by Cockatoo, 2026-04-26)

Metrics unique to the Verifiable Delay Function chain and its fairness protocol. Field names use camelCase as a hint that they're intended to surface as JSON fields in the next-gen Explorer API.

| Field | Meaning | Source / Endpoint | Status |
|---|---|---|---|
| `vdfComputeTime` | Time to solve VDF per block (ms) | Computed from `getblock` time diffs | Proposed |
| `vdfSequentialSteps` | Total sequential squarings (500k × blocks) | Computed from block height | Proposed |
| `vdfOutputEntropy` | Entropy of VDF outputs (randomness check) | Computed from `getblock` headers | Proposed |
| `vdfGracePeriodUtil` | % of blocks mined within 12s grace | Computed from `getblock` time | Proposed |
| `vdfProofVerifyTime` | Avg time to verify Wesolowski proof | Computed from node logs | Proposed |
| `vdfDifficulty` | Current VDF difficulty target | `getblockchaininfo` (DilV) | Proposed |
| `digitalDnaSimilarity` | Max similarity score detected (0–1) | Computed from Digital DNA module | Proposed |
| `dfmpHeatHistogram` | Distribution of miner heat levels | Computed from `getdfmpinfo` | Proposed |
| `mikDiversityIndex` | Unique MIKs per 1k blocks | Computed from coinbase analysis | Proposed |
| `bridgeLockDelayP50` | Median time to mint on Base | Computed from bridge logs | Proposed |
| `bridgeLiquidityRatio` | wDIL on Base vs. locked DIL | On-chain query (Base RPC) | Proposed |
| `pqSignatureSizeAvg` | Avg Dilithium3 signature size (bytes) | Computed from `getblock` | Proposed |
| `quantumThreatIndex` | "Safety Margin" vs. global qubit growth | Computed (external API) | Proposed |
| `devContributionTotal` | Total DIL/DilV to Dev Fund | Computed from `gettopholders` | Existing¹ |
| `utxoSetGrowthRate` | Bytes/day added to UTXO set | `gettxoutsetinfo` diff | Proposed |

¹ "Existing" in the sense that the underlying data is already queryable — `explorer/api/holders.php` returns `top[].label` including "Dev Fund". It is not currently surfaced as a standalone metric.

**Cross-references with §6.1–§6.6:**
- `vdfComputeTime` overlaps with §6.6 "VDF compute time per block"
- `vdfDifficulty` overlaps with §6.6 "VDF difficulty trend"
- `bridgeLiquidityRatio` overlaps with §6.3 "Cross-chain liquidity ratio" and §6.6 "Bridge ratio trend"
- `bridgeLockDelayP50` overlaps with §6.3 "Time-to-mint distribution"
- `mikDiversityIndex` overlaps with §6.1 "Per-MIK block share over time" and "Multi-MIK clustering score"
- `dfmpHeatHistogram` overlaps with §6.1 "DFMP penalty trigger rate"
- `digitalDnaSimilarity` overlaps with §6.1 "DNA verification failure rate"
- `utxoSetGrowthRate` overlaps with §6.2 "UTXO set size & dust count"

When implementing, dedupe against §6.1–§6.6 to avoid two metrics measuring the same quantity under different names.

---

## Section 7 — Files referenced

**Explorer (PHP)**
- `explorer/api/stats.php`
- `explorer/api/blocks.php`
- `explorer/api/transactions.php`
- `explorer/api/holders.php`
- `explorer/api/nodes.php`
- `explorer/api/supply.php`
- `explorer/api/mempool.php`
- `explorer/api/address.php`
- `explorer/api/search.php`
- `explorer/api/financial.php`
- `explorer/api/metrics_helpers.php`
- `explorer/api/tx.php`
- `explorer/api/rpc.php`
- `explorer/api/warmup_total_tx.php`

**Website homepage stats bar**
- `website/api/stats.php`

**Prometheus / Grafana**
- `src/api/metrics.h` — source of truth for emitted metrics
- `src/api/http_server.cpp` / `.h` — `/metrics` HTTP serving
- `monitoring/prometheus-mainnet.yml` — scrape config
- `monitoring/prometheus-testnet.yml`
- `monitoring/prometheus-2025-11-07.yml`
- `monitoring/grafana-dashboard-2025-11-07.json` — dashboard JSON
- `monitoring/docker-compose-monitoring.yml`

**Node REST API**
- `src/rpc/rest_api.cpp` / `.h`
- `src/rpc/ratelimiter.cpp`

**Bridge / monitoring**
- `bridge/relayer/relayer.py` — `_log_health()`
- `bridge/relayer/config.py` — thresholds, caps, confirmation counts
- `/root/bridge-relayer/monitor/monitor.py` — **deployed-only on NYC, not in repo**

**RPC registry**
- `src/rpc/server.cpp`
- `src/rpc/permissions.cpp`

---

## Appendix — Drift & correctness items found while compiling this doc

These should be addressed during Explorer redesign so the new dashboard isn't built on stale references.

1. **`dilithion_difficulty`**, **`dilithion_network_hashrate`**, **`dilithion_mining_active`**, **`dilithion_hashrate`** — listed in prometheus config comments, panelized in Grafana, but not in the metrics.h serializer. Either wire them up (preferred) or remove the dead references.
2. **stats.php cache TTL** — docstring says "10 seconds", code says 30 seconds. Update the docstring.
3. **No Prometheus alert-rules file** — thresholds split between Grafana JSON (color, not firing) and monitor.py (Python). A unified `.rules` file is a gap.
4. **monitor.py is deployed-only** — should be checked into the repo so it's reviewable + reproducible across seeds.
5. **NYC single-point-of-failure for monitoring** — if NYC is down, nothing alerts. Worth running monitor.py on a second seed (or external host) for redundancy.
