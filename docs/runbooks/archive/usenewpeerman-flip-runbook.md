# `--usenewpeerman` Flip Runbook — RETIRED

> **🛑 RETIRED 2026-05-05 — `--usenewpeerman` flag removed by v4.3.4 Option C architectural cut.**
>
> The `port::CPeerManager` class this runbook was written to flip-into has been deleted entirely. The `--usenewpeerman` CLI flag no longer exists in `dilv-node` or `dilithion-node`. `g_node_context.sync_coordinator` always backs onto legacy `CIbdCoordinator` via `CIbdCoordinatorAdapter`.
>
> This runbook is preserved here for **historical reference only**. The flip it describes is no longer possible against current binaries; references to telemetry fields like `manager_class == "both"` are likewise impossible (the field is now constant `"legacy"`).
>
> See `.claude/contracts/option_c_architectural_cut_contract.md` for the cut decision and `git tag v4.3.4-pre-cut-baseline` for the pre-cut codebase if any historical reproduction is needed.

---

# `--usenewpeerman` Flip Runbook

**Audience:** mainnet seed-node operators (NYC, LDN, SGP, SYD).
**Last revised:** 2026-05-01.
**Status:** PRE-FLIP — the rolling-flip sequence (§5) **MUST NOT** execute until the 8-bullet A1/A2 pre-condition list (§1) discharges.

---

## What this runbook is

Procedure for flipping the `--usenewpeerman` flag on Dilithion mainnet seed nodes from default OFF to default ON, after the Phase 9+ Track A A1/A2 decision discharges. The flag was wired in Phase 6 PR6.5b.1a (Bitcoin Core port PeerManager); the body work + dual-layer review closed in Phases 6/7/8 (2026-05-01); this runbook covers operations only.

**Track A (operations) only.** Track B engineering (the port itself) is complete on `port/bitcoin-core-peer-ibd`. This runbook is the operator interface.

---

## §1 — Pre-conditions for the flip (8-bullet cumulative list)

The flip MUST NOT proceed until ALL items below are checked. Source of truth: `cursor_phase_8_implementation_review.md` §"Phase 9+ A1-vs-A2 hard pre-condition status".

1. **✅ Phase 8 close** — orchestration + harness + demo data published (discharged 2026-05-01 commit `ce08681`).
2. **⏳ Production-grade bypass quantification run** (split per PR8.6-RT-MEDIUM-2):
   - **2a.** Aggregator script `tools/aggregate_phase8_bypass_quantification.py` implemented (CSV → bootstrap 95% CIs + Wilson CIs).
   - **2b.** Regtest MIK parsing fix OR Linux CI testnet wire-format scope decision (PR8.3 scenario 5 SOFT-PASS resolved).
   - **2c.** Production-grade run executed on Linux CI (NYC seed) with `PR8_TRIALS=30+`, `PR8_MIN_HEIGHT=150`; Layer-1 Cursor + Layer-2 red-team review on resulting decision-grade comparison.
3. **⏳ `consensus_activation_policy.md` gate** — 14-day pre-announcement, 75% version-signaling threshold.
4. **⏳ User + community review.**
5. **⏳ Miner coordination if A1 chosen** (consensus change → activation timing).
6. **⏳ Bridge operations review** — bridge contract pause/unpause SOP signed by relayer operator with explicit reorg-depth tolerance window cited; references `bridge_pause_2026_04_27.md` for the operational baseline.
7. **⏳ Wallet + exchange impact assessment** — A1 vs A2 changes reorg-window semantics affecting mempool retention, UTXO snapshot freshness, and address rotation in integrators. Explicit confirmation that integrators tolerate the chosen window.
8. **⏳ Explorer reindex policy** — `explorer/api/*` reads chain state; deeper reorgs under A2 require the explorer to drop and re-fetch historical data above the reorg point. Explorer reindex tolerance specified.

**A1 vs A2 framing:**
- **A1:** Re-implement fork-staging in the port adapter (consensus-adjacent; significant new code).
- **A2:** Accept the bypass — port adapter relies on max-cumulative-work selection alone (upstream Bitcoin Core behavior). Accepts transient reorg windows that the 2026-04-25 incident demonstrated are unsafe at Dilithion's current scale.

See `cursor_phase_7_implementation_review.md` §"Phase 9+ A1-vs-A2 DECISION CALLOUT" for full framing.

---

## §2 — Burn-in protocol (single seed, smallest-blast-radius)

Run `--usenewpeerman=1` on **one** seed for **N hours** (recommended: 72h minimum) before extending. Selection: **LDN** (smallest blast radius — non-bridge-host, lowest miner traffic).

### Step-by-step

1. **Snapshot LDN state pre-flip:**
   ```bash
   ssh root@167.172.56.119 "cp -a /root/.dilithion/blocks /root/.dilithion-blocks.pre-flip-$(date +%Y%m%d)"
   ssh root@167.172.56.119 "cp -a /root/.dilithion/chainstate /root/.dilithion-chainstate.pre-flip-$(date +%Y%m%d)"
   ```

2. **Stop LDN seed:**
   ```bash
   ssh root@167.172.56.119 "pkill dilithion-node && sleep 5 && pgrep dilithion || echo stopped"
   ```

3. **Restart with `--usenewpeerman=1`:**
   ```bash
   ssh root@167.172.56.119 "cd /root && nohup ./dilithion-node --relay-only --public-api --usenewpeerman=1 > /root/node.log 2>&1 &"
   ```

4. **Verify the flag took effect** (log line registered by Phase 6 PR6.5b.1a/1b):
   ```bash
   ssh root@167.172.56.119 "grep -m1 'sync_coordinator backed by port-CPeerManager' /root/node.log"
   # Expected: "Phase 6 PR6.5b.1a/1b: sync_coordinator backed by port-CPeerManager (--usenewpeerman=1); registered on connman for dual-dispatch"
   ```

5. **Run burn-in monitor loop (every 10min, 72h):**
   See §3 for telemetry checklist.

### Burn-in success criteria

- Zero reorg events with depth > 2 over 72h (PR8.3 stress 6 bound).
- Zero `[ChainState]` UndoBlock corruption log lines.
- Zero MIK concentration anomalies (single MIK > 50% of any 100-block window).
- Peer count stays within ±20% of pre-flip baseline.
- Headers-sync progress reaches 100% after restart and stays there.

If any criterion fails, execute the rollback procedure (§4) immediately.

---

## §3 — Telemetry checklist (PR9.3 RPCs)

Three new RPCs ship in PR9.3 specifically for burn-in observability. Use them every 10min during burn-in.

> **RPC port reference (PR9.6-RT-LOW-1):** examples below use mainnet DIL port `8332`. Replace as needed for other networks:
> - DilV mainnet: `9332`
> - DIL testnet: `18332`
> - DilV testnet (if used): `19332`
>
> See CLAUDE.md "Dilithion RPC commands" for the full port reference.

### `getsyncstatus` — headers-sync progress + best-header snapshot

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"getsyncstatus","params":[]}' \
  http://127.0.0.1:8332/
```

Expected response shape:
```json
{
  "headers_progress": 1.0,
  "best_header_height": <int, current chain tip>,
  "best_header_hash": "<64-char hex>",
  "manager_class": "both"
}
```

**Observe:** `manager_class` should be `"both"` (γ dual-dispatch active under flag=1). If `"legacy"`, the flag did not take effect — investigate Phase 6 PR6.5b.1a fallback at `dilithion-node.cpp:6918` (warns when prerequisites are null).

### `getblockdownloadstats` — block-download counters + stalled-blocks visibility

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"getblockdownloadstats","params":[]}' \
  http://127.0.0.1:8332/
```

Expected response shape:
```json
{
  "total_blocks_in_flight": <int>,
  "total_blocks_pending": <int>,
  "peers": [
    {"peer_id": <int>, "blocks_in_flight": <int>, "manager_class": "both"}
  ],
  "stalled_blocks": [
    {"height": <int>, "peer_id": <int>}
  ]
}
```

**Observe:**
- `total_blocks_in_flight` should oscillate (request → arrive → request next); a stuck non-zero value for >5min indicates a stall.
- `stalled_blocks` is a non-mutating snapshot (PR9.6-RT-MEDIUM-3): blocks listed have exceeded the 60s timeout but the RPC does NOT itself trigger requeue/rotation. Subsequent calls may return the same entries until block_fetcher's normal Tick path requeues them. If the same `(height, peer_id)` pair persists across multiple RPC calls separated by >30s, investigate the peer's responsiveness via `getpeerinfo`.
- Per-peer `blocks_in_flight` distribution should be roughly even across all connected peers (no single peer monopolizing requests).

### `getpeerinfo` (extended) — per-peer manager-class + standard fields

```bash
curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"getpeerinfo","params":[]}' \
  http://127.0.0.1:8332/ | jq '.[].manager_class' | sort | uniq -c
```

Expected: under flag=1, every peer reports `"both"` (γ dual-dispatch fires for every peer event in BOTH legacy + port managers). If any peer reports `"legacy"` while flag=1 is active, the connman registration window between `Start()` and `RegisterPortPeerManager()` lost an event — investigate per `dilithion-node.cpp:6943-6950` registration-ordering note.

### Existing RPCs that are also useful during burn-in

- `getblockchaininfo` — chain tip, height, headers-up-to.
- `getpeerinfo` — per-peer connection details (now with `manager_class`).
- `getconnectioncount` — total peer count.
- `listbanned` — confirm no unexpected ban escalations.

---

## §4 — Rollback procedure

If any §2 success criterion fails, OR an operator observes any unexpected behavior:

1. **Stop the node immediately:**
   ```bash
   ssh root@167.172.56.119 "pkill dilithion-node && sleep 5 && pgrep dilithion || echo stopped"
   ```

2. **Restart WITHOUT the flag** (default OFF):
   ```bash
   ssh root@167.172.56.119 "cd /root && nohup ./dilithion-node --relay-only --public-api > /root/node.log 2>&1 &"
   ```

3. **Verify legacy path active** (no PR6.5b.1a/1b log line under default-OFF):
   ```bash
   ssh root@167.172.56.119 "grep 'sync_coordinator backed by port-CPeerManager' /root/node.log || echo 'legacy default OK'"
   ```

4. **Verify chain state intact:**
   ```bash
   ssh root@167.172.56.119 "curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' --data-binary '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}' http://127.0.0.1:8332/"
   ```
   Expected: `"chain":"main"`, `"blocks":` matches LDN's known tip from monitoring.

5. **CRITICAL — Divergence check before re-joining the network** (PR9.6-RT-MEDIUM-1 hardening). The burn-in EXISTS to detect cases where the port-CPeerManager (γ dual-dispatch) leads the node to accept a block sequence the legacy path would have rejected. If burn-in failed for that reason, the on-disk chainstate at rollback time is already corrupted from the legacy path's POV — restarting flag=0 against that chainstate boots legacy on top of port-touched state, NOT a clean recovery. Cross-check `getbestblockhash` against the OTHER mainnet seeds (NYC, SGP, SYD — none of which ran flag=1 during this burn-in):
   ```bash
   # LDN (flag=1 burn-in target, just rolled back):
   LDN_HASH=$(curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' --data-binary '{"jsonrpc":"2.0","id":1,"method":"getbestblockhash","params":[]}' http://167.172.56.119:8332/ | jq -r '.result')
   # NYC / SGP / SYD (clean cohort):
   for seed in 138.197.68.128 165.22.103.114 134.199.159.83; do
     SEED_HASH=$(curl -s --user rpc:rpc -H 'X-Dilithion-RPC: 1' -H 'content-type:application/json' --data-binary '{"jsonrpc":"2.0","id":1,"method":"getbestblockhash","params":[]}' http://${seed}:8332/ | jq -r '.result')
     echo "  $seed → $SEED_HASH"
   done
   echo "  LDN  → $LDN_HASH"
   ```

   **Decision matrix:**
   - **If LDN_HASH matches at least 2 of {NYC, SGP, SYD}:** chain state intact; LDN can re-join the network. Continue to step 6.
   - **If LDN_HASH diverges from majority cohort by ≤ 6 blocks:** legacy reorg machinery should resolve on its own; monitor for 30 minutes via `getblockchaininfo` polling. If LDN converges with cohort, continue. If not, restore from snapshot (next bullet).
   - **If LDN_HASH diverges by > 6 blocks OR LDN's chain is on a different fork lineage:** **STOP**. The chainstate has been touched by port-pm in a way legacy cannot resolve. Restore from §2 step 1 snapshot:
     ```bash
     ssh root@167.172.56.119 "pkill dilithion-node && sleep 5"
     ssh root@167.172.56.119 "rm -rf /root/.dilithion/blocks /root/.dilithion/chainstate"
     ssh root@167.172.56.119 "cp -a /root/.dilithion-blocks.pre-flip-* /root/.dilithion/blocks"
     ssh root@167.172.56.119 "cp -a /root/.dilithion-chainstate.pre-flip-* /root/.dilithion/chainstate"
     ssh root@167.172.56.119 "cd /root && nohup ./dilithion-node --relay-only --public-api > /root/node.log 2>&1 &"
     ```
     The §2 step 1 snapshot is **NOT** a "safety belt that's optional" — under the divergence > 6 blocks branch, snapshot restoration is REQUIRED.

6. **Open an incident report at `.claude/contracts/incident_<YYYY-MM-DD>_usenewpeerman_burnin.md`** capturing the symptom, telemetry snapshots from §3, divergence-check results from step 5, and rollback timestamp.

---

## §5 — Rolling-flip sequence (EXPLICITLY Track A)

**⚠️ DO NOT EXECUTE until §1 pre-conditions ALL discharge.**

After successful 72h burn-in on LDN:

| Step | Seed | Wait before next | User approval gate |
|---|---|---|---|
| 1 | LDN (167.172.56.119) | 72h (already done in §2) | Burn-in success criteria met |
| 2 | SGP (165.22.103.114) | 24h | Operator approval after LDN+24h clean |
| 3 | SYD (134.199.159.83) | 24h | Operator approval after SGP+24h clean |
| 4 | NYC (138.197.68.128) | — | **EXTRA CARE** — bridge host; coordinate with bridge ops review (§1 item 6) |

**Each step requires explicit user approval at the gate.** The user can interrupt and trigger §4 rollback at any seed without affecting the others.

NYC last because:
- NYC is the bridge host; bridge operations gate this step (§1 item 6).
- NYC has no `--relay-only` (wallet for bridge). The flag flip on NYC must include bridge-side coordination.

---

## §6 — Bridge / wallet / explorer pre-flip checks

These are §1 items 6/7/8 made operationally concrete.

### Bridge ops (§1 item 6)

- [ ] Bridge contract pause/unpause SOP signed by relayer operator (per PR8.6-RT-INFO-2 acceptance criterion).
- [ ] Reorg-depth tolerance window cited explicitly (e.g., "bridge pauses on reorg > 6 blocks").
- [ ] Procedure tested on regtest using the 4-node harness (`scripts/four_node_local.sh stress` produces reorg events).
- [ ] Reference: `bridge_pause_2026_04_27.md` for the operational baseline.

### Wallet + exchange (§1 item 7)

- [ ] Mempool retention semantics under A1 vs A2 documented.
- [ ] UTXO snapshot freshness expectation communicated to integrators.
- [ ] Address rotation policy unchanged OR explicit communication if changed.
- [ ] At least one exchange + one wallet integrator confirms tolerance of the chosen reorg window.

### Explorer (§1 item 8)

- [ ] `explorer/api/*` reindex tolerance documented (max reorg depth before the explorer drops historical data).
- [ ] Reindex procedure tested on regtest using harness + getchaintips agreement check.
- [ ] Explorer maintenance banner template prepared for the flip window.

---

## §7 — A1/A2 decision sequencing

This runbook **cannot proceed beyond §1** until the A1/A2 decision is made. Phase 8 close brief explicitly lists 8 cumulative pre-conditions:

- Item #1 ✅ (Phase 8 close, 2026-05-01).
- Items #2–#8 ⏳ remaining (see §1 above).

Per `cursor_phase_8_implementation_review.md` §S6 6A, the production-grade run (#2) **may** be re-evaluated to execute before Phase 9 close if Phase 9 lands without touching a measurement-surface (PR9.1 = doc/help; PR9.2 = this runbook; PR9.3 = read-only RPCs — none touch measurement targets, so the production run could land alongside Phase 9 close to compress timeline to A1/A2 deliberation). This is an operator decision; execution still requires user approval.

---

## §8 — References

- `cursor_phase_7_implementation_review.md` — A1 vs A2 decision callout.
- `cursor_phase_8_implementation_review.md` §"Phase 9+ A1-vs-A2 hard pre-condition status" — canonical 8-bullet list.
- `port_phase_9_implementation_plan.md` v0.1.2 — PR9.3 RPC schemas locked.
- `consensus_activation_policy.md` — activation gate requirements.
- `bridge_pause_2026_04_27.md` (memory) — bridge ops baseline.
- `phase_8_bypass_quantification_results.md` — production-grade run checklist.
- `incident_2026_04_25_full_report.md` — symptom definitions for §2 success criteria.
- `tools/run_phase8_bypass_quantification.sh` — production-grade run orchestration.
- `scripts/four_node_local.sh` — regtest 4-node harness for rollback dry-runs.

---

## §9 — Regtest rollback dry-run (executed at PR9.6 close)

Operators verifying this runbook should execute a regtest rollback dry-run before the first production burn-in:

```bash
# 1. Boot the 4-node harness in stress mode
make four_node_test SCENARIO=stress

# 2. Mid-run, kill Node A and restart with --usenewpeerman=1
# (already covered by harness scenario 2)

# 3. Verify §3 telemetry checklist responses are well-formed against
#    each running node's RPC port (19332-19335)

# 4. Trigger a synthetic rollback: kill the flag-1 node, restart without
#    the flag, verify legacy path active and chain state intact
```

Dry-run pass criteria: all §3 telemetry RPCs return well-formed JSON under both flag states; rollback restores legacy path within 10s; no chain-state corruption.
