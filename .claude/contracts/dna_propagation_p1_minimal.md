# Contract: DNA Propagation Fix — Minimal Phase 1

**Status:** Active, approved 2026-04-19. Scope reduced from the original Phase-1+2 contract to a minimal propagation fix only. Phase 2 (shadow anomaly detector) deferred until we measure the impact of Phase 1 on mainnet.

## Task

Fix the three propagation gates that prevent enriched Digital DNA from spreading across the P2P network. Goal: mainnet seeds should see dimension coverage for `bandwidth`, `clock_drift`, `perspective`, and `behavioral` rise from 1–15% toward 40%+ as continuous-mining miners stay online.

No consensus changes. No new P2P message types. No anomaly detection. No signed envelope trailer. Just close the gates.

## Why now

4 of 8 DNA dimensions are effectively dark across the network today. The "DNA commitment mismatch (soft check)" warnings every miner sees are symptoms of the same root cause. Sybil defense is weaker than it appears because the statistical base we'd need for detection doesn't exist yet. Phase 1 is strictly additive on the network layer — zero consensus risk — and unblocks whatever we do later.

## Background (frozen for this contract)

Three propagation gates identified in prior analysis:

1. **Receiver drops updates** — [src/node/dilithion-node.cpp:4231-4239](../../src/node/dilithion-node.cpp#L4231-L4239) and the equivalent in `dilv-node.cpp`: `if (!existing) register_identity(*dna);` silently discards richer DNA when the MIK is already present.
2. **Sender only broadcasts on initial registration** — [src/node/dilithion-node.cpp:5893-5923](../../src/node/dilithion-node.cpp#L5893-L5923): the local enrichment path updates the registry but doesn't push to peers.
3. **Discovery only requests missing MIKs** — [src/node/dilithion-node.cpp:5954-5960](../../src/node/dilithion-node.cpp#L5954-L5960): the discovery loop never re-requests DNA for MIKs that are present but have stale/sparse records.

Plus a local bug: enrichment is gated by `new_dims > old_dims`, so same-dim refreshes with changed values never archive to history.

Existing infrastructure: `DNARegistryDB::update_identity` already archives old DNA to `make_hist_key(mik, timestamp)`; `get_dna_history` retrieves; `getdigitaldnahistory` RPC exposes. We extend rather than rebuild.

## Acceptance Criteria

### Propagation fix

- [ ] **Receiver accepts enriched DNA for existing MIKs** on both DIL and DilV. New handler logic:
  - If MIK not in registry → `register_identity` (current behavior).
  - If MIK present → rate-limit + plausibility check → `append_sample(mik, dna)` which calls `update_identity` (archives old to history, writes new as canonical).
- [ ] **Sender re-broadcasts after local enrichment** — the broadcast loop at [dilithion-node.cpp:5876-5890](../../src/node/dilithion-node.cpp#L5876-L5890) is lifted into a `BroadcastDNASample(dna)` helper and called from both the initial-registration path and the enrichment path.
- [ ] **Local enrichment accepts same-dim value changes** — drop the `new_dims > old_dims` gate at [dilithion-node.cpp:5906](../../src/node/dilithion-node.cpp#L5906); any update that doesn't *remove* dimensions is accepted and archived.
- [ ] **Discovery refreshes stale records** — the "missing MIK" query at [dilithion-node.cpp:5954-5960](../../src/node/dilithion-node.cpp#L5954-L5960) is extended to also re-request DNA for MIKs whose stored record has fewer than 8 populated dimensions.
- [ ] **Three-layer rate limit** on received samples (plausibility uses `g_mik_peer_map` only — no signed nonce this round):
  - Per-peer token bucket: 1 sample / 30s, burst 5.
  - Per-MIK global min interval: 10 min between accepted samples.
  - Per-MIK-per-peer min interval: 30 min.
  - Plausibility: sender must be the previously-mapped peer for this MIK (`g_mik_peer_map[mik] == peer_id`). Unmapped peers are silently rejected on the existing-MIK path.
- [ ] **History storage cap** — keep last 100 samples per MIK; drop oldest on each `append_sample`. No age-based eviction this round.
- [ ] **Symmetric implementation** — all changes applied to both `dilithion-node.cpp` and `dilv-node.cpp`. No logic divergence.
- [ ] **No change to `DigitalDNA::hash()`** or any consensus-relevant path. `git diff --name-only` shows no changes to `src/consensus/`.
- [ ] **Mixed-version compatibility** — old peers (< v4.0.13) continue to work. New receiver handles their single-snapshot DNA via the existing `!existing` path. Wire format unchanged.

### Cross-cutting

- [ ] **Unit tests** covering: receiver accepts richer DNA for existing MIK, rate limiter rejects per each of 3 layers, `append_sample` archives to history, history cap at 100 per MIK.
- [ ] **All existing DNA tests still pass.** No regression in `dna_serialization_test`, `dna_history_test`, `dna_p2p_test`, `dna_monitor_test`, `dna_detection_test`.
- [ ] **Build clean on MSYS2 Windows.** `make -j4` succeeds.
- [ ] **No consensus-layer files modified.**

### Deferred (explicit)

- 15-minute periodic DNA broadcast (even when no enrichment). Add as Phase 1.5 if coverage doesn't lift enough from enrichment-triggered broadcasts alone.
- Signed MIK-bound nonce + replay cache. Only needed if cross-relay scenarios become a concern.
- Shadow-mode anomaly detector and `getdnaanomaly` RPC.
- 30-day age-based history eviction.
- Soft-check log repurpose at `dilithion-node.cpp:5207`.
- Trust-score coupling of any statistical signal.

## Non-Goals (scope fence)

- No `DigitalDNA::hash()` change. No hash versioning.
- No consensus change. `CheckDNAHashEquality` untouched. `dnaHashEnforcementHeight` stays at `999999999`.
- No activation height.
- No UI / wallet changes.
- No hard fork. No soft fork. No block-content changes.
- No new P2P message types.

## Rollout Plan

1. **Implementation** (this contract) — incremental commits on main, unit tests green at each step.
2. **Local verification** — MSYS2 build clean, all DNA tests pass.
3. **NYC deploy first** — full binary replacement, watch logs for 1h.
4. **Rolling seed deploy** — LDN → SGP → SYD, verify sync + peer count + DNA RPC health at each step.
5. **24h observation** — confirm `getdnamonitor` coverage rising, no misbehaviour penalties spiking, no peer count drops.
6. **Decide on Phase 1.5** — based on 24h data, decide whether to add 15-min periodic push.

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Receiver accepts flood of malformed samples, registry DB balloons | 3-layer rate limit + 100-sample history cap + plausibility check via `g_mik_peer_map` |
| Enriched DNA propagates but hash mismatch causes spurious soft warnings on every block | Expected; log-only, not consensus. Repurpose deferred to later round |
| Trust penalty fires spuriously on value-level dimension changes | `core_dimensions_changed()` already gates on timing >10% + latency >20ms only; bandwidth/drift/perspective/thermal changes don't trigger it |
| Mixed-version network fragmentation | Receiver accepts both snapshot (old) and enriched (new) DNA via same `dnaires` path |
| Unmapped-peer plausibility blocks legitimate cross-peer DNA propagation | Accepted trade-off for Phase 1. If it bites, add signed envelope in Phase 1.5 |

## Definition of Done

All acceptance criteria checked. Binaries deployed to all 4 mainnet seeds on both DIL and DilV. 24h post-deploy observation shows rising dimension coverage (bandwidth / clock_drift / perspective moving from ≤15% toward 40%+). This contract archived to `archived_dna_propagation_p1_minimal.md`.

## Approval

- [x] Contract approved by Will (2026-04-19)
- [x] Plan previously drafted; this minimal scope is a subset, no new plan needed
- [ ] Implementation starts

---

**Estimated effort:** 8-10h implementation + 2h testing + 1-2h deploy/observe. Incremental commits on main.

---

# Deferred Phase-2 scope (reference only)

The following items were part of the original contract and are **deferred** — not abandoned. If Phase 1 lifts coverage as expected but Sybil pressure becomes a concern later, or if a calibration window makes sense, draft a fresh contract for these.

- Shadow anomaly detector (`src/digital_dna/anomaly_detector.{h,cpp}`): per-dimension robust z-score (MAD), Mahalanobis for latency array, DTW for thermal curve, EWMA + CUSUM for behavioral drift. Observe-only, logs to `dna_anomaly.log`.
- New RPC `getdnaanomaly`.
- Self-poisoning defence: bounded drift budget per dimension per 24h window.
- Replay defence: timestamp + 64-bit nonce; 10-min dedup cache. Only needed if signed envelope added.
- Reference plan: `.claude/plans/dna_continuous_sampling_p1_p2.md` (steps 1, 4–7 in-scope for minimal; steps 2, 3, 9–11 deferred; steps 8, 12, 13 partially in-scope).
