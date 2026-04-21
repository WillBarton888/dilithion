# Changelog

All notable changes to Dilithion are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/).

- **Added** — new features
- **Changed** — changes to existing features
- **Deprecated** — features marked for removal
- **Removed** — removed features
- **Fixed** — bug fixes
- **Security** — security-related changes

For releases older than v4.0.0, see git tags and
[docs/CHANGELOG-LEGACY.md](docs/CHANGELOG-LEGACY.md).

---

## [Unreleased]

Tracked but not yet shipped. See `git log origin/main...HEAD` on a fresh checkout.

---

## [v4.0.17] — 2026-04-21

### Added
- **Digital DNA propagation** now functions on DIL for the first time. Three-stage fix shipping together:
  - Phase 1 — receiver accepts progressively enriched DNA for already-registered MIKs; sender re-broadcasts on local enrichment; discovery refreshes stale records.
  - Phase 1.1 — relay seeds can dim-fill missing dimensions on behalf of unmapped peers while preserving data provenance (core fields stay authoritative to the miner).
  - Phase 1.2 — discovery now sources known MIKs from the DNA registry (plus the legacy VDF cooldown tracker), unblocking the discovery loop on DIL where the cooldown tracker was always empty.
- **Mining**: MIK registration PoW is now persisted to `mik_registration.dat` and restored on startup. Miners no longer re-solve the ~25-minute 28-bit PoW after a chain wipe or restart.
- **Node**: `--reset-chain` flag wipes chain-derived state (blocks, chainstate, headers, dna_registry, dfmp_identity, dna_trust, wal, mempool, DFMP heat files) while preserving wallet, MIK registration, peers, and configs. Requires typing `RESET` to proceed, or `--yes` for scripts.
- **Consensus**: peers sending headers with timestamps far in the future now receive misbehavior penalty (20 points / offense, ban after 5) instead of being silently tolerated.
- **Wallet RPC**: `gettransaction` now returns a top-level `wallet:{category, amount, fee, to_address, time}` block and a Bitcoin-Core-style `details[]` array, enabling forensic enumeration of outbound sends.

### Fixed
- **Mining dashboard**: `blocks_accepted` counter is now rebuilt from the canonical chain via connect/disconnect callbacks. The previous optimistic counter overcounted DilV blocks 4–5× because lowest-VDF-output tiebreaks routinely displace a briefly-tip block. The dashboard now shows `accepted · submitted` session-scoped values.
- **Wallet coin selection**: size-aware with a 999 KB per-transaction cap. Prevents building 50 MB sends that the mempool would reject, and returns a distinct "consolidate first" error instead of failing silently later.
- **Wallet fee estimator**: `EstimateDilithiumTxSize` no longer underestimates by 2 bytes when input/output counts cross 252 (varint boundary) — fixes self-rejected sends at high input counts.
- **Wallet REST API**: `/api/v1/utxos` and `/api/v1/balance` now filter UTXOs that are already spent by in-flight mempool transactions. Light wallets no longer broadcast double-spend attempts after the first send.
- **Light wallet JS**: floors fee rate at consensus minimum (5000 ions/KB) so a buggy server response cannot produce sub-consensus broadcasts. Connection manager fallback raised from 1000/500 to 5000/5000.
- **Wallet UX**: custom RPC port now persists per-chain across DIL ↔ DilV toggles. Previously the toggle overwrote the port from a hardcoded table.
- **Wallet persistence**: outbound sends are now saved synchronously on record. Previous "mark as dirty" stub silently dropped send history if the process was killed before a block-triggered flush.
- **Consensus auto-rebuild (BUG #277)**: chain-wipe helper now also clears `dfmp_identity/`, closing a footgun where stale identity state caused a Reference-coinbase emit before the registration block existed on the rebuilt chain.

### Changed
- **VDF tip-swap logs** on DilV are now gated behind `--verbose`. They fire ~5/min at normal steady state and were flooding the console while contending for `cs_main` against the REST API thread.
- **`getchaintips` RPC**: filters out stale tips more than 100 blocks behind the active tip to prevent unbounded accumulation of orphaned VDF competing blocks.
- **Mining outcome messages** (`BLOCK CONFIRMED!` / `BLOCK NOT SELECTED`) are now deferred until the round is settled — i.e. a child block has been connected on top of the candidate. Previously DilV's lowest-VDF-output tiebreak could displace a same-height tip block within ~2-15s, so users saw "Your block won this round!" followed by no reward — eroding trust. Same fix applied to DIL's RandomX and VDF block-found paths. Loss messages use friendly plain-English tone (no "orphaned"/"reorged out" jargon).
- **`MINING REWARD CREDITED!` message** is now deferred via the wallet's per-block callback. Only one message per settled height instead of 3-8 messages from transient tip-swap reorgs. Disconnects of pending notifications drop them silently.

### Security
- **New checkpoints added** to lock in canonical chain history and accelerate IBD:
  - DIL: height 44,000 → `0000002751fc99551f4fce1f2e92053b2432788f1dc12412fd81223204d11377`
  - DilV: height 36,500 → `3a6c72ee0ac27508fe82b76ed561dc93bc52ee5a26825cbf3f693bbc7070fd63`
  - `dfmpAssumeValidHeight` raised on both chains to match (skips signature validation below the assume-valid line during IBD).
  - Verified consensus across all 4 mainnet seeds (NYC, LDN, SGP, SYD) before locking in the hashes.

### Infrastructure / Developer
- Repo hygiene: build artifacts, release tarballs, session docs, scratch scripts, and screenshots untracked. Repo-hygiene CI check added to prevent cruft regression.
- Dependabot config hardened against consensus-breaking auto-bumps.
- Documentation refresh: authoritative `BUILDING.md` and `RELEASING.md`; updated `CHANGELOG.md` legacy link; `THREAT-MODEL.md` refreshed for mainnet-live posture.
- Line endings pinned via `.gitattributes` (`eol=lf`).
- New scripts: `consolidate-wallet.py` for Tier 1 UTXO consolidation; explorer API helpers committed from NYC.

### Notes for miners
- **Required action**: none. Run the new binary and mining continues normally.
- **Benefit**: Digital DNA coverage (bandwidth, clock drift, thermal) should begin climbing as your node broadcasts enriched samples and accepts them from peers. Check your own DNA coverage with `getmydigitaldna` and network-wide stats with `getdnamonitor`.
- **One-time save**: MIK registration PoW now persists, so subsequent restarts or `--reset-chain` runs do not re-mine the 25-minute PoW.

---

## [v4.0.16] — 2026-04-13

### Fixed
- Node no longer exits with status 141 when a peer socket closes mid-write; `SIGPIPE` is now ignored process-wide.

## [v4.0.15] — 2026-04-12

### Added
- `--quiet` flag and richer `--verbose` gating so default logs are clean and actionable.
- Clearer block-lifecycle messages for both DIL and DilV during mining.
- Improved VPN/datacenter error message; mining guide refreshed to match.

### Fixed
- DilV wrapper now uses an absolute path so auto-restart picks up the correct binary version.

## [v4.0.14] — 2026-04-11

### Fixed
- Long-running Linux nodes no longer OOM: `malloc_trim` + per-thread arena limit applied (systemic leak workaround).
- Wallet UTXO consolidation now sends to the intended address; explorer no longer counts immature outputs as confirmed balance.
- Consensus: DFMP preflight added to VDF distribution replacement (BUG #285).
- DilV: raised `dfmpAssumeValidHeight` to 18,700 and added checkpoint (BUG #285 follow-through).
- Wallet: chain switching, password persistence, and general UX polish.

## [v4.0.13] — 2026-04-10

### Added
- REST/RPC: `dumpprivkey` and `importprivkey` for key portability.
- Wallet: `sendtoaddress` accepts optional `from_address` to constrain the spending wallet.
- Bridge: additional REST API features for balance and history queries.

### Fixed
- Digital DNA: thermal, bandwidth, and clock-drift dimensions collect correctly on all platforms.
- Digital DNA: false-positive Sybil-cluster from empty perspective data eliminated.
- Logging: removed duplicate timestamp; mining address shown in startup banner.

### Changed
- Verbose logging cleanup across network/sync code.

## [v4.0.12] — 2026-04-09

### Added
- Wallet: one-click **Optimize** button for UTXO consolidation.

### Fixed
- Windows: graceful shutdown when the console window is closed.
- Windows: PID-file false positive when the OS reused a PID for an unrelated process.
- CI: resolved all remaining fuzz-target build failures blocking audit-readiness.

### Changed
- Updated Telegram links; added Mastodon verification.

## [v4.0.11] — 2026-04-08

### Security
- Added hard checkpoints at **DIL height 40,000** and **DilV height 15,000**.

### Fixed
- Mining: attestation deadlock resolved when DNA was not yet cached (BUG #284).
- Bridge: prevented SQLite binding error in `get_block_hash` fallback path.
- Mempool: transactions are now preserved across VDF distribution reorgs.

## [v4.0.10] — 2026-04-06

### Fixed
- IBD: skip MIK-ban check during initial block download to prevent sync stalls.
- IBD: store below-checkpoint headers to prevent fresh-sync stalls.
- DIL: attestation + DNA binding correctly wired for the height-40,000 activation.
- Networking: capped DEDUP misbehavior penalty so IBD clients are not banned by honest duplicates.

## [v4.0.9] — 2026-04-05

### Added
- Explorer: address-prefix search.

### Fixed
- DIL: raised `dfmpAssumeValidHeight` to 34,000 to match checkpoint placement.
- Mining: added IBD check to the RandomX `startmining` RPC so miners don't waste work on stale tips.
- DilV: raised checkpoint to 8,370 (covers all pre-ban blocks).
- DilV: skip MIK-ban + cooldown during IBD for checkpointed blocks (BUG #284).

## [v4.0.8] — 2026-04-03

### Added
- Sybil defense Layer 2 (MIK expiration) and Layer 3 (registration rate limit).
- Bridge: arb bot hardened with slippage protection and timing jitter.
- Website: auto-detects DIL vs DilV chain and shows the correct unit.

### Fixed
- REST API: strict P2PKH script matching in balance endpoint.
- Packaging: bootstrap script rewrite + safety checks in release scripts.
- DilV: stale-attestation refresh in template builder (BUG #283).
- Seeds: `--externalip` passed so seeds report the correct `seed_id`.

## [v4.0.7] — 2026-04-03

### Added
- DilV Sybil defense: Phases 2A, 4, 5.
- Wallet: encryption warning banner and "forgot password" hints.
- Explorer: Dev Fund address labeled on the holders page.

### Fixed
- IBD: fork detection suppressed during bulk IBD (BUG #282).
- Networking: all `Misbehaving()` calls now tagged with misbehavior type for ban diagnostics.
- Wallet: password validated at prompt; requirement relaxed from 16 to 8 characters.
- Wallet: HD scan now covers both chains and change addresses; address panel supports light mode.

## [v4.0.6] — 2026-04-01

### Security
- DilV: added checkpoint at height 2,961 to reject the exploit chain.

## [v4.0.5] — 2026-04-01

### Security
- DilV: reverted stall exemption; reduced cooldown window from 1,920 to 200; raised consecutive-miner stall threshold from 600 s to 3,600 s; added checkpoint and full Sybil defense following the 97-MIK round-robin attack.
- DilV: permanently-invalid blocks are now skipped in `ProcessNewBlock`.

### Added
- Wallet: lock/switch wallet and unlock from welcome screen.
- Service worker: network-first policy; HD scan for both chains and change addresses.

## [v4.0.4] — 2026-03-30

### Added
- Website: live peer-count and network-stats on landing page (no more hardcoded values).
- Website: mobile-responsive design across all pages.
- Mining guide page added; mining calculator rebranded to gold/black.

### Fixed
- Genesis height bug in HD wallet dashboard.
- Mining address UX.
- Explorer includes pre-fund in DilV circulating supply; pulls real difficulty from nodes API.

## [v4.0.3] — 2026-03-30

### Added
- PWA support for mobile wallet installation.
- Standalone web wallet: bridge deposits, HD scan, unlock prompt.
- WASM Dilithium rebuilt from reference implementation.

### Fixed
- BUG #281 suite:
  - Moved DNA hash-equality check outside `skipValidation`.
  - Moved attestation check outside `skipValidation` so it runs during VDF reorgs.
  - Raised DilV `dfmpAssumeValidHeight` to 2,000; added checkpoint fix.
  - Corrected `seedAttestationActivationHeight` vs `dfmpAssumeValidHeight` mix-up.
  - Unblocked DilV IBD past block 1,078.
- Stale `skipValidation` comments removed from `chain.cpp`.

## [v4.0.2] — 2026-03-29

### Fixed
- **Root cause of IBD rejection (BUG #280)**: cooldown is now correctly enforced during reorgs. This was the top IBD blocker reported by miners post-v4.0.0.

## [v4.0.1] — 2026-03-29

### Fixed
- IBD: assume-valid raised to 5,000; startup re-validation skipped below it.
- IBD: stall timeout race with RandomX header processing.
- IBD: undo cooldown-tracker state during re-validation.

### Added
- Cooldown and attestation trace logging for IBD investigation.

## [v4.0.0] — 2026-03-28

The first v4 release shipped the **DilV chain reset** and the **DIL residential-attestation activation at height 40,000**.

### Added
- **DilV chain reset** with DNA-bound registration PoW and mandatory DNA from genesis.
- **Mainnet seed attestation** pubkeys + 4-seed Byzantine (3-of-4) tolerance.
- Miner identity resolution and peer analysis added to the forensic tool.
- `getfullmikdistribution` now includes MIK-to-address mapping; `getblock` exposes MIK.
- Seed attestation activated on DilV testnet at height 15.

### Changed
- Coinbase `scriptSig` limit raised from 6 KB to 20 KB to accommodate Dilithium attestations.
- Dev fund / dev reward split across 3 bridge wallets; pre-fund bookkeeping updated.
- Explorer: shows pre-fund supply percentage; labels the bridge wallet.

### Fixed
- Seed attestation pubkeys were being read from the private-key offset — corrected.
- Auto-recollect attestations when a block is rejected.
- DilV genesis timestamp corrected to March 28, 2026 UTC.
- Genesis block exempt from the attestation check (height 0).
- DNA P2P discovery: rate-limit collision + misbehavior penalty resolved.

---

## Earlier releases

v3.9.0 and earlier (~March 2026 and before) are documented via git tags and
commit messages. Run `git log --oneline --tags --no-walk --decorate` or view
[github.com/dilithion/dilithion/releases](https://github.com/dilithion/dilithion/releases)
for a chronological list.

Key pre-v4 milestones:

- **v3.8.0–v3.9.0** (mid-March 2026): mempool propagation fixes, DilV 97-MIK Sybil incident response, stall-exemption removal, dual-window cooldown, protocol bump.
- **v3.7.x** (early March 2026): Digital DNA live on mainnet at height 30,000 (DIL); DilV active from genesis; 148+ DNA unit tests; 5-layer Sybil defense architecture live.
- **v3.6.x** (late Feb / early March 2026): Timestamp validation hard fork at DIL height 24,500 (600 s future-time limit); ASERT re-anchor.
- **v3.0.x** (Feb 2026): Bridge to Base L2 mainnet live (wDIL + wDilV ERC-20 contracts, Aerodrome pools, relayer); explorer live at explorer.dilithion.org.

Pre-v3 content previously in this file has been archived to
[docs/CHANGELOG-LEGACY.md](docs/CHANGELOG-LEGACY.md).

[Unreleased]: https://github.com/dilithion/dilithion/compare/v4.0.16...HEAD
[v4.0.16]: https://github.com/dilithion/dilithion/compare/v4.0.15...v4.0.16
[v4.0.15]: https://github.com/dilithion/dilithion/compare/v4.0.14...v4.0.15
[v4.0.14]: https://github.com/dilithion/dilithion/compare/v4.0.13...v4.0.14
[v4.0.13]: https://github.com/dilithion/dilithion/compare/v4.0.12...v4.0.13
[v4.0.12]: https://github.com/dilithion/dilithion/compare/v4.0.11...v4.0.12
[v4.0.11]: https://github.com/dilithion/dilithion/compare/v4.0.10...v4.0.11
[v4.0.10]: https://github.com/dilithion/dilithion/compare/v4.0.9...v4.0.10
[v4.0.9]: https://github.com/dilithion/dilithion/compare/v4.0.8...v4.0.9
[v4.0.8]: https://github.com/dilithion/dilithion/compare/v4.0.7...v4.0.8
[v4.0.7]: https://github.com/dilithion/dilithion/compare/v4.0.6...v4.0.7
[v4.0.6]: https://github.com/dilithion/dilithion/compare/v4.0.5...v4.0.6
[v4.0.5]: https://github.com/dilithion/dilithion/compare/v4.0.4...v4.0.5
[v4.0.4]: https://github.com/dilithion/dilithion/compare/v4.0.3...v4.0.4
[v4.0.3]: https://github.com/dilithion/dilithion/compare/v4.0.2...v4.0.3
[v4.0.2]: https://github.com/dilithion/dilithion/compare/v4.0.1...v4.0.2
[v4.0.1]: https://github.com/dilithion/dilithion/compare/v4.0.0...v4.0.1
[v4.0.0]: https://github.com/dilithion/dilithion/releases/tag/v4.0.0
