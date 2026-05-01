# Dilithion Wallet — Handoff for Cockatoo

**Date:** 2026-04-30
**Author:** Will Barton (will@bananatree.com.au)
**Purpose:** Self-contained briefing for the wallet rebuild. Read this end-to-end before opening the codebase.

---

## TL;DR

You're building a single Next.js PWA at `wallet.dilithion.org` that replaces the legacy split-wallet stack (node-embedded `wallet.dat` + web wallet with light/full sub-modes). One client, browser-side keys, encrypted IndexedDB, mnemonic-only recovery, supports both DIL and DilV chains.

**Phase 0 (Dashboard MVP with mock data) shipped 2026-04-19. Phase 1 (Crypto + storage core) is next.**

The authoritative spec is the master roadmap at `.claude/contracts/archived_wallet_master_now_a_roadmap.md` in the dilithion repo — read it end-to-end before starting Phase 1. This handoff doc summarizes it and adds context that emerged after the contract was written.

---

## Repo & stack

- **GitHub:** `github.com/dilithion/Wallet` — private during build, public when Phase 4 ships
- **Local path:** `c:\Users\will\wallet` (lowercase to satisfy npm; GitHub repo is capitalized as `Wallet`)
- **Stack:** Next.js 16 (App Router) + React 19 + TypeScript + Tailwind v4 + shadcn/ui (new-york, neutral, css-vars) + pnpm
- **pnpm install:** use `npx pnpm@latest` — corepack global install needs admin rights this machine doesn't have
- **Build constraint:** `pnpm build` must exit clean. Never enable `ignoreBuildErrors` in `next.config.*`. Strict TS, no `any` without explicit `// reason:` comment

---

## Phase status

| # | Phase | Status | Cursor gate |
|---|---|---|---|
| 0 | Dashboard MVP (mock data) | DONE 2026-04-19 | not required |
| 1 | Crypto + storage core | **NEXT** | required |
| 2 | Onboarding + unlock | after 1 | not required |
| 3 | Network layer (auto-detect local node vs explorer API) | after 2 | not required |
| 4 | Real Send pipeline | after 3 | required |
| 5 | Bridge to Base | after 4 | required |
| 6 | PWA polish, mining page, history page | after 5 | not required |

Phases ship sequentially. After each, run `/handoff <phase>` so context resets cleanly. Cursor gate = the contract gets a second-opinion review by Cursor before code starts on that phase.

---

## Frozen architectural commitments

These are not up for renegotiation inside a phase. If a phase forces revisiting one, stop and update the contract first.

1. **Keys are browser-side, always.** Encrypted IndexedDB. Mnemonic never leaves the device. No server custody, no key escrow, no "forgot password" recovery — only mnemonic-restore.
2. **Encryption is mandatory.** No opt-out.
3. **No mode toggle.** Auto-detect: local node (`localhost:8332` DIL, `localhost:9332` DilV) if reachable, else public explorer API. Status pill shows which path is active. One click to manually configure.
4. **Mnemonic is the source of truth.** BIP39 24-word, optional passphrase.
5. **Address validation always uses Base58Check checksum**, never just format/length.
6. **Signing is local.** WASM Dilithium3. WASM init failure → full-screen failure state, no silent degradation.
7. **One canonical URL.** `wallet.dilithion.org`. No Tauri/Electron in v1.
8. **Two chains, one wallet.** Same Dilithium key derives both DIL and DilV balances. Chain selection is a UI affordance, not address-prefix discrimination.

---

## Critical crypto parameters (MUST MATCH legacy exactly)

The legacy web wallet at `c:\Users\will\dilithion\website\wallet.html` already implements all of this — when in doubt, port from there. These values are non-negotiable because existing IndexedDB blobs and node-wallet imports must continue to decrypt.

### Encryption
- PBKDF2-SHA256, **100,000 iterations**, 16-byte random salt, AES-256-GCM
- Stored as `{ciphertext, salt, iv}` base64 blobs

### Mnemonic & seed
- BIP39 24 words, English wordlist, optional passphrase
- Seed: PBKDF2-SHA3-512 with salt `"dilithion-mnemonic" + passphrase` → 64-byte master seed

### HD derivation — READ THIS, IT'S THE COMMON PITFALL
- BIP44 path `m/44'/573'/0'/0'/0'` (coin type **573**, all-hardened)
- **Derivation uses HMAC-SHA3-512, NOT the BIP32 standard HMAC-SHA512**
- Copying a stock BIP32 library will derive different addresses and silently brick recovery. Confirm test vectors against the legacy wallet before declaring Phase 1 done.

### Address derivation
- `Base58Check(versionByte=0x1E, payload=SHA3-256(SHA3-256(pubkey)).slice(0,20))`
- 'D' prefix on all addresses

### Signing
- WASM Dilithium3 (`dilithium.js` exposing `_dilithium_keypair / _sign / _verify`)
- Built from the Dilithium reference implementation. Existing build at `c:\Users\will\dilithion\website\js\dilithium.wasm` (24KB)
- **Per-input weight: 5,265 bytes** (signature 3,309 + pubkey 1,952). Critical for fee estimation and consolidation thresholds.

---

## Recent UX decisions (2026-04-30) — LOCKED for v1

These change defaults from what most BTC-derivative wallets do. Don't accidentally flip them back during implementation.

### 1. Change goes back to the same address, not a fresh one

**Default behavior:** when a user sends a transaction, change returns to the address that contributed the largest input value (or to a user-designated primary address, if set in the account drawer). "Generate fresh change address each send" is an opt-in setting, off by default.

**Why this is inverted from BTC:**
- Real operational pain. Miners were generating repeated support questions about "where did my coins go?" because change scattered balances across a tree of HD-derived addresses they didn't recognize on the explorer
- The mental model "my address has X, I sent Y, now it has X−Y−fee" matches how non-crypto users think about money. Fighting that mental model has measurable cost — Will is paying for it right now in support questions
- Bitcoin's fresh-change-by-default is for privacy-conscious audiences. Dilithion's current user base is miners and infrastructure operators who self-select for clarity. Different audience, different defaults.
- Dilithium pubkeys (1,952 bytes) publish on-chain at first spend anyway, so the privacy heuristic that fresh-change defeats is already weaker on us than on ECDSA

**UTXO-selection edge case:** if a tx pulls inputs from multiple addresses, "the same address" is ambiguous. The decision is **largest-contributor wins** — change goes back to the address that supplied the most input value. If the user has set a primary address in account drawer, that overrides.

**Bridge exemption:** the bridge wallet keeps fresh-change explicitly. Forensic-audit clarity matters more than UX for that one wallet. Need a "bridge mode" flag in setup or settings — see open question 1 below.

### 2. Auto-consolidation runs in the background

**Default behavior:** the wallet automatically merges small UTXOs back into one larger UTXO at the same address.

- **Triggers on:** wallet unlock (30s delay) and during idle periods (60s no-input)
- **Threshold:** any HD address with ≥30 UTXOs, OR dust ratio exceeds 5% (UTXO spend cost = 5,265 bytes × fee rate exceeds 5% of its value)
- **Throttle:** max one consolidation per address per 6 hours
- **Fee:** consensus minimum (5,000 ions/KB). A 50-input consolidation = ~263 KB = ~0.013 DIL minimum fee.

**Why this is needed:** Dilithium signatures are 5,265 bytes per input. A miner accumulating daily payouts for a year has 365+ UTXOs. Without consolidation, sending becomes prohibitively expensive and eventually hits block-relay size limits. This pairs naturally with the same-address-default — change accumulates at one address, then periodic consolidation collapses it back into one fat UTXO.

**Visibility rule:** silent at decision time (no approval prompt), but **logged in the activity timeline** as "Consolidated N UTXOs at address D..." with txid linking to the explorer. Brief "Optimizing..." status pill while running. The whole point is removing miner support questions, so don't recreate the same support burden by surprising users with unexplained outgoing txs. Display cumulative consolidation fees in the settings panel for user audit.

**Skips:**
- Pending-send addresses (UTXOs reserved for in-flight tx)
- Immature coinbase outputs (consolidation would just fail)
- Addresses flagged as "bridge mode"
- Locked wallets — defer until natural unlock, never auto-prompt for password

**Opt-out:** account drawer toggle, default ON.

---

## Migration story for existing wallet.dat users

Zero new node-side work. The dilithion-node already exposes:
- `exportmnemonic` — gated by `ADMIN_WALLET` permission, requires `walletpassphrase` first
- `dumpprivkey` / `importprivkey` — same gating

Phase 2 setup detects a local node (`localhost:8332` or `:9332` reachable), prompts the user for the node's RPC passphrase, calls `exportmnemonic`, pre-fills the result into the password-set screen. The new wallet encrypts that mnemonic under a fresh user-chosen password and stores it in IndexedDB. Legacy `wallet.dat` is left untouched as backup.

No CLI required. No file copy. No exposed seed in terminal.

**Pre-fund address note:** ~277K DilV sits on 3 non-HD pre-fund addresses (DQwMX2C, DGem6bm, DESyLBc) imported into the legacy wallet.dat. These are NOT derivable from the mnemonic. Will is OK leaving funds on non-HD addresses for now — the new wallet doesn't need to support them.

---

## Network layer (Phase 3)

### Local node RPC
- DIL: `http://localhost:8332`, DilV: `http://localhost:9332`
- Headers: `Authorization: Basic base64(user:pass)` + `X-Dilithion-RPC: 1` (CSRF guard, mandatory)
- JSON-RPC 2.0

### Public explorer API (fallback)
- DIL: `https://explorer.dilithion.org/api/v1/...`
- DilV: `https://explorer.dilithion.org/dilv/api/v1/...`
- nginx CORS proxy already wired up (proxy_hide_header to prevent double headers)

### Auto-detect
- Try local node ping (3s timeout) on app start + every 60s
- Per-chain detection — possible to have local DIL but explorer DilV
- User can override via connection settings modal (force-local / force-explorer)

### Status pill
- Green = local node, blue = explorer API, red = disconnected
- Sync-freshness indicator: green <30s, amber 30s–2min, red >2min

---

## Bridge integration (Phase 5)

### Contracts on Base
- **wDIL:** `0x30629128d1d3524F1A01B9c385FbE84fDCbD36C2`
  - `maxPerDeposit = 500 DIL`, `dailyMintCap = 5,000 DIL`
- **wDilV:** `0xF162F6B432FeeD73458D4653ef8E74Ba014403E8`
  - `maxPerDeposit = 5,000 DilV`, `dailyMintCap = 10,000 DilV`

### Deposit format (L1 → L2)
3-output transaction:
1. Bridge address (chain-specific)
2. `OP_RETURN` (`0x6a`) with payload: Base recipient address + amount + chain id + version
3. Change

### Direction
- DIL → wDIL and DilV → wDilV are in scope for Phase 5
- Reverse (wDIL → DIL) calls a different smart contract — out of scope this phase. Link to public bridge UI for now.

### Base recipient validation
- EVM address checksum (EIP-55) — full validation, not just format

---

## Known constraints (Dilithium-specific gotchas)

### Per-input weight is huge
- 5,265 bytes per input (sig 3,309 + pubkey 1,952). Bitcoin's is ~107.
- Affects fee math, UTXO selection (favor fewer larger UTXOs), and the consolidation threshold
- A 50-input tx is ~263 KB. A 100-input tx may exceed relay limits.

### Pubkey reuse
- Address reuse on Dilithium publishes the 1,952-byte pubkey. Heavy-traffic addresses (bridge, exchanges) should keep fresh-change behavior.
- Dilithium3 is fine for substantial reuse; this is a soft signal, not a security failure.

### Mempool confirmation timing on DilV
- DilV mempool txs take 15-20 blocks (~12 min) to confirm
- Only the sender's node includes mempool txs in its block template; other miners' templates are built before the tx propagates
- Not a bug — inherent to VDF mining with distribution rounds. UI should set expectations accordingly.

### Two recent node-side fixes (April 2026)
These mean Phase 4 send-history UI can rely on the node:
- **Fix A** — wallet sends now persist to disk immediately (`SaveUnlocked` after `RecordSentTransaction`). Previously survived only by luck.
- **Fix B** — `gettransaction` is now wallet-aware. Returns top-level `wallet:{category, amount, fee, to_address, time}` and `details[]` per-output array.

---

## Out-of-scope (explicit non-goals for v1)

Don't build any of these unless the master contract is updated first:

- Native binary distribution (Tauri / Electron) — PWA install covers desktop UX
- Light/full mode user-facing toggle — auto-detect or bust
- Multi-account UI — single account, multi-address. Add accounts when first user complains.
- Watch-only addresses
- Custom fee selection UI — consensus minimum + dynamic floor is the safe default
- iOS PWA install (Apple's restrictions; Safari users get the web URL)
- Hardware wallet support (no Dilithium hardware exists)
- Token swap / DEX integration — bridge is the surface for moving value
- Fiat price display — needs an oracle, defer until exchange-listed
- Settings mega-page — settings live where they're used (theme in top bar, network in status pill, account in drawer)
- Server-side anything beyond static hosting — no backend, no analytics, no telemetry
- Reverse bridge direction (wDIL → DIL withdrawal) — own phase later if demand exists

---

## Process

### Per phase
1. Update `.claude/contracts/active_contract.md` with the phase's acceptance criteria (or use the master roadmap if you prefer one source of truth)
2. If the phase has a Cursor gate (Phase 1, 4, 5): write a self-contained Cursor review prompt covering the risk areas, paste Cursor's response back, integrate findings before code
3. Build with TodoWrite — one task in_progress at a time, mark complete immediately
4. Test exhaustively — `pnpm build` clean, `pnpm test` clean, manual end-to-end
5. PR with `gh pr create` — never `git push origin main` (protected branch)
6. Run `/handoff <phase>` after merge so context resets

### Cross-cutting requirements
- Every external dep added must be **pinned** (no `^`/`~` ranges) for crypto-adjacent packages: `qrcode`, `idb`, anything HD or BIP39
- `pnpm audit` clean before each phase merges
- No emoji in code or UI
- Tests alongside crypto / tx / bridge code, not optional. UI tests not required (Storybook scope creep).
- Privacy: no analytics, no telemetry, no third-party scripts
- Address-set queries to public explorer batched and rate-limited (a single observer shouldn't trivially correlate address ownership)

---

## Reference files (in dilithion repo)

| File | What it is |
|---|---|
| `.claude/contracts/archived_wallet_master_now_a_roadmap.md` | **AUTHORITATIVE SPEC.** Master roadmap with full Phase 0-6 acceptance criteria. Read this end-to-end. |
| `website/wallet.html` | Legacy web wallet — port primitives from here (WASM loader, HD scan, transaction builder) |
| `website/js/dilithium.wasm` | Pre-built WASM Dilithium3 (24KB) |
| `website/js/dilithium-crypto.js` | Legacy crypto module — has 4 derivation bug fixes already applied |
| `website/js/local-wallet.js` | HD scan implementation (GAP_LIMIT=250) |
| `website/js/transaction-builder.js` | Sighash + chain ID logic |
| `src/rpc/server.cpp` | Node RPC interface — `exportmnemonic` is at line ~232, gated by `ADMIN_WALLET` |

---

## Open questions for Will

If you hit any of these during implementation, ask before deciding:

1. **Bridge-mode flag UX.** Recommendation: explicit checkbox in setup ("This wallet will hold bridge funds — keep fresh-change addresses and disable auto-consolidation for forensic clarity"), with a clear warning. Alternative: settings toggle the user can flip later. Worth confirming with Will before locking in.
2. **Multi-input UTXO selection when source addresses differ.** Largest-contributor-wins is locked for change destination. Open question: when the user has UTXOs scattered across many addresses, do we surface a "send-from picker" or just collapse to primary? Recommendation: collapse to primary by default, expose picker as "advanced" affordance in Phase 6.
3. **Consolidation visibility.** Recommendation locked: silent at decision time, logged in timeline. If users find the silent behavior surprising during testing, may need to add a "you have N UTXOs that will be consolidated soon" pre-notice. Re-evaluate after Phase 4 lands.

---

## Hard safety rules (apply to any wallet code)

These are inherited from the major-change workflow at `memory/template_major_change_workflow.md`:

1. **NEVER** delete `wallet.dat` or any wallet file without explicit, in-conversation user permission
2. **NEVER** touch the bridge wallet on NYC seed (138.197.68.128) without explicit GO per action — bridge wallet holds ~244,943 DIL + ~531,773 DilV
3. **NEVER** print, log, or write to file any private key, mnemonic seed, or passphrase, even in debug paths
4. **NEVER** `git push origin main` — protected branch. Always feature branch → `gh pr create` → merge in GitHub UI
5. **NEVER** bypass the contract / Cursor-review protocol for gated phases (1, 4, 5)

---

## Contact

- Will Barton — `will@bananatree.com.au`

Good luck. The legacy code at `website/wallet.html` works and ships real txs today — port from it where you can, modernize where it's worth it, and keep crypto parameters byte-identical so existing wallets continue to decrypt.
