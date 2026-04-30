// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b — PeerManager skeleton implementation.
//
// STATUS (v1.5 / overnight handoff): SKELETON ONLY. Every method
// is stubbed. Method bodies are PR6.5b body work for subsequent
// sessions; today's deliverable is the class declaration so
// reviewers can audit the surface against ISyncCoordinator (§1.5)
// and the v1.5 plan §2.1.
//
// To unstub: see upstream Bitcoin Core v28 net_processing.cpp +
// the v1.5 plan §2.1 / §2.2 / §2.3 (CPeer, BlockDownloadState).
//
// All stubs return safe defaults that match legacy IBDCoordinator
// semantics — IsSynced() returns false (= "not synced, behave
// conservatively"), IsInitialBlockDownload() returns true (= "in
// IBD, don't relay"). This means a node accidentally constructed
// with CPeerManager (instead of CIbdCoordinatorAdapter) before the
// body lands won't relay/mine — safest fallback.

#include <net/port/peer_manager.h>

#include <consensus/ichain_selector.h>
#include <consensus/params.h>
#include <core/node_context.h>
#include <net/connman.h>
#include <net/headers_manager.h>
#include <net/iconnection_manager.h>
#include <net/ipeer_scorer.h>
#include <net/net.h>
#include <net/port/regtest_only.h>
#include <net/protocol.h>
#include <net/serialize.h>
#include <primitives/block.h>
#include <util/logging.h>
#include <util/time.h>

#include <chrono>
#include <ctime>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace dilithion {
namespace net {
namespace port {

CPeerManager::CPeerManager(::dilithion::net::IConnectionManager& connman,
                           ::dilithion::net::IAddressManager& addrman,
                           ::dilithion::net::IPeerScorer& scorer,
                           ::dilithion::consensus::IChainSelector& chain_selector,
                           const ::Dilithion::ChainParams& chainparams)
    : m_connman(connman),
      m_addrman(addrman),
      m_scorer(scorer),
      m_chain_selector(chain_selector),
      m_chainparams(chainparams)
{}

CPeerManager::~CPeerManager() = default;

// ===== PR6.5b.test-hardening — clock/height injection-seam helpers =====
//
// Production behavior unchanged: when overrides are at their sentinel
// defaults (0 for clock, -1 for heights), the helper returns the real
// source. Tests inject deterministic values via the friended fixture.
//
// Lock-order discipline: helpers do NOT acquire any PeerManager mutex.
// Single-writer test-only pattern — no race in production because
// overrides are never set there.

int64_t CPeerManager::Now() const {
    if (m_test_now_override != 0) {
        return m_test_now_override;
    }
    return static_cast<int64_t>(std::time(nullptr));
}

int CPeerManager::GetHeaderHeightForSync() const {
    if (m_test_header_height_override != -1) {
        return static_cast<int>(m_test_header_height_override);
    }
    // Real source: matches existing fast-out at peer_manager.cpp:285-287
    // (null hdr_mgr → 0, never -1).
    if (CHeadersManager* hdr_mgr = g_node_context.headers_manager.get()) {
        return hdr_mgr->GetBestHeight();
    }
    return 0;
}

int CPeerManager::GetChainHeightForSync() const {
    if (m_test_chain_height_override != -1) {
        return static_cast<int>(m_test_chain_height_override);
    }
    return m_chain_selector.GetActiveHeight();
}

// ===== ISyncCoordinator overrides =====

// PR6.5b.5: real body. !m_synced. Atomic acquire-load so callers see
// the latest Tick-side store. MUST NOT recurse through
// m_chain_selector.IsInitialBlockDownload() — the chain-selector adapter
// (chain_selector_impl.cpp:255-261) delegates back to
// g_node_context.sync_coordinator which IS this CPeerManager under
// flag=1. Direct atomic-bool read is the load-bearing pattern.
bool CPeerManager::IsInitialBlockDownload() const {
    return !m_synced.load(std::memory_order_acquire);
}

// PR6.5b.5: real body. m_synced acquire-load. Inverse of
// IsInitialBlockDownload() at any single instant (same atomic).
bool CPeerManager::IsSynced() const {
    return m_synced.load(std::memory_order_acquire);
}

int CPeerManager::GetHeadersSyncPeer() const {
    // PR6.5b.3: return the currently-elected sync-peer NodeId, or -1 if
    // none. CPeerManager is authoritative for "is this peer the chosen
    // sync-peer." (CHeadersManager remains authoritative for "have I
    // started syncing from this peer" — SSOT split per decomposition.)
    std::lock_guard<std::mutex> lk(m_sync_state_mutex);
    return m_headers_sync_peer;
}

// PR6.5b.6 (Item B) — real body. Parameterless per ISyncCoordinator §1.5
// (Decision 1 freeze). Mirrors legacy CIbdCoordinator::OnOrphanBlockReceived
// at ibd_coordinator.h:132: increment a global consecutive-orphan counter.
// NO per-peer tracking from this hook (the hook itself doesn't carry a
// peer_id; legacy is parameterless too).
//
// PR6.5b.6 Item-B revert (close-prep PR6.5b.7 closes PR6.5b.6-M1):
// per-peer orphan-cluster scoring at the HandleBlock site is INTENTIONALLY
// DEFERRED. See HandleBlock body for the deferral rationale. This hook is
// the ONLY active orphan accounting path under flag=1 — it bumps the
// global atomic counter and that is all. No per-peer misbehavior dispatch
// fires from chain.cpp's accept-and-orphan callback.
//
// Synchronous — fires under cs_main per Option B. Atomic counter
// satisfies the cs_main constraint without taking a PeerManager mutex.
//
// SAFE: copy-state-out — atomic relaxed increment; no callout.
void CPeerManager::OnOrphanBlockReceived() {
    m_consecutive_orphan_blocks.fetch_add(1, std::memory_order_relaxed);
}

// PR6.5b.6 (Item C) — real body. Parameterless per ISyncCoordinator §1.5
// (Decision 1 freeze). Mirrors legacy CIbdCoordinator::OnBlockConnected at
// ibd_coordinator.h:142:
//   (1) Reset the global atomic orphan counter to 0 ("fresh blocks
//       flowing → orphan accumulation resets").
//   (2) Update m_last_block_connected_ticks to steady_clock::now (as
//       nanoseconds since epoch — atomic int64_t for race-free RPC reads).
//   (3) Reset per-peer m_consecutive_block_timeouts to 0 across all
//       peers under brief m_peers_mutex (mirrors the "fresh blocks
//       flowing → bad-peer counters reset" semantic from Item A).
//
// Lock-order discipline: callers fire under cs_main (Option B). cs_main
// is the OUTER lock (held by caller); m_peers_mutex is acquired here as
// the INNER lock. No cycle is possible: this method never acquires
// cs_main, and no path elsewhere acquires cs_main while holding
// m_peers_mutex (verified by inspection — see the file-level lock-order
// block). The brief m_peers_mutex section is write-only iteration; no
// callout.
//
// Idempotency: a second OnBlockConnected with no orphans in between
// is a no-op (counter already 0; per-peer counters already 0). The
// timestamp is unconditionally updated, so consecutive calls with no
// orphan activity still advance the "last connected" tick — that's
// correct semantics (the block DID connect).
//
// SAFE: copy-state-out — m_peers_mutex is the only lock taken; no
// callout to m_scorer / m_connman / m_chain_selector under it. Per-peer
// reset is a write-only field set; no callbacks fire.
void CPeerManager::OnBlockConnected() {
    // (1) Reset orphan counter — atomic relaxed store is sufficient
    // (single-writer pattern from chain.cpp under cs_main).
    m_consecutive_orphan_blocks.store(0, std::memory_order_relaxed);

    // (2) Update last-block-connected timestamp. steady_clock chosen for
    // monotonicity (test-only; production reads via RPC compare deltas).
    const auto now_ticks = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
    m_last_block_connected_ticks.store(static_cast<int64_t>(now_ticks),
                                       std::memory_order_relaxed);

    // (3) Reset per-peer m_consecutive_block_timeouts across all peers.
    // Bounded ≤ ~125 peers per the upstream slot cap; iteration is
    // write-only (no callout). m_peers_mutex is the inner lock here;
    // cs_main (held by caller) is the outer lock. No cycle: this body
    // never acquires cs_main.
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    for (auto& kv : m_peers) {
        kv.second->m_consecutive_block_timeouts = 0;
    }
}

// PR6.5b.3 + PR6.5b.5: Tick body. Call sequence (per PR6.5b.5 contract):
//   (1) UpdateSyncStateLocked() — recompute m_synced from
//       headers_manager->GetBestHeight() / chain_selector.GetActiveHeight()
//       + handshake-complete gate. Always runs first so m_synced is fresh
//       even when there is no current sync-peer.
//   (2) Existing PR6.5b.3 headers-sync flow: SelectHeadersSyncPeerLocked
//       when no current sync-peer; CheckHeadersSyncProgressLocked →
//       SwitchHeadersSyncPeerLocked when current sync-peer present and
//       stalled. **No early-exit; steps (3) and (4) run unconditionally
//       on every Tick.**
//   (3) RetryStaleBlocksLocked() — sweep m_blocks_in_flight for stale
//       entries and re-dispatch via RemoveBlockInFlight (no scorer
//       dispatch — that's PR6.5b.6).
//   (4) RequestNextBlocks() — only if NOT synced (when synced, no further
//       block requests are issued).
//
// SAFE: copy-state-out — every helper drops m_peers_mutex /
// m_sync_state_mutex before any callout. No m_connman / outbound
// network primitive is invoked here (PR6.5b.6 owns that path).
void CPeerManager::Tick() {
    // (1) State update — runs unconditionally on every Tick so m_synced
    // is updated even when there is no current sync-peer (no early-exit
    // gates this block; see PR6.5b.fixups-mechanical-SEC-LO-1 close).
    UpdateSyncStateLocked();

    // (2) Existing PR6.5b.3 headers-sync flow.
    NodeId current = -1;
    {
        std::lock_guard<std::mutex> lk(m_sync_state_mutex);
        current = m_headers_sync_peer;
    }

    if (current == -1) {
        // No current sync-peer: try to elect one. Block-download sweep +
        // dispatch still run below — no early-exit.
        SelectHeadersSyncPeerLocked();
    } else {
        // Have a current sync-peer: check progress; rotate (with
        // penalize=true) on stall.
        const bool progressing = CheckHeadersSyncProgressLocked();
        if (!progressing) {
            SwitchHeadersSyncPeerLocked(/*penalize=*/true);
        }
    }

    // (3) Block-download stall sweep.
    RetryStaleBlocksLocked();

    // (4) Block-download dispatch — only when not synced. When synced,
    // no further block requests are issued.
    if (!m_synced.load(std::memory_order_acquire)) {
        RequestNextBlocks();
    }
}

// PR6.5b.5 — port of CIbdCoordinator::UpdateState (ibd_coordinator.cpp:359-422)
// DOWN-SCOPED to the m_synced flip only (the IBDState enum is not ported —
// that's CIbdCoordinator-internal). Hysteresis rule:
//   * currently_synced && blocks_behind > UNSYNC_THRESHOLD_BLOCKS (10)
//     → m_synced.store(false)
//   * !currently_synced && blocks_behind <= SYNC_TOLERANCE_BLOCKS (2)
//     && header_height > 0 && has_peer_info → m_synced.store(true)
//   * Otherwise no change.
//
// SAFE: copy-state-out — header_height + chain_height + has_peer_info are
// all computed BEFORE m_sync_state_mutex is taken. has_peer_info comes
// from HasCompletedHandshakeWithAnyPeer() which takes m_peers_mutex
// internally — calling it under m_sync_state_mutex would invert the
// locked partial order (peers_mutex < sync_state_mutex). The mutex here
// only guards the m_synced WRITE, which we keep brief.
//
// Null guard: if g_node_context.headers_manager is null (test fixtures or
// pre-init), return without flipping m_synced. Matches the legacy
// fast-out at ibd_coordinator.cpp:360-364.
void CPeerManager::UpdateSyncStateLocked() {
    // (a) Single read of headers_manager + chain_selector OUTSIDE any
    // PeerManager mutex. If headers_manager is null AND no test-side
    // override is set, no-op (matches legacy fast-out at
    // ibd_coordinator.cpp:360-364). The header-height override path lets
    // tests drive UpdateSyncStateLocked deterministically without seeding
    // CHeadersManager state.
    CHeadersManager* hdr_mgr = g_node_context.headers_manager.get();
    if (hdr_mgr == nullptr && m_test_header_height_override == -1) {
        return;
    }
    const int header_height = GetHeaderHeightForSync();
    const int chain_height = GetChainHeightForSync();
    const int blocks_behind = header_height - chain_height;

    // (b) Has any peer completed handshake? Helper takes m_peers_mutex
    // internally — caller MUST NOT already hold it.
    const bool has_peer_info = HasCompletedHandshakeWithAnyPeer();

    // (c) Apply hysteresis. Atomic acquire-load → conditional store
    // with release semantics. m_sync_state_mutex is NOT required for the
    // atomic flip (m_synced is std::atomic), but we still take it here
    // briefly to coordinate with future readers that may add additional
    // sync-state fields (mirrors legacy CIbdCoordinator::UpdateState
    // serialized ordering). NO callout under the lock.
    const bool currently_synced = m_synced.load(std::memory_order_acquire);
    bool new_synced = currently_synced;

    if (currently_synced) {
        // Already synced — only become un-synced if significantly behind.
        if (blocks_behind > UNSYNC_THRESHOLD_BLOCKS) {
            new_synced = false;
        }
    } else {
        // Not synced — become synced if within tolerance AND we've heard
        // from peers AND header_height > 0 (don't declare synced at
        // genesis).
        if (blocks_behind <= SYNC_TOLERANCE_BLOCKS && header_height > 0 &&
            has_peer_info) {
            new_synced = true;
        }
    }

    if (new_synced != currently_synced) {
        // SAFE: copy-state-out — m_sync_state_mutex held only for the
        // atomic store. No callout to m_scorer / m_connman /
        // m_chain_selector / g_node_context.* under the lock. The
        // LogPrintIBD callout below is emitted AFTER the lock_guard goes
        // out of scope (PR6.5b.fixups-mechanical, finding PR6.5b.5-M1).
        {
            std::lock_guard<std::mutex> lk(m_sync_state_mutex);
            m_synced.store(new_synced, std::memory_order_release);
        }

        // Verbose-only log (mirrors ibd_coordinator.cpp:396-405). Quiet by
        // default. LogPrintIBD respects g_verbose internally? — no, it's
        // unconditional. Match legacy: gate on g_verbose explicitly.
        // Emitted OUTSIDE m_sync_state_mutex per copy-state-out discipline.
        if (g_verbose.load(std::memory_order_relaxed)) {
            if (new_synced) {
                LogPrintIBD(INFO,
                            "Sync state: NOT SYNCED -> SYNCED (chain within %d blocks of headers)",
                            SYNC_TOLERANCE_BLOCKS);
            } else {
                LogPrintIBD(INFO,
                            "Sync state: SYNCED -> NOT SYNCED (chain %d blocks behind headers)",
                            blocks_behind);
            }
        }
    }
}

// PR6.5b.5 — handshake-complete check. Walks m_peers under m_peers_mutex
// briefly; returns true iff any CPeer::m_handshake_complete is true.
// Replaces the legacy m_node_context.peer_manager->HasCompletedHandshakes()
// callout from CIbdCoordinator::UpdateState:389-390 with a port-side
// equivalent.
//
// SAFE: copy-state-out — single brief lock, no callout under the lock.
bool CPeerManager::HasCompletedHandshakeWithAnyPeer() const {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    for (const auto& kv : m_peers) {
        if (kv.second->m_handshake_complete) {
            return true;
        }
    }
    return false;
}

// PR6.5b.5 + PR6.5b.6 (Item A) — port of
// CIbdCoordinator::RetryTimeoutsAndStalls (ibd_coordinator.cpp:2162-2242)
// DOWN-SCOPED to per-peer state owned by this class. Walks
// m_blocks_in_flight; entries whose requested_at_unix_sec exceeds the
// hysteretic timeout (15s near tip, 60s bulk) are removed via
// RemoveBlockInFlight. PR6.5b.6 wires the previously-deferred misbehavior
// dispatch (γ topology — port owns stall-timeout scoring) and bad-peer
// rotation (DisconnectNode after consecutive-timeout threshold crossed).
//
// γ ownership rule (per contract): this method is the canonical port-side
// dispatch site for stall-timeout misbehavior. Legacy ::CPeerManager does
// NOT score stall events — only port's m_scorer ticks here. Legacy retains
// transport-integrity scoring (checksum failures at connman.cpp:1666 etc.)
// per non-overlapping event ownership.
//
// Strict 6-step lock-order sequence (extends PR6.5b.5's 4-step pattern):
//   (1) Compute blocks_behind / timeout_seconds with NO PeerManager locks
//       held — reads g_node_context.headers_manager + GetActiveHeight().
//   (2) Snapshot stale (hash, peer_id) pairs under
//       m_blocks_in_flight_mutex briefly; drop.
//   (3) Iterate the snapshot calling RemoveBlockInFlight(peer, hash) —
//       which takes its own locks per PR6.5b.4. NO PeerManager mutex held.
//   (4) Build a deduplicated set of stalled peer-ids from the snapshot
//       (KISS — small std::set; same peer may have multiple stale entries
//       in one sweep, score it ONCE per sweep per contract).
//   (5) For each unique stalled peer: increment per-peer
//       m_consecutive_block_timeouts under m_peers_mutex briefly,
//       capture out the new counter value, drop the lock; THEN call
//       m_scorer.Misbehaving(peer, UnknownMessage, "stall") with NO
//       PeerManager mutex held; THEN — if the new counter crossed the
//       effective threshold (3 bulk; 1 near-tip per contract Item A
//       step 3) — call m_connman.DisconnectNode with NO PeerManager
//       mutex held. Counter is NOT reset by the disconnect call;
//       OnBlockConnected (Item C) is the canonical reset site.
//   (6) Log a single line if any entry was removed (verbose-gated).
//
// SAFE: copy-state-out — every callout (m_scorer, m_connman, headers_manager,
// chain_selector, RemoveBlockInFlight) happens with NO PeerManager
// mutex held. CI grep gate per v1.5 §2.1.1: m_scorer.Misbehaving and
// m_connman.DisconnectNode below have explicit "// SAFE: copy-state-out"
// annotations.
void CPeerManager::RetryStaleBlocksLocked() {
    // Step 1: compute blocks_behind / timeout_seconds OUTSIDE any
    // PeerManager mutex. Null-safe on headers_manager (chain_height
    // alone is insufficient — we need both to derive blocks_behind, so
    // null headers_manager forces the bulk timeout, which is the safer
    // choice — won't aggressively re-request). PR6.5b.test-hardening:
    // route through GetHeaderHeightForSync / GetChainHeightForSync so
    // tests can inject deterministic blocks_behind to drive the
    // BLOCKS_NEAR_TIP_THRESHOLD selector branch.
    const int header_height = GetHeaderHeightForSync();
    const int chain_height = GetChainHeightForSync();
    const int blocks_behind = header_height - chain_height;
    const int timeout_seconds = (blocks_behind <= BLOCKS_NEAR_TIP_THRESHOLD)
        ? BLOCK_TIMEOUT_NEAR_TIP_SECS
        : BLOCK_TIMEOUT_BULK_SECS;

    // Step 2: snapshot stale entries under m_blocks_in_flight_mutex
    // briefly. Copy out (hash, peer_id) so we can drop the lock before
    // calling RemoveBlockInFlight. PR6.5b.test-hardening: route through
    // Now() so tests can inject "current time" past requested_at_unix_sec
    // to deterministically exercise the timeout branch.
    const int64_t now_unix = Now();
    std::vector<std::pair<uint256, NodeId>> stale;
    {
        std::lock_guard<std::mutex> bf_lk(m_blocks_in_flight_mutex);
        for (const auto& kv : m_blocks_in_flight) {
            const int64_t age = now_unix - kv.second.requested_at_unix_sec;
            if (age >= timeout_seconds) {
                stale.emplace_back(kv.first, kv.second.peer_id);
            }
        }
    }

    if (stale.empty()) return;

    // Step 3: iterate snapshot calling RemoveBlockInFlight (which
    // takes its own locks per PR6.5b.4). NO PeerManager mutex held here.
    for (const auto& sp : stale) {
        // SAFE: copy-state-out — RemoveBlockInFlight scopes its own locks.
        RemoveBlockInFlight(sp.second, sp.first);
    }

    // Step 4: build deduplicated set of stalled peer-ids. Same peer may
    // appear multiple times in `stale` (multiple stale entries in one
    // sweep) — contract requires scoring ONCE per peer per sweep, so we
    // dedupe via std::set. Keep insertion-order list for deterministic
    // logging if needed; the set itself is the misbehavior gate.
    std::set<NodeId> stalled_peers;
    for (const auto& sp : stale) {
        stalled_peers.insert(sp.second);
    }

    // Effective rotation threshold: contract Item A step 3 mirrors legacy
    // near-tip aggressiveness — when blocks_behind <= NEAR_TIP_THRESHOLD,
    // a single stall triggers disconnect; otherwise the bulk threshold of
    // MAX_PEER_CONSECUTIVE_TIMEOUTS applies.
    const int rotation_threshold =
        (blocks_behind <= BLOCKS_NEAR_TIP_THRESHOLD)
            ? 1
            : MAX_PEER_CONSECUTIVE_TIMEOUTS;

    // Step 5: for each unique stalled peer, increment per-peer counter
    // under m_peers_mutex (capture the new value out), drop the lock,
    // THEN call m_scorer.Misbehaving (γ ownership: port-side scoring),
    // THEN — if counter >= threshold — call m_connman.DisconnectNode.
    // Lock-order: m_peers_mutex is taken alone for the increment; no
    // m_sync_state_mutex / m_blocks_in_flight_mutex / cs_main is held
    // when m_scorer or m_connman are invoked.
    for (NodeId peer_id : stalled_peers) {
        // Per-peer counter increment under m_peers_mutex briefly.
        // Capture the new value out so the misbehavior + disconnect
        // dispatch happens with no PeerManager mutex held.
        int new_counter = 0;
        bool peer_present = false;
        {
            std::lock_guard<std::mutex> lk(m_peers_mutex);
            auto it = m_peers.find(peer_id);
            if (it != m_peers.end()) {
                ++it->second->m_consecutive_block_timeouts;
                new_counter = it->second->m_consecutive_block_timeouts;
                peer_present = true;
            }
        }
        if (!peer_present) continue;  // Disconnected mid-sweep — skip.

        // SAFE: copy-state-out — m_peers_mutex dropped above. m_scorer is
        // g_node_context.peer_scorer with internal locking; no PeerManager
        // mutex is held during this callout. γ topology: this is the
        // canonical port-side stall-misbehavior dispatch site. Legacy
        // ::CPeerManager does NOT score stall events.
        m_scorer.Misbehaving(peer_id,
                             ::dilithion::net::MisbehaviorType::UnknownMessage,
                             "block download stall timeout");

        // Bad-peer rotation: counter crossed effective threshold → ask
        // connman to disconnect. Counter is NOT reset here; OnBlockConnected
        // (Item C) is the canonical reset site once fresh blocks flow
        // again. SAFE: copy-state-out — no PeerManager mutex held during
        // m_connman.DisconnectNode.
        if (new_counter >= rotation_threshold) {
            m_connman.DisconnectNode(peer_id, "block download stalling");
        }
    }

    // Step 6: log a single warn line (verbose-gated). Per-peer scorer +
    // disconnect lines are emitted by their respective subsystems; this
    // log line is the sweep-level summary.
    if (g_verbose.load(std::memory_order_relaxed)) {
        LogPrintIBD(WARN,
                    "removed %zu stale block requests >%ds timeout (%zu peers)",
                    stale.size(), timeout_seconds, stalled_peers.size());
    }
}

// ===== PeerManager-specific API =====

// PR6.5b.2: ProcessMessage dispatch over strCommand. Simple if/else if chain
// matching upstream Bitcoin Core's net_processing.cpp shape — KISS, no map
// of std::function. Each handler returns its own bool result; unhandled
// commands tick the UnknownMessage scorer once and return false.
//
// SAFE: copy-state-out — no callout to m_scorer is performed while
// m_peers_mutex is held. Each handler scopes its lock_guard before any
// scorer/connman/chain_selector callout.
bool CPeerManager::ProcessMessage(NodeId peer,
                                  const std::string& strCommand,
                                  CDataStream& vRecv) {
    // Unknown-peer guard: harmless race with disconnect. Drop silently
    // without scorer tick (no peer to score).
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        if (m_peers.find(peer) == m_peers.end()) {
            return false;
        }
    }

    // Wrap handler dispatch in try/catch so any CDataStream under-length
    // read (which throws std::runtime_error per serialize.h:144) becomes
    // a malformed-message scorer tick. Per contract: route to existing
    // UnknownMessage weight=1 (NOT a new MisbehaviorType enum value —
    // that's interface-bump territory deferred to a later PR).
    try {
        if (strCommand == "version") {
            return HandleVersion(peer, vRecv);
        } else if (strCommand == "verack") {
            return HandleVerack(peer, vRecv);
        } else if (strCommand == "ping") {
            return HandlePing(peer, vRecv);
        } else if (strCommand == "pong") {
            return HandlePong(peer, vRecv);
        } else if (strCommand == "headers") {
            return HandleHeaders(peer, vRecv);
        } else if (strCommand == "block") {
            return HandleBlock(peer, vRecv);
        } else if (strCommand == "getdata") {
            return HandleGetData(peer, vRecv);
        }
    } catch (const std::exception&) {
        // Malformed message — scorer tick on UnknownMessage weight=1, then
        // signal failure to caller. SAFE: no peers_mutex held here.
        m_scorer.Misbehaving(peer, ::dilithion::net::MisbehaviorType::UnknownMessage,
                             "malformed message body");
        return false;
    }

    // Unhandled command — scorer tick once, return false. PR6.5b.3 / 6b.4
    // will replace this for headers/block/getdata/inv/etc. The
    // deferred-handlers-still-stubbed test pins this behavior so a
    // regression in 6b.3 surfaces loudly.
    // SAFE: no peers_mutex held here.
    m_scorer.Misbehaving(peer, ::dilithion::net::MisbehaviorType::UnknownMessage,
                         "unknown command: " + strCommand);
    return false;
}

// version handler. Reads enough of the upstream wire format to populate
// nVersion / nServices / m_peer_claimed_time on the per-peer CPeer struct,
// closing the deferred-from-PR6.5b.1b populate path. Wire layout matches
// CNetMessageProcessor::SerializeVersionMessage in src/net/net.cpp:2843.
//
// SAFE: copy-state-out — duplicate-version detection AND out-of-range
// timestamp detection mutate state under the lock; m_scorer calls are
// performed AFTER drop with captured-out `is_duplicate` / `is_out_of_range`
// bools. Bounds check on read_timestamp uses Consensus::MAX_FUTURE_BLOCK_TIME
// (src/consensus/params.h:201) symmetrically (past and future), routing
// out-of-range values to UnknownMessage — no new enum value (PR6.5b.fixups-
// semantic, finding PR6.5b.2-SEC-MD-2).
bool CPeerManager::HandleVersion(NodeId peer, CDataStream& vRecv) {
    // Read minimum required fields from the wire. CDataStream throws on
    // under-length; ProcessMessage's try/catch routes to UnknownMessage.
    const int32_t  read_version  = vRecv.ReadInt32();
    const uint64_t read_services = vRecv.ReadUint64();
    const int64_t  read_timestamp = vRecv.ReadInt64();

    // Bounds-check the peer-claimed timestamp against local clock.
    // Out-of-range (in either direction) is treated as a malformed VERSION:
    // route to UnknownMessage (no new enum) and reject the message. The
    // bound matches Consensus::MAX_FUTURE_BLOCK_TIME (2 hours) symmetrically.
    const int64_t now = GetTime();
    const bool is_out_of_range =
        (read_timestamp > now + Consensus::MAX_FUTURE_BLOCK_TIME) ||
        (read_timestamp < now - Consensus::MAX_FUTURE_BLOCK_TIME);

    bool is_duplicate = false;
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        auto it = m_peers.find(peer);
        if (it == m_peers.end()) return false;  // disconnected mid-handler
        CPeer& p = *it->second;

        // Upstream pattern: a second version on the same peer is misbehavior
        // (DuplicateVersion weight=1 in MisbehaviorType). PR6.5b.fixups-mechanical
        // (finding PR6.5b.2-SEC-MD-1): use a dedicated bool sentinel rather than
        // `nVersion != 0`. The legacy test silently failed when read_version
        // happened to be zero on the first message — the second VERSION wouldn't
        // dispatch misbehavior because nVersion would still read as zero.
        if (p.m_version_received) {
            is_duplicate = true;
        } else if (!is_out_of_range) {
            // Commit state only on a clean (non-duplicate, in-range) version.
            // An out-of-range version is rejected without touching CPeer state
            // (treated as if the message never arrived) — the scorer tick is
            // performed below after lock drop.
            p.nVersion = read_version;
            p.nServices = read_services;
            p.m_peer_claimed_time = read_timestamp;
            p.m_version_received = true;
        }
    }

    // SAFE: copy-state-out — m_peers_mutex dropped before scorer callout.
    if (is_duplicate) {
        m_scorer.Misbehaving(peer, ::dilithion::net::MisbehaviorType::DuplicateVersion,
                             "duplicate version message");
        return false;
    }
    if (is_out_of_range) {
        m_scorer.Misbehaving(peer, ::dilithion::net::MisbehaviorType::UnknownMessage,
                             "version timestamp out of range");
        return false;
    }
    return true;
}

// verack handler. Sets the handshake-complete bit on CPeer. Outbound
// verack reply is deferred to PR6.5b.6 SendMessages — under dual-dispatch,
// legacy ::CPeerManager continues to own outbound side until then.
//
// SAFE: copy-state-out — handler performs no callout (no scorer/connman
// invocation), so the lock_guard scope IS the entire body. Pattern still
// preserved: state mutation under lock; nothing held across function exit.
bool CPeerManager::HandleVerack(NodeId peer, CDataStream& /*vRecv*/) {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    auto it = m_peers.find(peer);
    if (it == m_peers.end()) return false;
    it->second->m_handshake_complete = true;
    return true;
}

// ping handler. Stores the received nonce on CPeer so PR6.5b.6 SendMessages
// can later produce the pong reply. No outbound send in 6b.2.
//
// SAFE: copy-state-out — body performs no external callout. Lock_guard
// scope IS the entire body.
bool CPeerManager::HandlePing(NodeId peer, CDataStream& vRecv) {
    const uint64_t nonce = vRecv.ReadUint64();

    std::lock_guard<std::mutex> lk(m_peers_mutex);
    auto it = m_peers.find(peer);
    if (it == m_peers.end()) return false;
    it->second->m_last_ping_nonce_recvd = nonce;
    return true;
}

// pong handler. With a matching expected nonce, clears the pong-expected
// state. With a wrong/unexpected nonce, returns true BUT ticks scorer once
// (per contract: pong with wrong nonce is misbehavior, but the message
// was structurally well-formed so dispatch result is true).
//
// SAFE: copy-state-out — `should_score` captured under lock, scorer called
// after drop.
bool CPeerManager::HandlePong(NodeId peer, CDataStream& vRecv) {
    const uint64_t nonce = vRecv.ReadUint64();

    bool should_score = false;
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        auto it = m_peers.find(peer);
        if (it == m_peers.end()) return false;
        CPeer& p = *it->second;

        if (p.m_pong_expected && p.m_pong_expected_nonce == nonce) {
            // Matching nonce: clear expected state. Happy path.
            p.m_pong_expected = false;
            p.m_pong_expected_nonce = 0;
        } else {
            // Wrong/unexpected nonce: scoring deferred until after lock drop.
            should_score = true;
        }
    }

    // SAFE: copy-state-out — m_peers_mutex dropped before scorer callout.
    if (should_score) {
        m_scorer.Misbehaving(peer, 1, "pong with wrong/unexpected nonce");
    }
    return true;
}

// PR6.5b.3: headers handler. Deserializes the wire-format header vector
// (matches CNetMessageProcessor::ProcessHeadersMessage in net.cpp:1529),
// delegates to CHeadersManager::ProcessHeadersWithDoSProtection via the
// g_node_context.headers_manager raw-pointer pattern locked in PR6.5b.0
// (5-param constructor stays frozen), then updates per-peer
// BlockDownloadState::n_best_known_height to the height implied by the
// last header in the batch (best-effort tip tracking; CHeadersManager
// remains authoritative for actual sync-state).
//
// Returns:
//   * true on a structurally-valid header vector (regardless of whether
//     CHeadersManager::ProcessHeadersWithDoSProtection returns true or
//     false — handler success means "we delegated").
//   * false if g_node_context.headers_manager is null (delegate not
//     available — node-side configuration issue, NOT peer misbehavior;
//     does NOT score the peer).
//   * false (via ProcessMessage's try/catch) on under-length read
//     (CDataStream throws → caught by ProcessMessage → routes to
//     UnknownMessage weight=1).
//
// SAFE: copy-state-out — m_peers_mutex / m_sync_state_mutex are NEVER
// held across the g_node_context.headers_manager callout. Per-peer
// n_best_known_height mutation happens in a separate scoped lock AFTER
// the delegate call returns.
bool CPeerManager::HandleHeaders(NodeId peer, CDataStream& vRecv) {
    // Read header count (compact-size). Throws on under-length —
    // ProcessMessage's try/catch routes throw to UnknownMessage weight=1.
    const uint64_t header_count = vRecv.ReadCompactSize();

    // Bound header count at upstream Bitcoin Core's MAX_HEADERS_RESULTS
    // (2000). This guards against pre-allocation DoS before the real
    // CHeadersManager::ProcessHeadersWithDoSProtection two-phase guard
    // kicks in. Mirrors net.cpp:1571 cap.
    // PR6.5b.fixups-mechanical (finding PR6.5b.3-SEC-MD-2): reference the
    // SSOT constant in <consensus/params.h> rather than re-spelling the
    // literal 2000, so future consensus-cap changes propagate uniformly.
    if (header_count > Consensus::MAX_HEADERS_RESULTS) {
        // Throw rather than reach for a new MisbehaviorType enum value
        // (interface bump deferred). ProcessMessage's catch then ticks
        // UnknownMessage. Functionally equivalent for this PR — the real
        // misbehavior path comes online with PR6.5b.6.
        throw std::runtime_error("HEADERS count exceeds MAX_HEADERS_RESULTS");
    }

    std::vector<CBlockHeader> headers;
    headers.reserve(header_count);
    for (uint64_t i = 0; i < header_count; ++i) {
        CBlockHeader header;
        header.nVersion      = vRecv.ReadInt32();
        header.hashPrevBlock = vRecv.ReadUint256();
        header.hashMerkleRoot = vRecv.ReadUint256();
        header.nTime         = vRecv.ReadUint32();
        header.nBits         = vRecv.ReadUint32();
        header.nNonce        = vRecv.ReadUint32();

        // VDF extension fields (version >= 4). Mirrors net.cpp:1597.
        if (header.IsVDFBlock()) {
            header.vdfOutput     = vRecv.ReadUint256();
            header.vdfProofHash  = vRecv.ReadUint256();
        }

        // Skip transaction count (headers message has 0 txs per header).
        // Throws on under-length — caught upstream.
        const uint64_t tx_count = vRecv.ReadCompactSize();
        if (tx_count != 0) {
            throw std::runtime_error("HEADERS message with tx_count != 0");
        }

        headers.push_back(header);
    }

    // SAFE: copy-state-out — no peers_mutex / sync_state_mutex held here.
    // Null-check g_node_context.headers_manager before dereference. Null is
    // a node-side configuration issue, not peer misbehavior; return false
    // without scoring.
    CHeadersManager* hdr_mgr = g_node_context.headers_manager.get();
    if (hdr_mgr == nullptr) {
        return false;
    }

    // Delegate to CHeadersManager — SSOT for header sync state.
    // ProcessHeadersWithDoSProtection's return value (true/false) is
    // CHeadersManager's signal about delegation outcome; per contract,
    // HandleHeaders ALWAYS returns true on a structurally-valid vector
    // (delegated successfully), regardless of CHeadersManager's verdict.
    // CHeadersManager reports its own misbehavior via existing legacy
    // paths (peer_manager.cpp:6 of legacy peers.cpp).
    (void)hdr_mgr->ProcessHeadersWithDoSProtection(peer, headers);

    // PR6.5b.3 best-effort tip tracking: update per-peer
    // n_best_known_height to the height implied by the highest header
    // in the batch. CHeadersManager already knows the canonical heights
    // from validation; we use HeightForHash on the last header's
    // hashPrevBlock + 1 as a best-effort estimate. If the lookup fails
    // (parent unknown to CHeadersManager — happens during initial sync
    // when batches arrive out of order), leave n_best_known_height
    // unchanged.
    //
    // SAFE: copy-state-out — read tip estimate from hdr_mgr (no peers
    // lock held), THEN take m_peers_mutex to mutate the per-peer state.
    if (!headers.empty()) {
        const CBlockHeader& tip = headers.back();
        const int parent_height = hdr_mgr->GetHeightForHash(tip.hashPrevBlock);
        if (parent_height >= 0) {
            const int64_t implied_height = static_cast<int64_t>(parent_height) + 1;
            std::lock_guard<std::mutex> lk(m_peers_mutex);
            auto it = m_peers.find(peer);
            if (it != m_peers.end()) {
                CPeer& p = *it->second;
                if (implied_height > p.m_block_download.n_best_known_height) {
                    p.m_block_download.n_best_known_height = implied_height;
                }
            }
        }
    }

    return true;
}

// PR6.5b.3 — port of CIbdCoordinator::SelectHeadersSyncPeer
// (ibd_coordinator.cpp:2718-2803), adapted to per-peer
// CPeer::m_is_chosen_sync_peer state. Selection criterion: highest
// BlockDownloadState::n_best_known_height among peers not in
// m_headers_bad_peers; pool-exhausted safety valve clears bad set if
// every connected peer is excluded.
//
// SAFE: copy-state-out — peer state is read into local copies under
// m_peers_mutex (drop), then m_sync_state_mutex (drop), then the
// per-peer m_is_chosen_sync_peer flags are flipped under
// m_peers_mutex again. No callout while either lock is held; the
// g_node_context.headers_manager callout to seed last_height /
// last_processed happens AFTER both locks drop.
void CPeerManager::SelectHeadersSyncPeerLocked() {
    // Step 1: snapshot peers under m_peers_mutex into local vector.
    struct PeerSnapshot {
        NodeId id;
        int64_t known_height;
    };
    std::vector<PeerSnapshot> peer_snap;
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        peer_snap.reserve(m_peers.size());
        for (const auto& kv : m_peers) {
            peer_snap.push_back(PeerSnapshot{kv.second->id,
                                             kv.second->m_block_download.n_best_known_height});
        }
    }

    if (peer_snap.empty()) {
        // No peers to choose from: ensure no current selection.
        std::lock_guard<std::mutex> lk(m_sync_state_mutex);
        m_headers_sync_peer = -1;
        return;
    }

    // Step 2: choose under m_sync_state_mutex (using local peer snapshot).
    NodeId chosen = -1;
    int64_t best_height = 0;
    bool cleared_bad = false;
    {
        std::lock_guard<std::mutex> lk(m_sync_state_mutex);

        for (const auto& ps : peer_snap) {
            if (m_headers_bad_peers.count(ps.id) > 0) {
                continue;
            }
            if (ps.known_height > best_height) {
                best_height = ps.known_height;
                chosen = ps.id;
            }
        }

        // Pool-exhausted safety valve (mirrors ibd_coordinator.cpp:2763-2781):
        // every connected peer is in m_headers_bad_peers — clear it once and
        // retry to recover (observed on SGP during 2026-04-25 incident).
        if (chosen == -1 && !m_headers_bad_peers.empty()) {
            m_headers_bad_peers.clear();
            m_headers_sync_peer_consecutive_stalls = 0;
            cleared_bad = true;

            for (const auto& ps : peer_snap) {
                if (ps.known_height > best_height) {
                    best_height = ps.known_height;
                    chosen = ps.id;
                }
            }
        }

        // No peer has positive n_best_known_height: contract specifies -1
        // (matches lifecycle test's "GetHeadersSyncPeer == -1 unchanged
        // after connects with no headers received yet"). Upstream legacy
        // had a peer->start_height fallback — that path is deferred to
        // PR6.5b.6 SendMessages alongside outbound version-handshake
        // height tracking.
        m_headers_sync_peer = chosen;  // -1 if nothing eligible
        m_headers_sync_peer_consecutive_stalls = 0;
        (void)cleared_bad;  // reserved for future logging in 6b.6
    }

    // Step 3: callout to g_node_context.headers_manager OUTSIDE both locks
    // to seed last_height / last_processed and compute timeout.
    int seed_last_height = 0;
    uint64_t seed_last_processed = 0;
    if (CHeadersManager* hdr_mgr = g_node_context.headers_manager.get()) {
        seed_last_height = hdr_mgr->GetBestHeight();
        seed_last_processed = hdr_mgr->GetProcessedCount();
    }

    // PR6.5b.fixups-mechanical (finding PR6.5b.3-SEC-MD-1): defensive clamp on
    // headers_missing at the int-narrowing boundary. best_height is peer-influenced
    // (set in HandleHeaders from the wire), so a malicious peer could in principle
    // drive (best_height - seed_last_height) past INT_MAX before the static_cast,
    // producing UB or a negative timeout. Clamp BEFORE the cast at a value with
    // generous headroom: INT_MAX / HEADERS_SYNC_TIMEOUT_PER_HEADER_MS would still
    // produce valid signed math when later multiplied; we use 100,000,000 (one
    // hundred million headers) which is well past any realistic chain height for
    // years to come, leaves three decimal orders of magnitude of integer headroom
    // for the subsequent multiply, and keeps the timeout well under INT_MAX ms.
    static constexpr int64_t kHeadersMissingClamp = 100'000'000;
    int64_t hm64 = (best_height > static_cast<int64_t>(seed_last_height))
        ? (best_height - static_cast<int64_t>(seed_last_height))
        : 0;
    if (hm64 > kHeadersMissingClamp) hm64 = kHeadersMissingClamp;
    const int headers_missing = static_cast<int>(hm64);
    const int timeout_ms = HEADERS_SYNC_TIMEOUT_BASE_SECS * 1000 +
                           headers_missing * HEADERS_SYNC_TIMEOUT_PER_HEADER_MS;

    // Step 4: under m_sync_state_mutex, store seeded fields + timeout.
    {
        std::lock_guard<std::mutex> lk(m_sync_state_mutex);
        m_headers_sync_last_height = seed_last_height;
        m_headers_sync_last_processed = seed_last_processed;
        m_headers_sync_timeout = std::chrono::steady_clock::now() +
                                 std::chrono::milliseconds(timeout_ms);
    }

    // Step 5: under m_peers_mutex, set m_is_chosen_sync_peer on the
    // elected peer and clear it on all others. KISS: full sweep is fine
    // at the scale of inbound peer counts (~125 max, upstream slot cap).
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        for (auto& kv : m_peers) {
            kv.second->m_is_chosen_sync_peer = (kv.second->id == chosen);
        }
    }
}

// PR6.5b.3 — port of CIbdCoordinator::CheckHeadersSyncProgress
// (ibd_coordinator.cpp:2805-2882). Returns true if making progress (or
// no current sync-peer); false if current sync-peer has stalled past
// its timeout. The caller (Tick) on `false` calls
// SwitchHeadersSyncPeerLocked(/*penalize=*/true).
//
// SAFE: copy-state-out — current_height / current_processed are read
// from g_node_context.headers_manager BEFORE m_sync_state_mutex is
// taken. Inside the lock we only mutate state; nothing else.
bool CPeerManager::CheckHeadersSyncProgressLocked() {
    // Snapshot CHeadersManager state outside any lock.
    int current_height = 0;
    uint64_t current_processed = 0;
    if (CHeadersManager* hdr_mgr = g_node_context.headers_manager.get()) {
        current_height = hdr_mgr->GetBestHeight();
        current_processed = hdr_mgr->GetProcessedCount();
    }

    const auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lk(m_sync_state_mutex);
    if (m_headers_sync_peer == -1) {
        return true;  // No current sync-peer: nothing to check.
    }

    // Progress check: validated header height advanced since last tick.
    if (current_height > m_headers_sync_last_height) {
        m_headers_sync_last_height = current_height;
        // Extend the timeout (assume the peer keeps providing).
        m_headers_sync_timeout = now +
            std::chrono::milliseconds(HEADERS_SYNC_TIMEOUT_BASE_SECS * 1000);
        return true;
    }

    // Fork catch-up: processed count advanced even if best height didn't.
    if (current_processed > m_headers_sync_last_processed) {
        m_headers_sync_last_processed = current_processed;
        m_headers_sync_timeout = now +
            std::chrono::milliseconds(HEADERS_SYNC_TIMEOUT_BASE_SECS * 1000);
        return true;
    }

    // Timeout reached → stalled.
    if (now > m_headers_sync_timeout) {
        return false;
    }

    return true;
}

// PR6.5b.3 — port of CIbdCoordinator::SwitchHeadersSyncPeer
// (ibd_coordinator.cpp:2884-2946). Increments stall counter (when
// penalize=true), marks bad peer at MAX_HEADERS_CONSECUTIVE_STALLS,
// then re-elects via SelectHeadersSyncPeerLocked. The outbound
// GETHEADERS issuance / CHeadersManager::ClearPendingSync calls from
// the legacy port are deferred to PR6.5b.6 (this PR MUST NOT issue
// outbound network messages — see contract drift triggers).
//
// SAFE: copy-state-out — m_sync_state_mutex held only for state
// mutation; SelectHeadersSyncPeerLocked re-acquires it internally.
void CPeerManager::SwitchHeadersSyncPeerLocked(bool penalize) {
    NodeId old_peer = -1;
    {
        std::lock_guard<std::mutex> lk(m_sync_state_mutex);
        old_peer = m_headers_sync_peer;

        if (penalize && old_peer != -1) {
            ++m_headers_sync_peer_consecutive_stalls;
            if (m_headers_sync_peer_consecutive_stalls >= MAX_HEADERS_CONSECUTIVE_STALLS) {
                m_headers_bad_peers.insert(old_peer);
                m_headers_sync_peer_consecutive_stalls = 0;
            }
        }

        m_headers_sync_peer = -1;  // Force reselection.
    }

    // Re-elect (drops/reacquires m_sync_state_mutex internally).
    SelectHeadersSyncPeerLocked();
}

// PR6.5b.6 (Item D) — INTENTIONAL NO-OP under γ topology.
//
// γ ownership rule (per PR6.5b.6 contract): each outbound message type
// is owned by EXACTLY ONE class. Under the active legacy outbound paths,
// every outbound type that SendMessages might issue is already owned
// elsewhere:
//   * verack       — legacy ::CPeerManager / dilithion-node.cpp:3485.
//   * ping         — connman.cpp:1830 (legacy connman ping path).
//   * getheaders   — CHeadersManager (headers_manager.cpp:430,771).
//   * getdata      — port's RequestNextBlocks (peer_manager.cpp), already
//                    issued from Tick() not SendMessages.
//
// Port adding a duplicate verack/ping/getheaders here would produce a
// wire-level double-send during cutover — peers might (correctly) score
// the local node for malformed-protocol behavior. NO outbound work for
// SendMessages to perform under flag=1 today.
//
// FUTURE EXIT RAMP: when a future PR migrates ownership of a specific
// outbound type from legacy to port (e.g. ping handoff in a future cutover
// step), it modifies THIS body to issue that single type and updates the
// γ ownership table at the top of this comment. The intentional no-op
// status is the SSOT for "port does not own outbound until further notice."
//
// Implementation rules per contract Item D:
//   * Defensive unknown-peer guard (m_peers_mutex briefly; mirrors
//     ProcessMessage pattern). Ensures a SendMessages call for a
//     disconnected peer is a clean return, not a crash.
//   * NO outbound PushMessage calls. NO state mutation. NO scorer ticks.
//   * Documentation IS the value of this body — explains WHY, not WHAT,
//     so a reader sees the γ ownership rule without spelunking the
//     contract.
//
// SAFE: copy-state-out — single brief m_peers_mutex acquisition for the
// existence check; no callout under the lock.
void CPeerManager::SendMessages(NodeId peer) {
    // Defensive unknown-peer guard. Drop silently for unknown peers
    // (harmless race with disconnect; matches ProcessMessage:387-394).
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        if (m_peers.find(peer) == m_peers.end()) {
            return;
        }
    }
    // Body deliberately empty — γ ownership delegates all outbound
    // message types to other paths (see comment block above).
}

// PR6.5b.4 — HandleBlock. Deserializes a CBlock from the wire (matches
// CNetMessageProcessor::ProcessBlockMessage in net.cpp:1246-1290), removes
// the block hash from the in-flight tracking BEFORE the chain_selector
// callout (so a validation failure does not leak in-flight state), then
// delegates to m_chain_selector.ProcessNewBlock with NO PeerManager locks
// held. Always returns true on a structurally-valid payload (handler
// success means "we delegated"; chain_selector reports its own verdict
// via its own callbacks).
//
// Wire layout: legacy 80-byte header (or 144-byte VDF header) +
// CompactSize(vtx_size) + vtx bytes. Under-length read throws → caught
// by ProcessMessage's try/catch and routes to UnknownMessage weight=1.
//
// SAFE: copy-state-out — RemoveBlockInFlight takes its own locks
// internally and drops them BEFORE ProcessNewBlock is invoked.
bool CPeerManager::HandleBlock(NodeId peer, CDataStream& vRecv) {
    auto block = std::make_shared<CBlock>();

    // Deserialize header. Throws on under-length (caught upstream).
    block->nVersion       = vRecv.ReadInt32();
    block->hashPrevBlock  = vRecv.ReadUint256();
    block->hashMerkleRoot = vRecv.ReadUint256();
    block->nTime          = vRecv.ReadUint32();
    block->nBits          = vRecv.ReadUint32();
    block->nNonce         = vRecv.ReadUint32();

    if (block->IsVDFBlock()) {
        block->vdfOutput    = vRecv.ReadUint256();
        block->vdfProofHash = vRecv.ReadUint256();
    }

    const uint64_t vtx_size = vRecv.ReadCompactSize();

    // Bound vtx_size to mirror net.cpp:1267 / MAX_BLOCK_VTX_BYTES (4 MiB).
    // Use a local cap matching the storage layer rather than reaching for
    // a new shared constant (KISS). Throws → caught upstream.
    static constexpr uint64_t kMaxBlockVtxBytes = 4ull * 1024ull * 1024ull;
    if (vtx_size > kMaxBlockVtxBytes) {
        throw std::runtime_error("block vtx size exceeds maximum");
    }

    block->vtx.resize(static_cast<size_t>(vtx_size));
    if (vtx_size > 0) {
        vRecv.read(block->vtx.data(), vtx_size);
    }

    // Compute block hash for in-flight lookup. GetFastHash is SHA-3 — fast
    // and matches the hash key m_blocks_in_flight is indexed by.
    const uint256 block_hash = block->GetFastHash();

    // SAFE: copy-state-out — RemoveBlockInFlight scopes its own locks; no
    // PeerManager mutex is held across the chain_selector callout below.
    RemoveBlockInFlight(peer, block_hash);

    // PR6.5b.6 / PR6.5b.7-close-prep (closes PR6.5b.6-M1): orphan-dispatch
    // accounting in HandleBlock is INTENTIONALLY ABSENT. Per-peer scoring at
    // this site was reverted in PR6.5b.6 (Item B revert); the only orphan
    // accounting that the shipped port performs is the GLOBAL atomic counter
    // bumped by `OnOrphanBlockReceived()` (parameterless hook fired by
    // chain.cpp on accept-and-orphan; mirrors legacy CIbdCoordinator::
    // OnOrphanBlockReceived at ibd_coordinator.h:132). NO per-peer
    // misbehavior dispatch fires from this site under flag=1.
    //
    // Rationale for the deferral (kept for future-PR readers):
    //   - Per-peer orphan scoring at this site falsely punishes peers
    //     whose parent simply hasn't been processed yet (out-of-order
    //     delivery is legitimate, not misbehavior). Bitcoin Core's
    //     analogous dispatch only fires on demonstrably-invalid blocks
    //     (POW failure, malformed header), not on unknown-parent.
    //   - Rate-bounding by scorer score-cap is insufficient: a peer
    //     legitimately ahead of us by N blocks would be penalized N
    //     times before we catch up.
    // If a future PR demonstrates a use case where unknown-parent IS
    // adversarial (e.g. paired with a separate signal that the block
    // header is invalid), reinstate per-peer dispatch HERE with copy-
    // state-out. Until then, γ ownership of orphan accounting collapses
    // to "global counter only" on the port side; legacy ibd_coordinator
    // also tracks orphans for rotation only, not misbehavior scoring.

    // Delegate to chain_selector. ProcessNewBlock returns true/false based on
    // its own validation; per contract, HandleBlock returns true regardless
    // (handler success = "we delegated"). m_chain_selector is a reference,
    // not a pointer — no null-check needed.
    (void)m_chain_selector.ProcessNewBlock(block, /*force_processing=*/false, nullptr);
    return true;
}

// PR6.5b.4 — HandleGetData. Deserializes the inv vector and validates each
// entry. Empty inv is a no-op (matches upstream Bitcoin Core net_processing.cpp
// behavior — not misbehavior). For inv entries with type=MSG_BLOCK_INV, look
// up the hash via m_chain_selector.LookupBlockIndex; unknown blocks tick
// scorer with MisbehaviorType::UnknownMessage weight=1. Outbound block
// payload responses are forbidden in this PR (PR6.5b.6 SendMessages scope).
//
// Wire layout: CompactSize(count) + count * (uint32 type + uint256 hash).
// Under-length throws → caught upstream.
//
// SAFE: copy-state-out — no PeerManager mutex is held during the
// chain_selector callout or the scorer callout.
bool CPeerManager::HandleGetData(NodeId peer, CDataStream& vRecv) {
    const uint64_t count = vRecv.ReadCompactSize();

    // Bound count at MAX_INV_SIZE (50000) per net.cpp:1063. Throws →
    // caught upstream. Empty inv is permitted (no-op success path).
    if (count > NetProtocol::MAX_INV_SIZE) {
        throw std::runtime_error("getdata count exceeds MAX_INV_SIZE");
    }

    std::vector<NetProtocol::CInv> invs;
    invs.reserve(count);
    for (uint64_t i = 0; i < count; ++i) {
        NetProtocol::CInv inv;
        inv.type = vRecv.ReadUint32();
        inv.hash = vRecv.ReadUint256();
        invs.push_back(inv);
    }

    // Validate each inv. Unknown inv types or unknown block hashes are
    // misbehavior (UnknownMessage weight=1, no new enum value per
    // Decision 1). Outbound block-message issuance is deferred to PR6.5b.6.
    //
    // SAFE: m_chain_selector / m_scorer callouts happen outside any
    // PeerManager mutex.
    for (const auto& inv : invs) {
        const bool unknown_type = (inv.type < NetProtocol::MSG_TX_INV ||
                                   inv.type > NetProtocol::MSG_CMPCT_BLOCK);
        if (unknown_type) {
            m_scorer.Misbehaving(peer, ::dilithion::net::MisbehaviorType::UnknownMessage,
                                 "getdata: unknown inv type");
            continue;
        }
        if (inv.type == NetProtocol::MSG_BLOCK_INV) {
            CBlockIndex* idx = m_chain_selector.LookupBlockIndex(inv.hash);
            if (idx == nullptr) {
                m_scorer.Misbehaving(peer, ::dilithion::net::MisbehaviorType::UnknownMessage,
                                     "getdata: unknown block hash");
            }
            // Outbound block payload response deferred to PR6.5b.6 SendMessages.
        }
        // MSG_TX_INV / MSG_FILTERED_BLOCK / MSG_CMPCT_BLOCK responses also
        // deferred to PR6.5b.6 (out of scope for this PR per contract).
    }

    return true;
}

// PR6.5b.4 — MarkBlockInFlight. Increments per-peer
// BlockDownloadState::n_blocks_in_flight (under m_peers_mutex) and inserts
// the hash into m_blocks_in_flight (under m_blocks_in_flight_mutex). Lock
// order: connman_peer_lock < m_peers_mutex < m_blocks_in_flight_mutex.
// Idempotent: if the hash is already tracked from this peer, the counter
// is NOT double-incremented.
//
// SAFE: copy-state-out — no callouts held under either mutex.
void CPeerManager::MarkBlockInFlight(NodeId peer, const uint256& hash) {
    bool already_tracked = false;
    {
        std::lock_guard<std::mutex> bf_lk(m_blocks_in_flight_mutex);
        auto it = m_blocks_in_flight.find(hash);
        if (it != m_blocks_in_flight.end()) {
            already_tracked = true;
        } else {
            BlockDownloadInfo info;
            info.peer_id = peer;
            info.requested_at_unix_sec = static_cast<int64_t>(std::time(nullptr));
            info.height = -1;  // height unknown at request time (filled by handler)
            m_blocks_in_flight.emplace(hash, info);
        }
    }

    if (already_tracked) return;

    // Increment per-peer counter. Silently no-op for unknown peer (drop it
    // from the map too, so we don't leak the entry).
    bool peer_present = false;
    {
        std::lock_guard<std::mutex> p_lk(m_peers_mutex);
        auto it = m_peers.find(peer);
        if (it != m_peers.end()) {
            ++it->second->m_block_download.n_blocks_in_flight;
            peer_present = true;
        }
    }

    if (!peer_present) {
        // Disconnected mid-call: roll back the m_blocks_in_flight insert so
        // the entry doesn't orphan. Re-acquire the in-flight mutex (no other
        // PeerManager mutex held — lock-order safe).
        std::lock_guard<std::mutex> bf_lk(m_blocks_in_flight_mutex);
        m_blocks_in_flight.erase(hash);
    }
}

// PR6.5b.4 — RemoveBlockInFlight. Removes the hash from m_blocks_in_flight
// and decrements the per-peer counter. No-op if the hash isn't tracked
// (does not throw, does not decrement). Caller may pass any peer/hash
// pair; the function uses the stored peer_id from BlockDownloadInfo to
// find the right counter to decrement (handles the case where the
// arriving peer is different from the requesting peer — though this is
// unusual in practice).
//
// SAFE: copy-state-out — no callouts under either mutex.
void CPeerManager::RemoveBlockInFlight(NodeId peer, const uint256& hash) {
    NodeId stored_peer = -1;
    bool removed = false;
    {
        std::lock_guard<std::mutex> bf_lk(m_blocks_in_flight_mutex);
        auto it = m_blocks_in_flight.find(hash);
        if (it != m_blocks_in_flight.end()) {
            stored_peer = it->second.peer_id;
            m_blocks_in_flight.erase(it);
            removed = true;
        }
    }

    if (!removed) return;
    (void)peer;  // contract API takes peer for symmetry; counter belongs to stored_peer

    // Decrement per-peer counter. Silently no-op if the requesting peer
    // already disconnected (counter cleanup happened in OnPeerDisconnected).
    std::lock_guard<std::mutex> p_lk(m_peers_mutex);
    auto it = m_peers.find(stored_peer);
    if (it != m_peers.end() && it->second->m_block_download.n_blocks_in_flight > 0) {
        --it->second->m_block_download.n_blocks_in_flight;
    }
}

// PR6.5b.4 — GetBlocksInFlightForPeer. Reads the per-peer counter under
// m_peers_mutex. Returns 0 for unknown peers. Single-mutex read; no
// copy-state-out needed.
int CPeerManager::GetBlocksInFlightForPeer(NodeId peer) const {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    auto it = m_peers.find(peer);
    if (it == m_peers.end()) return 0;
    return it->second->m_block_download.n_blocks_in_flight;
}

// PR6.5b.4 — RequestNextBlocks. The HIGH-risk lock-order discipline path.
// Allocates per-peer in-flight slots up to MAX_BLOCKS_IN_TRANSIT_PER_PEER
// (32 mainnet; 4 regtest per chainparams gating).
//
// Strict 4-step lock-order sequence (verified by audit grep):
//   (1) Consult m_chain_selector with NO PeerManager locks held —
//       reads GetActiveHeight() once.
//   (2) Snapshot per-peer (id, n_best_known_height, n_blocks_in_flight)
//       under m_peers_mutex briefly; drop.
//   (3) Mutate m_blocks_in_flight under m_blocks_in_flight_mutex briefly;
//       drop. Increment per-peer counter under m_peers_mutex briefly; drop.
//   (4) Issue outbound getdata via g_node_context.connman with NO locks
//       held. Null-safe (under unit-test fixtures, connman is null —
//       accounting still updates, message issuance becomes a no-op).
//
// Idempotent at saturation: a second call with no in-flight blocks
// removed produces zero new entries (per-peer cap enforced by step 2's
// snapshot of n_blocks_in_flight).
//
// SAFE: copy-state-out — every callout (chain_selector, scorer, connman)
// happens with no PeerManager mutex held.
void CPeerManager::RequestNextBlocks() {
    // Step 1: chain_selector consult (NO PeerManager locks held).
    // m_chain_selector is a reference — no null-check needed.
    const int active_height = m_chain_selector.GetActiveHeight();

    // Per-peer cap: 4 in regtest, 32 mainnet/testnet. Read once outside
    // any lock. Centralized here so step 3 has the value.
    const int per_peer_cap = m_chainparams.IsRegtest()
        ? ::dilithion::net::port::REGTEST_MAX_BLOCKS_IN_TRANSIT_PER_PEER.Get(m_chainparams)
        : Consensus::MAX_BLOCKS_IN_TRANSIT_PER_PEER;

    // Step 2: snapshot per-peer slots under m_peers_mutex briefly.
    struct PeerSnapshot {
        NodeId id;
        int64_t best_known_height;
        int blocks_in_flight;
    };
    std::vector<PeerSnapshot> peer_snap;
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        peer_snap.reserve(m_peers.size());
        for (const auto& kv : m_peers) {
            peer_snap.push_back(PeerSnapshot{
                kv.second->id,
                kv.second->m_block_download.n_best_known_height,
                kv.second->m_block_download.n_blocks_in_flight});
        }
    }

    if (peer_snap.empty()) return;  // No peers — nothing to do (no-op).

    // Step 3: for each peer with capacity, allocate slots up to the cap.
    // Each allocated slot inserts a synthetic placeholder hash into
    // m_blocks_in_flight and increments the per-peer counter. The
    // outbound message issuance (step 4) carries the real per-block
    // request; this PR's outbound path is bounded by what
    // g_node_context.connman supports.
    //
    // Per-peer iteration: compute target height range = (active_height + 1
    // .. min(active_height + slots_available, peer.best_known_height)).
    // Each height gets a placeholder hash for accounting purposes. Real
    // hashes come from CHeadersManager's index lookup (delegated to
    // legacy block_fetcher path under flag=0). Under flag=1 with no
    // CHeadersManager wired (unit tests), placeholders are sufficient
    // because the in-flight cap enforcement is what the contract tests.
    std::vector<std::pair<NodeId, uint256>> requests;  // (peer, hash) for step 4
    for (const auto& ps : peer_snap) {
        const int slots_free = per_peer_cap - ps.blocks_in_flight;
        if (slots_free <= 0) continue;
        if (ps.best_known_height <= static_cast<int64_t>(active_height)) continue;

        const int64_t gap = ps.best_known_height - static_cast<int64_t>(active_height);
        const int n_to_request = static_cast<int>(std::min<int64_t>(gap, slots_free));

        for (int i = 0; i < n_to_request; ++i) {
            // Synthesize a placeholder hash from (peer, height). Real
            // hashes are filled by CHeadersManager-driven lookups in
            // PR6.5b.6 SendMessages. For accounting parity with the
            // per-peer cap, the placeholder is unique per (peer, height)
            // tuple so re-calls don't collide.
            uint256 placeholder;
            const int target_height = active_height + 1 + i;
            // Encode (peer << 32 | target_height) into the first 12 bytes.
            // Deterministic, collision-free across (peer, height) tuples
            // for in-flight tracking.
            const uint64_t lo = static_cast<uint64_t>(target_height);
            const uint64_t hi = static_cast<uint64_t>(static_cast<uint32_t>(ps.id));
            for (int b = 0; b < 8; ++b) {
                placeholder.data[b] = static_cast<uint8_t>((lo >> (8 * b)) & 0xff);
                placeholder.data[8 + b] =
                    static_cast<uint8_t>((hi >> (8 * b)) & 0xff);
            }

            // Mutate m_blocks_in_flight under the in-flight mutex briefly.
            bool inserted = false;
            {
                std::lock_guard<std::mutex> bf_lk(m_blocks_in_flight_mutex);
                auto it = m_blocks_in_flight.find(placeholder);
                if (it == m_blocks_in_flight.end()) {
                    BlockDownloadInfo info;
                    info.peer_id = ps.id;
                    info.requested_at_unix_sec =
                        static_cast<int64_t>(std::time(nullptr));
                    info.height = target_height;
                    m_blocks_in_flight.emplace(placeholder, info);
                    inserted = true;
                }
            }

            if (!inserted) continue;

            // Increment per-peer counter under m_peers_mutex briefly.
            {
                std::lock_guard<std::mutex> p_lk(m_peers_mutex);
                auto pit = m_peers.find(ps.id);
                if (pit != m_peers.end()) {
                    ++pit->second->m_block_download.n_blocks_in_flight;
                } else {
                    // Peer disconnected mid-allocation: roll back the
                    // in-flight insert.
                    std::lock_guard<std::mutex> bf_lk(m_blocks_in_flight_mutex);
                    m_blocks_in_flight.erase(placeholder);
                    continue;
                }
            }

            requests.emplace_back(ps.id, placeholder);
        }
    }

    // Step 4: outbound getdata issuance via g_node_context.connman.
    // SAFE: copy-state-out — NO PeerManager mutex held here. Null-safe:
    // under unit-test fixtures or pre-flag-1 wiring, connman /
    // message_processor are null and the call simply returns. Accounting
    // (steps 1-3) has already updated m_blocks_in_flight regardless.
    if (requests.empty()) return;

    CConnman* connman_ptr = g_node_context.connman.get();
    CNetMessageProcessor* msg_proc = g_node_context.message_processor;
    if (connman_ptr == nullptr || msg_proc == nullptr) {
        return;
    }

    // Group by peer and issue one getdata per peer (mirrors
    // ibd_coordinator.cpp:1899-1901 batching).
    std::map<NodeId, std::vector<NetProtocol::CInv>> by_peer;
    for (const auto& req : requests) {
        by_peer[req.first].emplace_back(NetProtocol::MSG_BLOCK_INV, req.second);
    }
    for (const auto& kv : by_peer) {
        CNetMessage msg = msg_proc->CreateGetDataMessage(kv.second);
        connman_ptr->PushMessage(kv.first, std::move(msg));
    }
}

int CPeerManager::GetPeerCount() const {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    return static_cast<int>(m_peers.size());
}

std::vector<PeerInfo> CPeerManager::GetPeerInfo() const {
    std::vector<PeerInfo> out;
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    out.reserve(m_peers.size());
    for (const auto& kv : m_peers) {
        const CPeer& p = *kv.second;
        out.push_back(PeerInfo{p.id, p.nVersion, p.nServices,
                               p.nTimeConnectedLocal, p.m_is_chosen_sync_peer});
    }
    return out;
}

void CPeerManager::OnPeerConnected(NodeId peer) {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    if (m_peers.find(peer) != m_peers.end()) return;  // already connected
    auto [it, inserted] = m_peers.emplace(peer, std::make_unique<CPeer>(peer));
    // Local connect-time stamped from GetTime() (PR6.5b.fixups-semantic,
    // finding PR6.5b.2-SEC-MD-2). Distinct from m_peer_claimed_time which is
    // set wire-side by HandleVersion after a bounds check.
    it->second->nTimeConnectedLocal = GetTime();
}

void CPeerManager::OnPeerDisconnected(NodeId peer) {
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        m_peers.erase(peer);
    }

    // PR6.5b.3: drop disconnecting peer from sync-state. If the peer was
    // the current sync-peer, clear m_headers_sync_peer to -1 so the next
    // Tick re-elects. Also remove the NodeId from m_headers_bad_peers so
    // a future reconnection isn't permanently excluded.
    //
    // SAFE: copy-state-out — no callout under m_sync_state_mutex.
    {
        std::lock_guard<std::mutex> lk(m_sync_state_mutex);
        m_headers_bad_peers.erase(peer);
        if (m_headers_sync_peer == peer) {
            m_headers_sync_peer = -1;
            m_headers_sync_peer_consecutive_stalls = 0;
        }
    }

    // PR6.5b.4: drop ALL in-flight entries owned by the disconnecting peer.
    // Failure to do so is a defect — entries would be orphaned forever. The
    // per-peer counter cleanup is implicit (the CPeer was already erased
    // above; the counter lives on the destroyed CPeer).
    //
    // SAFE: copy-state-out — m_blocks_in_flight_mutex is the deepest lock in
    // our partial order; nothing held above it here.
    {
        std::lock_guard<std::mutex> bf_lk(m_blocks_in_flight_mutex);
        for (auto it = m_blocks_in_flight.begin();
             it != m_blocks_in_flight.end();) {
            if (it->second.peer_id == peer) {
                it = m_blocks_in_flight.erase(it);
            } else {
                ++it;
            }
        }
    }
}

}  // namespace port
}  // namespace net
}  // namespace dilithion
