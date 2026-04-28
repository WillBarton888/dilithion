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
#include <core/node_context.h>
#include <net/headers_manager.h>
#include <net/ipeer_scorer.h>
#include <net/serialize.h>

#include <chrono>
#include <ctime>
#include <stdexcept>

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

// ===== ISyncCoordinator overrides =====

bool CPeerManager::IsInitialBlockDownload() const {
    // STUB: safe default = "yes, in IBD" so callers behave conservatively
    // until the body lands.
    return true;
}

bool CPeerManager::IsSynced() const {
    // STUB: safe default = "no, not synced".
    return false;
}

int CPeerManager::GetHeadersSyncPeer() const {
    // PR6.5b.3: return the currently-elected sync-peer NodeId, or -1 if
    // none. CPeerManager is authoritative for "is this peer the chosen
    // sync-peer." (CHeadersManager remains authoritative for "have I
    // started syncing from this peer" — SSOT split per decomposition.)
    std::lock_guard<std::mutex> lk(m_sync_state_mutex);
    return m_headers_sync_peer;
}

void CPeerManager::OnOrphanBlockReceived() {
    // STUB: no-op. PR6.5b body will track per-peer orphan counts
    // and dispatch misbehavior penalties via m_scorer.
}

void CPeerManager::OnBlockConnected() {
    // STUB: no-op. PR6.5b body will reset stall counters and update
    // last-block-arrival timestamps in per-peer state.
}

// PR6.5b.3: Tick body — headers-sync stall detection + peer rotation.
// Mirrors the (CheckHeadersSyncProgress → SwitchHeadersSyncPeer)
// rhythm from CIbdCoordinator::Tick. IsIBD/IsSynced + RequestNextBlocks
// dispatch + outbound message issuance remain stubbed (PR6.5b.4 / 6b.5 / 6b.6).
//
// SAFE: copy-state-out — every helper drops m_peers_mutex /
// m_sync_state_mutex before any callout. No m_connman / outbound
// network primitive is invoked here (PR6.5b.6 owns that path).
void CPeerManager::Tick() {
    NodeId current = -1;
    {
        std::lock_guard<std::mutex> lk(m_sync_state_mutex);
        current = m_headers_sync_peer;
    }

    if (current == -1) {
        // No current sync-peer: try to elect one.
        SelectHeadersSyncPeerLocked();
        return;
    }

    // Have a current sync-peer: check progress; rotate (with penalize=true)
    // on stall.
    const bool progressing = CheckHeadersSyncProgressLocked();
    if (!progressing) {
        SwitchHeadersSyncPeerLocked(/*penalize=*/true);
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
// nVersion / nServices / nTimeConnected on the per-peer CPeer struct,
// closing the deferred-from-PR6.5b.1b populate path. Wire layout matches
// CNetMessageProcessor::SerializeVersionMessage in src/net/net.cpp:2843.
//
// SAFE: copy-state-out — duplicate-version detection mutates state under
// the lock; the m_scorer call is performed AFTER drop with a captured-out
// `is_duplicate` bool.
bool CPeerManager::HandleVersion(NodeId peer, CDataStream& vRecv) {
    // Read minimum required fields from the wire. CDataStream throws on
    // under-length; ProcessMessage's try/catch routes to UnknownMessage.
    const int32_t  read_version  = vRecv.ReadInt32();
    const uint64_t read_services = vRecv.ReadUint64();
    const int64_t  read_timestamp = vRecv.ReadInt64();

    bool is_duplicate = false;
    {
        std::lock_guard<std::mutex> lk(m_peers_mutex);
        auto it = m_peers.find(peer);
        if (it == m_peers.end()) return false;  // disconnected mid-handler
        CPeer& p = *it->second;

        // Upstream pattern: a second version on the same peer is misbehavior
        // (DuplicateVersion weight=1 in MisbehaviorType). Detect by checking
        // nVersion already populated (zero on fresh peer per peer.h:60).
        if (p.nVersion != 0) {
            is_duplicate = true;
        } else {
            p.nVersion = read_version;
            p.nServices = read_services;
            p.nTimeConnected = read_timestamp;
        }
    }

    // SAFE: copy-state-out — m_peers_mutex dropped before scorer callout.
    if (is_duplicate) {
        m_scorer.Misbehaving(peer, ::dilithion::net::MisbehaviorType::DuplicateVersion,
                             "duplicate version message");
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
    if (header_count > 2000) {
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

    const int headers_missing = (best_height > static_cast<int64_t>(seed_last_height))
        ? static_cast<int>(best_height - static_cast<int64_t>(seed_last_height))
        : 0;
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

void CPeerManager::SendMessages(NodeId /*peer*/) {
    // STUB: no-op. Body work in PR6.5b.
}

void CPeerManager::RequestNextBlocks() {
    // STUB: no-op. Body work in PR6.5b.
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
                               p.nTimeConnected, p.m_is_chosen_sync_peer});
    }
    return out;
}

void CPeerManager::OnPeerConnected(NodeId peer) {
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    if (m_peers.find(peer) != m_peers.end()) return;  // already connected
    m_peers.emplace(peer, std::make_unique<CPeer>(peer));
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
}

}  // namespace port
}  // namespace net
}  // namespace dilithion
