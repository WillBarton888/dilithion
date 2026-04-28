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
#include <net/ipeer_scorer.h>
#include <net/serialize.h>

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
    // STUB: -1 sentinel = "no peer selected".
    return -1;
}

void CPeerManager::OnOrphanBlockReceived() {
    // STUB: no-op. PR6.5b body will track per-peer orphan counts
    // and dispatch misbehavior penalties via m_scorer.
}

void CPeerManager::OnBlockConnected() {
    // STUB: no-op. PR6.5b body will reset stall counters and update
    // last-block-arrival timestamps in per-peer state.
}

void CPeerManager::Tick() {
    // STUB: no-op. PR6.5b body will run sync-peer rotation, stall
    // detection, in-flight cleanup, and RequestNextBlocks dispatch.
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
    std::lock_guard<std::mutex> lk(m_peers_mutex);
    m_peers.erase(peer);
}

}  // namespace port
}  // namespace net
}  // namespace dilithion
