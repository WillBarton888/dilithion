// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 1 interface contract for the Bitcoin Core peer/IBD/chain-selection port.
// Architecture document: .claude/contracts/bitcoin_core_port_architecture.md
// Code mapping: .claude/contracts/port_phase_0_code_mapping.md
//
// IAddressManager is the abstraction over Bitcoin Core's AddrMan (address
// manager). Phase 1 produces the concrete implementation in src/net/addrman.h
// (replacing the existing stub). PeerManager (Phase 6) and ConnMan (Phase 4)
// consume this interface, never the concrete class — keeps phases independently
// mergeable.

#ifndef DILITHION_NET_IADDRESS_MANAGER_H
#define DILITHION_NET_IADDRESS_MANAGER_H

#include <cstdint>
#include <vector>
#include <optional>

// Forward declaration — concrete CAddress lives in net/protocol.h.
namespace NetProtocol { class CAddress; }

namespace dilithion::net {

// Outcome of a peer's most recent connection attempt — feeds the AddrMan
// quality model (terrible-peer eviction, retry backoff).
enum class ConnectionOutcome {
    Success,                 // Successful handshake AND useful data exchange
    HandshakeFailed,         // TCP connected but handshake didn't complete
    Timeout,                 // No response within reasonable time
    PeerMisbehaved,          // Banned for protocol violation
    LocalDisconnect,         // We disconnected (eviction, shutdown, etc.)
};

// Connection class for outbound peers — Bitcoin Core's net/connection_types.h
// equivalent. Phase 4 consumes this when selecting outbound targets.
enum class OutboundClass {
    FullRelay,        // Default outbound, exchanges blocks + tx + addrs
    BlockRelay,       // Blocks only (no tx, no addr — anti-eclipse)
    Manual,           // --connect / --addnode persistent
    Feeler,           // Brief connect to refresh AddrMan freshness
};

class IAddressManager {
public:
    virtual ~IAddressManager() = default;

    // Add a peer address learned from any source (DNS seed, peer ADDR message,
    // command-line --addnode). Source affects bucketing/quality.
    virtual bool Add(const NetProtocol::CAddress& addr,
                     const NetProtocol::CAddress& source) = 0;

    // Mark a peer as having a connection attempted/completed/failed.
    // Updates AddrMan's quality model.
    virtual void RecordAttempt(const NetProtocol::CAddress& addr,
                               ConnectionOutcome outcome) = 0;

    // Select an address to attempt outbound connection to, biased by:
    // - Quality (success rate, freshness)
    // - Group diversity (no two outbound peers in same /16 + /32 group)
    // - Connection class requirements (FullRelay vs BlockRelay vs Feeler)
    // Returns nullopt if no suitable address available.
    virtual std::optional<NetProtocol::CAddress> Select(OutboundClass cls) = 0;

    // Select N addresses for ADDR-message gossip to a peer (Bitcoin Core's
    // GetAddr) — picks random subset of "good" addresses, biased by group.
    virtual std::vector<NetProtocol::CAddress> GetAddresses(
        size_t max_count,
        size_t max_pct,        // Limit to N% of total (anti-fingerprint)
        std::optional<int> network_filter) = 0;

    // Persist current state to peers.dat. Called periodically + at shutdown.
    virtual bool Save() = 0;

    // Load state from peers.dat. Called at startup. Returns false if file
    // missing / corrupt; caller should initialize empty in that case.
    virtual bool Load() = 0;

    // Diagnostics — number of addresses tracked.
    virtual size_t Size() const = 0;

    // ============================================================
    // Dilithion-specific extension (advisory, NOT consensus)
    // ============================================================
    // When a peer announces a MIK identity hash, AddrMan can record it for
    // diagnostics + advisory tie-breaking on outbound selection. Purely
    // optional; Bitcoin Core's AddrMan ignores this entirely.
    virtual void SetPeerMIKHint(const NetProtocol::CAddress& addr,
                                const std::vector<uint8_t>& mik_identity) = 0;
};

}  // namespace dilithion::net

#endif  // DILITHION_NET_IADDRESS_MANAGER_H
