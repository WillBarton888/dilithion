// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 interface contract. Connection management surface that PeerManager
// (Phase 6) needs from CConnman. Decouples high-level peer logic from
// socket-level details.

#ifndef DILITHION_NET_ICONNECTION_MANAGER_H
#define DILITHION_NET_ICONNECTION_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include <net/iaddress_manager.h>  // OutboundClass enum

namespace dilithion::net {

using NodeId = int;

// Snapshot of a connection for PeerManager queries. Bigger than NodeId
// because PeerManager needs to know connection class, manual flag, etc.
struct ConnectionInfo {
    NodeId node_id;
    bool is_outbound;
    bool is_manual;                    // --connect / --addnode
    OutboundClass outbound_class;     // FullRelay, BlockRelay, Manual, Feeler
    std::string remote_addr_string;   // For logging only
};

class IConnectionManager {
public:
    virtual ~IConnectionManager() = default;

    // Disconnect a peer. Reason string is for logging only.
    virtual void DisconnectNode(NodeId peer, const std::string& reason) = 0;

    // Initiate outbound connection to address. Returns NodeId on success,
    // -1 on failure. PeerManager calls this when it wants to fill an
    // outbound slot via AddrMan-selected target.
    virtual NodeId ConnectNode(const std::string& addr,
                               OutboundClass cls) = 0;

    // Snapshot of all current connections. Used by PeerManager for
    // periodic reconciliation (target counts, eviction, etc.).
    virtual std::vector<ConnectionInfo> GetConnections() const = 0;

    // Configured target count for an outbound class. Phase 4 / Phase 6
    // queries this to know how many slots to fill.
    virtual int GetOutboundTarget(OutboundClass cls) const = 0;

    // Check if address is banned. PeerManager queries before connect.
    virtual bool IsBanned(const std::string& addr) const = 0;

    // Currently connected count by class — for reconciliation.
    virtual int GetConnectionCount(OutboundClass cls) const = 0;
    virtual int GetTotalInbound() const = 0;
    virtual int GetTotalOutbound() const = 0;
};

}  // namespace dilithion::net

#endif  // DILITHION_NET_ICONNECTION_MANAGER_H
