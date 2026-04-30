// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.0 — adapter exposing IConnectionManager surface over CConnman.
//
// Strategy locked per subagent V5 grep (`port_phase_6_5b_decomposition.md`
// post-D wiring-gap amendment 2026-04-27 PM): 7 of 8 IConnectionManager
// virtuals diverge from CConnman's public surface (return types, parameter
// types, missing methods, OutboundClass enum-scope mismatch). Option (a)
// "retrofit CConnman to inherit IConnectionManager" was not viable; option (b)
// adapter is the locked approach.
//
// Scope: PR6.5b.0 ships a CONSTRUCTION-READY adapter — methods that derive
// trivially from CConnman::GetNodes() are real (count walks, ConnectionInfo
// conversion); methods that require config/banman exposure (GetOutboundTarget,
// IsBanned) return safe defaults with a TODO marker for PR6.5b.5/6 to wire
// properly when port-CPeerManager actually calls them. This is acceptable
// because under flag=0 the adapter is never constructed; under flag=1 the
// PR6.5b.1a stub bodies don't invoke these methods. Real callers land in
// downstream sub-PRs.
//
// Lifetime: holds a non-owning CConnman& reference. CConnman MUST outlive
// this adapter. Standard ownership: adapter is owned by NodeContext; CConnman
// is owned by NodeContext; NodeContext destructor + std::unique_ptr ordering
// handles teardown.

#ifndef DILITHION_NET_PORT_CONNMAN_ADAPTER_H
#define DILITHION_NET_PORT_CONNMAN_ADAPTER_H

#include <net/iconnection_manager.h>

#include <string>
#include <vector>

class CConnman;

namespace dilithion::net::port {

class CConnmanAdapter final : public ::dilithion::net::IConnectionManager {
public:
    explicit CConnmanAdapter(CConnman& connman);
    ~CConnmanAdapter() override = default;

    CConnmanAdapter(const CConnmanAdapter&) = delete;
    CConnmanAdapter& operator=(const CConnmanAdapter&) = delete;

    // ---- IConnectionManager interface ----

    void DisconnectNode(::dilithion::net::NodeId peer,
                        const std::string& reason) override;

    ::dilithion::net::NodeId
    ConnectNode(const std::string& addr,
                ::dilithion::net::OutboundClass cls) override;

    std::vector<::dilithion::net::ConnectionInfo>
    GetConnections() const override;

    int  GetOutboundTarget(::dilithion::net::OutboundClass cls) const override;
    bool IsBanned(const std::string& addr) const override;

    int  GetConnectionCount(::dilithion::net::OutboundClass cls) const override;
    int  GetTotalInbound() const override;
    int  GetTotalOutbound() const override;

    // Phase 6 sub-stream (c) — forwards to CConnman::PushMessage(int, const
    // CNetMessage&). See ratification §3.
    bool PushMessage(::dilithion::net::NodeId peer,
                     const ::CNetMessage& msg) override;

private:
    CConnman& m_connman;
};

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_CONNMAN_ADAPTER_H
