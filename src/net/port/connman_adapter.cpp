// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.0 — CConnmanAdapter implementation. See header for design
// rationale (option (b) per subagent V5 grep — option (a) retrofit not viable
// because 7 of 8 IConnectionManager virtuals diverge from CConnman's surface).

#include <net/port/connman_adapter.h>

#include <net/connman.h>
#include <net/node.h>
#include <net/protocol.h>

namespace dilithion::net::port {

namespace {

// Translate CNode::OutboundClass (per-node enum, lives in node.h) to
// dilithion::net::OutboundClass (frozen interface enum, lives in
// iaddress_manager.h). Values are aligned by name per node.h:94-95
// comment "Matches the FROZEN OutboundClass enum"; this function
// makes the type translation explicit at the boundary.
::dilithion::net::OutboundClass TranslateClass(CNode::OutboundClass cls)
{
    switch (cls) {
        case CNode::OutboundClass::FullRelay:
            return ::dilithion::net::OutboundClass::FullRelay;
        case CNode::OutboundClass::BlockRelay:
            return ::dilithion::net::OutboundClass::BlockRelay;
        case CNode::OutboundClass::Manual:
            return ::dilithion::net::OutboundClass::Manual;
        case CNode::OutboundClass::Feeler:
            return ::dilithion::net::OutboundClass::Feeler;
    }
    // Unreachable under any valid enum value; default to FullRelay for safety.
    return ::dilithion::net::OutboundClass::FullRelay;
}

}  // anonymous namespace

CConnmanAdapter::CConnmanAdapter(CConnman& connman)
    : m_connman(connman)
{}

void CConnmanAdapter::DisconnectNode(::dilithion::net::NodeId peer,
                                     const std::string& reason)
{
    // Direct proxy. CConnman::DisconnectNode signature (`int nodeid, const
    // std::string& reason=""`) matches IConnectionManager::DisconnectNode
    // because NodeId IS int.
    m_connman.DisconnectNode(peer, reason);
}

::dilithion::net::NodeId
CConnmanAdapter::ConnectNode(const std::string& /*addr*/,
                             ::dilithion::net::OutboundClass /*cls*/)
{
    // STUB (PR6.5b.0): port-CPeerManager.RequestNextBlocks (PR6.5b.4) and
    // SendMessages (PR6.5b.6) will be the first callers. CConnman::ConnectNode
    // takes NetProtocol::CAddress (not string) — the address-string-to-CAddress
    // translation needs lookup tooling that's out-of-scope for PR6.5b.0's
    // wiring prep. Returns -1 sentinel; PR6.5b.4 will replace with a real
    // implementation including string→CAddress parsing.
    // TODO(PR6.5b.4): replace with real proxy once port-CPeerManager calls it.
    return -1;
}

std::vector<::dilithion::net::ConnectionInfo>
CConnmanAdapter::GetConnections() const
{
    std::vector<::dilithion::net::ConnectionInfo> out;
    auto nodes = m_connman.GetNodes();
    out.reserve(nodes.size());
    for (CNode* node : nodes) {
        if (!node) continue;
        ::dilithion::net::ConnectionInfo info;
        info.node_id = node->id;
        info.is_outbound = !node->fInbound;
        info.is_manual = node->fManual;
        info.outbound_class = TranslateClass(node->m_outbound_class);
        info.remote_addr_string = node->addr.ToString();
        out.push_back(std::move(info));
    }
    return out;
}

int CConnmanAdapter::GetOutboundTarget(::dilithion::net::OutboundClass cls) const
{
    // STUB (PR6.5b.0): real implementation needs CConnmanOptions exposure
    // (CConnman doesn't currently surface its configured outbound targets
    // via a public accessor). Returns conservative defaults that match
    // current Dilithion outbound counts:
    //   FullRelay  = 8  (default outbound full-relay slots)
    //   BlockRelay = 2  (anti-eclipse block-only slots)
    //   Manual     = 0  (sized by --connect / --addnode count)
    //   Feeler     = 1  (brief refresh slot)
    // TODO(PR6.5b.5/6): replace with real proxy once port-CPeerManager
    // calls this for slot reconciliation.
    switch (cls) {
        case ::dilithion::net::OutboundClass::FullRelay:  return 8;
        case ::dilithion::net::OutboundClass::BlockRelay: return 2;
        case ::dilithion::net::OutboundClass::Manual:     return 0;
        case ::dilithion::net::OutboundClass::Feeler:     return 1;
    }
    return 0;
}

bool CConnmanAdapter::IsBanned(const std::string& /*addr*/) const
{
    // STUB (PR6.5b.0): real implementation queries banman. PR6.5b.6's
    // misbehavior dispatch is the first caller; until then, conservative
    // "not banned" stub is safe because the callers (also stubbed) don't
    // act on the result.
    // TODO(PR6.5b.6): wire to banman.
    return false;
}

int CConnmanAdapter::GetConnectionCount(::dilithion::net::OutboundClass cls) const
{
    // Real implementation: walk current nodes and count by class.
    int count = 0;
    auto nodes = m_connman.GetNodes();
    for (CNode* node : nodes) {
        if (!node) continue;
        if (node->fInbound) continue;  // Inbound nodes have no outbound class
        if (TranslateClass(node->m_outbound_class) == cls) {
            ++count;
        }
    }
    return count;
}

int CConnmanAdapter::GetTotalInbound() const
{
    int count = 0;
    auto nodes = m_connman.GetNodes();
    for (CNode* node : nodes) {
        if (!node) continue;
        if (node->fInbound) ++count;
    }
    return count;
}

int CConnmanAdapter::GetTotalOutbound() const
{
    int count = 0;
    auto nodes = m_connman.GetNodes();
    for (CNode* node : nodes) {
        if (!node) continue;
        if (!node->fInbound) ++count;
    }
    return count;
}

}  // namespace dilithion::net::port
