// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Address-type adapter shim for the Bitcoin Core peer/IBD/chain-selection port.
// Bridges Dilithion's interface address type (NetProtocol::CAddress) and the
// internal types used for AddrMan-style operations (CService, CNetAddr).
//
// Header-only by design — small, inline, no link cost. Every conversion is a
// straightforward struct copy; no allocation, no failure modes worth modeling.
//
// Used by: src/net/port/addrman_v2.{h,cpp}, src/net/port/addrman_migrator.cpp.

#ifndef DILITHION_NET_NETADDRESS_DILITHION_H
#define DILITHION_NET_NETADDRESS_DILITHION_H

#include <net/netaddress.h>   // CNetAddr, CService, Network
#include <net/protocol.h>     // NetProtocol::CAddress
#include <cstdint>
#include <cstring>

namespace dilithion::net {

// ============================================================================
// NetProtocol::CAddress  →  CService
// ============================================================================
//
// CService is the internal type AddrMan uses for indexing (it's CNetAddr +
// port, with `GetGroup()`, `IsRoutable()`, etc. predicates inherited from
// CNetAddr). NetProtocol::CAddress carries the wire-format extra (services,
// time) which AddrMan tracks separately as AddrInfo fields.
inline CService ToService(const NetProtocol::CAddress& addr)
{
    // Detect IPv4-mapped (Bitcoin convention: ::ffff:0:0/96) vs native IPv6.
    // Mirrors NetProtocol::CAddress::IsIPv4() at protocol.h:190-192.
    static const uint8_t kV4MappedPrefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };
    Network net = (std::memcmp(addr.ip, kV4MappedPrefix, 12) == 0)
                      ? NET_IPV4
                      : NET_IPV6;
    return CService(addr.ip, addr.port, net);
}

// ============================================================================
// CService  →  NetProtocol::CAddress
// ============================================================================
//
// Reverse direction: pack the internal type back into the wire-format struct
// that callers above the AddrMan layer (peers.cpp, peer_discovery.cpp) work
// with. `services` and `time` come from caller (AddrMan tracks them as
// per-address state, not per-CService).
inline NetProtocol::CAddress FromService(const CService& svc,
                                         uint64_t services,
                                         uint32_t time_secs)
{
    NetProtocol::CAddress out;
    out.time = time_secs;
    out.services = services;
    out.port = svc.GetPort();
    // CService inherits from CNetAddr; copy raw bytes.
    // CNetAddr stores IPv6 form (IPv4 is v4-mapped at index 12-15).
    // NetProtocol::CAddress uses the same convention (protocol.h:174-184).
    std::memcpy(out.ip, svc.GetAddrBytes(), 16);
    return out;
}

// ============================================================================
// NetProtocol::CAddress  →  CNetAddr
// ============================================================================
//
// Drops the port. Used when AddrMan needs the network/group identity only
// (e.g., when learning a peer's source address from an ADDR message — only
// the IP matters for source-grouping, not the port the source happened to
// be using).
inline CNetAddr ToNetAddr(const NetProtocol::CAddress& addr)
{
    static const uint8_t kV4MappedPrefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };
    Network net = (std::memcmp(addr.ip, kV4MappedPrefix, 12) == 0)
                      ? NET_IPV4
                      : NET_IPV6;
    return CNetAddr(addr.ip, net);
}

}  // namespace dilithion::net

#endif  // DILITHION_NET_NETADDRESS_DILITHION_H
