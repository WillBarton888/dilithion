// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Adapter: wraps the existing CAddrMan (legacy) so that callers see only the
// IAddressManager interface. Used when DILITHION_USE_ADDRMAN_V2=0 (operator
// rollback escape hatch) — production default is CAddrMan_v2.
//
// Header-only by design: the adapter is pure type-translation logic, no
// state of its own beyond the wrapped CAddrMan instance + persistence path.
//
// Algorithm fidelity: this adapter does NOT change behavior; it just maps
// IAddressManager method calls onto the existing legacy methods. Operators
// who set DILITHION_USE_ADDRMAN_V2=0 get the exact same address-management
// behavior they had pre-Phase 1.

#ifndef DILITHION_NET_PORT_LEGACY_ADDRMAN_ADAPTER_H
#define DILITHION_NET_PORT_LEGACY_ADDRMAN_ADAPTER_H

#include <net/iaddress_manager.h>
#include <net/addrman.h>            // legacy CAddrMan / CAddrInfo / CNetworkAddr
#include <net/netaddress.h>         // CNetAddr / CService
#include <net/protocol.h>           // NetProtocol::CAddress
#include <net/netaddress_dilithion.h>  // ToService / ToNetAddr / FromService

#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace dilithion::net::port {

class LegacyAddrManAdapter : public ::dilithion::net::IAddressManager {
public:
    LegacyAddrManAdapter()
        : m_legacy(std::make_unique<CAddrMan>()) {}

    // ---- IAddressManager interface ----

    bool Add(const NetProtocol::CAddress& addr,
             const NetProtocol::CAddress& source) override
    {
        // Convert NetProtocol::CAddress -> CNetworkAddr (legacy's address
        // type, which extends CService with services + nTime).
        CService svc = ::dilithion::net::ToService(addr);
        CNetworkAddr na(svc, addr.services, static_cast<int64_t>(addr.time));
        return m_legacy->Add(na, ::dilithion::net::ToNetAddr(source));
    }

    void RecordAttempt(const NetProtocol::CAddress& addr,
                       ::dilithion::net::ConnectionOutcome outcome) override
    {
        const CService svc = ::dilithion::net::ToService(addr);
        switch (outcome) {
            case ::dilithion::net::ConnectionOutcome::Success:
                m_legacy->Good(svc);
                break;
            case ::dilithion::net::ConnectionOutcome::HandshakeFailed:
            case ::dilithion::net::ConnectionOutcome::Timeout:
            case ::dilithion::net::ConnectionOutcome::PeerMisbehaved:
                m_legacy->Attempt(svc, /*fCountFailure=*/true);
                break;
            case ::dilithion::net::ConnectionOutcome::LocalDisconnect:
                m_legacy->Attempt(svc, /*fCountFailure=*/false);
                break;
        }
    }

    std::optional<NetProtocol::CAddress>
    Select(::dilithion::net::OutboundClass cls) override
    {
        const bool new_only = (cls == ::dilithion::net::OutboundClass::Feeler);
        auto picked = m_legacy->Select(new_only);
        const CNetworkAddr& na = picked.first;

        // Legacy Select returns a default-constructed CNetworkAddr (port 0,
        // null bytes) when nothing is selectable. Detect that.
        if (!na.IsValid()) {
            return std::nullopt;
        }
        return CNetworkAddrToCAddress(na);
    }

    std::vector<NetProtocol::CAddress>
    GetAddresses(size_t max_count, size_t max_pct,
                 std::optional<int> /*network_filter*/) override
    {
        // Legacy GetAddr ignores network filter; KISS — Phase 1 doesn't
        // need that yet. (Phase 6 may revisit when ADDR-by-network gossip
        // becomes a thing.)
        auto legacy_out = m_legacy->GetAddr(max_count, max_pct);
        std::vector<NetProtocol::CAddress> out;
        out.reserve(legacy_out.size());
        for (const auto& na : legacy_out) {
            out.push_back(CNetworkAddrToCAddress(na));
        }
        return out;
    }

    bool Save() override
    {
        if (m_data_path.empty()) return true;
        return m_legacy->SaveToFile(m_data_path);
    }

    bool Load() override
    {
        if (m_data_path.empty()) return true;
        return m_legacy->LoadFromFile(m_data_path);
    }

    size_t Size() const override { return m_legacy->Size(); }

    void SetDataPath(const std::string& path) override { m_data_path = path; }

private:
    static NetProtocol::CAddress
    CNetworkAddrToCAddress(const CNetworkAddr& na)
    {
        NetProtocol::CAddress out;
        std::memcpy(out.ip, na.GetAddrBytes(), 16);
        out.port = na.GetPort();
        out.services = na.nServices;
        out.time = static_cast<uint32_t>(na.nTime);
        return out;
    }

    std::unique_ptr<CAddrMan> m_legacy;
    std::string m_data_path;
};

}  // namespace dilithion::net::port

#endif  // DILITHION_NET_PORT_LEGACY_ADDRMAN_ADAPTER_H
