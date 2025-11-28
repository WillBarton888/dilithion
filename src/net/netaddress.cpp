// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/netaddress.h>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <iomanip>

// IPv4-mapped IPv6 prefix: ::ffff:0:0/96
static const uint8_t IPV4_IN_IPV6_PREFIX[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

//-----------------------------------------------------------------------------
// CNetAddr implementation
//-----------------------------------------------------------------------------

CNetAddr::CNetAddr() : m_net(NET_IPV6), m_scope_id(0) {
    memset(m_addr, 0, sizeof(m_addr));
}

CNetAddr::CNetAddr(const uint8_t ipv6[16], Network net) : m_net(net), m_scope_id(0) {
    memcpy(m_addr, ipv6, 16);
    if (net == NET_IPV6) {
        DetectNetwork();
    }
}

CNetAddr CNetAddr::FromIPv4(uint32_t ipv4) {
    CNetAddr addr;
    addr.SetIPv4(ipv4);
    return addr;
}

bool CNetAddr::FromString(const std::string& str, CNetAddr& addr) {
    // Try parsing as IPv4 first (e.g., "192.168.1.1")
    unsigned int a, b, c, d;
    if (sscanf(str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        if (a <= 255 && b <= 255 && c <= 255 && d <= 255) {
            uint32_t ipv4 = (a << 24) | (b << 16) | (c << 8) | d;
            addr = CNetAddr::FromIPv4(ipv4);
            return true;
        }
    }

    // Try parsing as IPv6 (simplified - just handles full form)
    // For production, would need full IPv6 parsing including compressed forms
    // This is a simplified implementation
    return false;
}

void CNetAddr::SetIPv4(uint32_t ipv4) {
    memset(m_addr, 0, 10);
    m_addr[10] = 0xff;
    m_addr[11] = 0xff;
    m_addr[12] = (ipv4 >> 24) & 0xFF;
    m_addr[13] = (ipv4 >> 16) & 0xFF;
    m_addr[14] = (ipv4 >> 8) & 0xFF;
    m_addr[15] = ipv4 & 0xFF;
    m_net = NET_IPV4;
}

void CNetAddr::SetIPv6(const uint8_t ipv6[16]) {
    memcpy(m_addr, ipv6, 16);
    DetectNetwork();
}

uint32_t CNetAddr::GetIPv4() const {
    if (!IsIPv4()) return 0;
    return (static_cast<uint32_t>(m_addr[12]) << 24) |
           (static_cast<uint32_t>(m_addr[13]) << 16) |
           (static_cast<uint32_t>(m_addr[14]) << 8) |
           static_cast<uint32_t>(m_addr[15]);
}

void CNetAddr::DetectNetwork() {
    // Check for IPv4-mapped address (::ffff:0:0/96)
    if (memcmp(m_addr, IPV4_IN_IPV6_PREFIX, 12) == 0) {
        m_net = NET_IPV4;
        return;
    }

    // Check for all-zeros (unroutable)
    static const uint8_t ZERO_ADDR[16] = {0};
    if (memcmp(m_addr, ZERO_ADDR, 16) == 0) {
        m_net = NET_UNROUTABLE;
        return;
    }

    // Check for loopback (::1)
    static const uint8_t LOOPBACK[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(m_addr, LOOPBACK, 16) == 0) {
        m_net = NET_UNROUTABLE;
        return;
    }

    // Default to IPv6
    m_net = NET_IPV6;
}

bool CNetAddr::IsValid() const {
    // All-zeros is invalid
    static const uint8_t ZERO_ADDR[16] = {0};
    if (memcmp(m_addr, ZERO_ADDR, 16) == 0) return false;

    // Loopback is valid but not for external connections
    return m_net != NET_UNROUTABLE;
}

bool CNetAddr::IsLocal() const {
    if (IsIPv4()) {
        // 127.0.0.0/8
        return m_addr[12] == 127;
    }
    // IPv6 loopback ::1
    static const uint8_t LOOPBACK[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return memcmp(m_addr, LOOPBACK, 16) == 0;
}

bool CNetAddr::IsRFC1918() const {
    if (!IsIPv4()) return false;
    // 10.0.0.0/8
    if (m_addr[12] == 10) return true;
    // 172.16.0.0/12
    if (m_addr[12] == 172 && (m_addr[13] >= 16 && m_addr[13] <= 31)) return true;
    // 192.168.0.0/16
    if (m_addr[12] == 192 && m_addr[13] == 168) return true;
    return false;
}

bool CNetAddr::IsRFC2544() const {
    // 198.18.0.0/15 - benchmark testing
    if (!IsIPv4()) return false;
    return m_addr[12] == 198 && (m_addr[13] == 18 || m_addr[13] == 19);
}

bool CNetAddr::IsRFC3927() const {
    // 169.254.0.0/16 - link-local
    if (!IsIPv4()) return false;
    return m_addr[12] == 169 && m_addr[13] == 254;
}

bool CNetAddr::IsRFC6598() const {
    // 100.64.0.0/10 - CGN (carrier-grade NAT)
    if (!IsIPv4()) return false;
    return m_addr[12] == 100 && (m_addr[13] >= 64 && m_addr[13] <= 127);
}

bool CNetAddr::IsRFC5737() const {
    // Documentation addresses
    if (!IsIPv4()) return false;
    // 192.0.2.0/24 (TEST-NET-1)
    if (m_addr[12] == 192 && m_addr[13] == 0 && m_addr[14] == 2) return true;
    // 198.51.100.0/24 (TEST-NET-2)
    if (m_addr[12] == 198 && m_addr[13] == 51 && m_addr[14] == 100) return true;
    // 203.0.113.0/24 (TEST-NET-3)
    if (m_addr[12] == 203 && m_addr[13] == 0 && m_addr[14] == 113) return true;
    return false;
}

bool CNetAddr::IsRFC3849() const {
    // 2001:db8::/32 - IPv6 documentation
    if (IsIPv4()) return false;
    return m_addr[0] == 0x20 && m_addr[1] == 0x01 &&
           m_addr[2] == 0x0d && m_addr[3] == 0xb8;
}

bool CNetAddr::IsRFC4862() const {
    // fe80::/10 - IPv6 link-local
    if (IsIPv4()) return false;
    return m_addr[0] == 0xfe && (m_addr[1] & 0xc0) == 0x80;
}

bool CNetAddr::IsRFC4193() const {
    // fc00::/7 - IPv6 unique local
    if (IsIPv4()) return false;
    return (m_addr[0] & 0xfe) == 0xfc;
}

bool CNetAddr::IsRFC4843() const {
    // 2001:10::/28 - ORCHID
    if (IsIPv4()) return false;
    return m_addr[0] == 0x20 && m_addr[1] == 0x01 &&
           m_addr[2] == 0x00 && (m_addr[3] & 0xf0) == 0x10;
}

bool CNetAddr::IsRFC7343() const {
    // 2001:20::/28 - ORCHIDv2
    if (IsIPv4()) return false;
    return m_addr[0] == 0x20 && m_addr[1] == 0x01 &&
           m_addr[2] == 0x00 && (m_addr[3] & 0xf0) == 0x20;
}

bool CNetAddr::IsRoutable() const {
    if (!IsValid()) return false;
    if (IsLocal()) return false;
    if (IsRFC1918()) return false;
    if (IsRFC2544()) return false;
    if (IsRFC3927()) return false;
    if (IsRFC6598()) return false;
    if (IsRFC5737()) return false;
    if (IsRFC3849()) return false;
    if (IsRFC4862()) return false;
    if (IsRFC4193()) return false;
    if (IsRFC4843()) return false;
    if (IsRFC7343()) return false;

    // IPv4 multicast (224.0.0.0/4)
    if (IsIPv4() && m_addr[12] >= 224) return false;

    // IPv4 broadcast
    if (IsIPv4() && m_addr[12] == 255 && m_addr[13] == 255 &&
        m_addr[14] == 255 && m_addr[15] == 255) return false;

    return true;
}

std::vector<uint8_t> CNetAddr::GetGroup() const {
    std::vector<uint8_t> result;

    if (IsIPv4()) {
        // For IPv4: return /16 prefix (first 2 bytes after removing mapping)
        result.push_back(NET_IPV4);
        result.push_back(m_addr[12]);
        result.push_back(m_addr[13]);
    } else if (IsIPv6()) {
        // For IPv6: return /32 prefix (first 4 bytes)
        result.push_back(NET_IPV6);
        result.push_back(m_addr[0]);
        result.push_back(m_addr[1]);
        result.push_back(m_addr[2]);
        result.push_back(m_addr[3]);
    } else {
        // Other network types get unique groups
        result.push_back(m_net);
        // Include full address for uniqueness
        for (int i = 0; i < 16; i++) {
            result.push_back(m_addr[i]);
        }
    }

    return result;
}

std::string CNetAddr::ToString() const {
    return ToStringIP();
}

std::string CNetAddr::ToStringIP() const {
    if (IsIPv4()) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                 m_addr[12], m_addr[13], m_addr[14], m_addr[15]);
        return buf;
    }

    // IPv6 format
    std::ostringstream ss;
    ss << std::hex;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << std::setfill('0') << static_cast<int>(m_addr[i])
           << std::setw(2) << std::setfill('0') << static_cast<int>(m_addr[i+1]);
    }
    return ss.str();
}

bool CNetAddr::operator==(const CNetAddr& other) const {
    return m_net == other.m_net && memcmp(m_addr, other.m_addr, 16) == 0;
}

bool CNetAddr::operator<(const CNetAddr& other) const {
    if (m_net != other.m_net) return m_net < other.m_net;
    return memcmp(m_addr, other.m_addr, 16) < 0;
}

//-----------------------------------------------------------------------------
// CService implementation
//-----------------------------------------------------------------------------

CService::CService() : CNetAddr(), m_port(0) {}

CService::CService(const CNetAddr& addr, uint16_t port)
    : CNetAddr(addr), m_port(port) {}

CService::CService(const uint8_t ipv6[16], uint16_t port, Network net)
    : CNetAddr(ipv6, net), m_port(port) {}

CService CService::FromIPv4(uint32_t ipv4, uint16_t port) {
    CService addr;
    addr.SetIPv4(ipv4);
    addr.m_port = port;
    return addr;
}

bool CService::FromString(const std::string& str, CService& addr) {
    // Find the last colon (port separator)
    size_t colonPos = str.rfind(':');
    if (colonPos == std::string::npos) {
        return false;
    }

    std::string ipPart = str.substr(0, colonPos);
    std::string portPart = str.substr(colonPos + 1);

    // Parse port
    int port = atoi(portPart.c_str());
    if (port <= 0 || port > 65535) {
        return false;
    }

    // Parse IP
    CNetAddr netAddr;
    if (!CNetAddr::FromString(ipPart, netAddr)) {
        return false;
    }

    addr = CService(netAddr, static_cast<uint16_t>(port));
    return true;
}

std::string CService::ToString() const {
    if (IsIPv4()) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%s:%u", ToStringIP().c_str(), m_port);
        return buf;
    }

    // IPv6 addresses need brackets
    std::ostringstream ss;
    ss << "[" << ToStringIP() << "]:" << m_port;
    return ss.str();
}

std::string CService::ToStringKey() const {
    // Simple format for use as map key
    std::ostringstream ss;
    ss << ToStringIP() << ":" << m_port;
    return ss.str();
}

bool CService::operator==(const CService& other) const {
    return CNetAddr::operator==(other) && m_port == other.m_port;
}

bool CService::operator<(const CService& other) const {
    if (CNetAddr::operator<(other)) return true;
    if (other.CNetAddr::operator<(*this)) return false;
    return m_port < other.m_port;
}
