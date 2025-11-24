// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/protocol.h>
#include <util/strencodings.h>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace NetProtocol {

/** Global network magic (defaults to mainnet) */
uint32_t g_network_magic = MAINNET_MAGIC;

std::string CInv::ToString() const {
    const char* type_str = "unknown";
    switch (type) {
        case MSG_TX_INV: type_str = "TX"; break;
        case MSG_BLOCK_INV: type_str = "BLOCK"; break;
        case MSG_FILTERED_BLOCK: type_str = "FILTERED_BLOCK"; break;
        case MSG_CMPCT_BLOCK: type_str = "CMPCT_BLOCK"; break;
    }
    return strprintf("CInv(%s %s)", type_str, hash.GetHex().c_str());
}

std::string CAddress::ToStringIP() const {
    // Check if IPv4-mapped IPv6
    if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0) {
        // IPv4
        return strprintf("%d.%d.%d.%d",
                        ip[12], ip[13], ip[14], ip[15]);
    } else {
        // IPv6 (simplified - just show first few bytes)
        return strprintf("[%02x%02x::%02x%02x]",
                        ip[0], ip[1], ip[14], ip[15]);
    }
}

std::string CAddress::ToString() const {
    return strprintf("%s:%d (services=%016x, time=%u)",
                    ToStringIP().c_str(), port, services, time);
}

// BUG #50 FIX: Accept blockchain height parameter following Bitcoin Core pattern
// This enables proper Initial Block Download (IBD) detection by remote peers
CVersionMessage::CVersionMessage(int32_t blockchain_height)
    : version(PROTOCOL_VERSION),
      services(NODE_NETWORK),
      timestamp(std::time(nullptr)),
      nonce(0),
      user_agent("/Dilithion:0.1.0/"),
      start_height(blockchain_height),  // Use actual blockchain height, not hardcoded 0
      relay(true)
{
}

std::string CVersionMessage::ToString() const {
    return strprintf("CVersionMessage(version=%d, services=%016x, timestamp=%ld, "
                    "user_agent=%s, start_height=%d, relay=%s)",
                    version, services, timestamp,
                    user_agent.c_str(), start_height, relay ? "true" : "false");
}

} // namespace NetProtocol
