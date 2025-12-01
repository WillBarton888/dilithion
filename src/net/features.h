// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_FEATURES_H
#define DILITHION_NET_FEATURES_H

#include <net/protocol.h>
#include <cstdint>

/**
 * Feature flags system (Bitcoin Core pattern)
 *
 * Provides structured way to check and negotiate protocol features
 * between peers during handshake.
 */

namespace NetFeatures {

/**
 * Check if peer supports a specific service
 *
 * @param services Service flags from version message
 * @param flag Service flag to check
 * @return true if flag is set
 */
inline bool HasService(uint64_t services, NetProtocol::ServiceFlags flag) {
    return (services & static_cast<uint64_t>(flag)) != 0;
}

/**
 * Check if peer supports full block serving (NODE_NETWORK)
 */
inline bool SupportsFullBlocks(uint64_t services) {
    return HasService(services, NetProtocol::NODE_NETWORK);
}

/**
 * Check if peer supports bloom filtering
 */
inline bool SupportsBloomFilter(uint64_t services) {
    return HasService(services, NetProtocol::NODE_BLOOM);
}

/**
 * Check if peer supports witness data
 */
inline bool SupportsWitness(uint64_t services) {
    return HasService(services, NetProtocol::NODE_WITNESS);
}

/**
 * Check if peer is a limited node (pruned history)
 */
inline bool IsLimitedNode(uint64_t services) {
    return HasService(services, NetProtocol::NODE_NETWORK_LIMITED);
}

/**
 * Get our service flags (what we advertise to peers)
 *
 * @return Service flags we support
 */
inline uint64_t GetOurServices() {
    // Always advertise NODE_NETWORK (full block serving)
    return static_cast<uint64_t>(NetProtocol::NODE_NETWORK);
}

} // namespace NetFeatures

#endif // DILITHION_NET_FEATURES_H

