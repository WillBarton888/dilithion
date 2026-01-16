// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// UPnP port mapping support using miniupnpc
// Enables automatic port forwarding on NAT routers

#ifndef DILITHION_NET_UPNP_H
#define DILITHION_NET_UPNP_H

#include <string>
#include <cstdint>

namespace UPnP {

/**
 * Attempt to map external port to local port via UPnP
 * @param port The port to map (both internal and external)
 * @param externalIP Output: the external IP address discovered via UPnP
 * @return true if successful, false otherwise
 */
bool MapPort(uint16_t port, std::string& externalIP);

/**
 * Remove port mapping
 * @param port The port to unmap
 */
void UnmapPort(uint16_t port);

/**
 * Check if UPnP is available on the network
 * @return true if a UPnP-capable gateway was found
 */
bool IsAvailable();

/**
 * Get the last error message
 * @return Error string describing the last failure
 */
std::string GetLastError();

} // namespace UPnP

#endif // DILITHION_NET_UPNP_H
