// Copyright (c) 2014-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Ported from Bitcoin Core v28.0 src/zmq/zmqutil.cpp
// PR-Z-1: ZMQ notifications skeleton.

#include <zmq/zmqutil.h>

#include <util/logging.h>

#include <zmq.h>

#include <cerrno>
#include <string>

namespace zmq_util {

const std::string ADDR_PREFIX_IPC = "ipc://";

void zmqError(const std::string& str)
{
    LogPrintZMQ(WARN, "[zmq] error: %s, msg: %s", str.c_str(), zmq_strerror(errno));
}

// Detect IPv6 TCP addresses so the caller can flip ZMQ_IPV6 on the publisher
// socket. On platforms where ZMQ_IPV6 is OFF by default (notably OpenBSD,
// and any Linux host with sysctl net.ipv6.bindv6only=1) a bare IPv6 endpoint
// will silently fail to bind unless ZMQ_IPV6 is enabled.
//
// HEURISTIC (NOT a port of Bitcoin Core's check): BC uses LookupHost() from
// netaddress, which resolves the host portion and inspects the result. That
// pulls the full net subsystem and is out of scope for the skeleton. Instead
// we strip the tcp:// prefix and the trailing :port (only if all-digits),
// then count the colons remaining in the host portion:
//   * brackets present       -> bracketed IPv6 literal      -> IPv6
//   * 0 colons in host       -> IPv4 dotted-quad / hostname -> IPv4
//   * 1+ colons in host      -> bare IPv6 literal           -> IPv6
//
// This correctly classifies bare IPv6 (e.g. tcp://2001:db8::1:5555 has 3
// colons in the host after stripping the trailing :5555), bracketed IPv6
// (tcp://[::1]:28332), and IPv4 (tcp://127.0.0.1:28332 -> 0 colons after
// stripping). PR-Z-2 can revisit if we ever need true resolver-based parity
// with Bitcoin Core.
bool IsZMQAddressIPV6(const std::string& zmq_address)
{
    const std::string tcp_prefix = "tcp://";
    if (zmq_address.rfind(tcp_prefix, 0) != 0) return false;

    // Bracketed IPv6 literals are the canonical form: tcp://[addr]:port.
    if (zmq_address.find('[') != std::string::npos) return true;

    // Strip the tcp:// prefix to expose host[:port].
    std::string host_port = zmq_address.substr(tcp_prefix.size());

    // Strip the trailing :port if present. We look for the LAST ':' because
    // an IPv6 host can contain many colons; the port (if any) follows the
    // final colon. The trailing :port is treated as a port only if
    // everything after the final ':' is decimal digits. Otherwise the final
    // ':' is part of the address itself and must be counted as host content.
    std::string host = host_port;
    size_t last_colon = host_port.find_last_of(':');
    if (last_colon != std::string::npos) {
        bool all_digits = (last_colon + 1 < host_port.size());
        for (size_t i = last_colon + 1; i < host_port.size() && all_digits; ++i) {
            if (host_port[i] < '0' || host_port[i] > '9') {
                all_digits = false;
            }
        }
        if (all_digits) {
            host = host_port.substr(0, last_colon);
        }
    }

    // Any colons remaining in the host portion mean it is IPv6.
    return host.find(':') != std::string::npos;
}

}  // namespace zmq_util
