// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// Socket utilities for event-driven networking
// Cross-platform wrappers for select/poll operations
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#ifndef DILITHION_NET_SOCK_H
#define DILITHION_NET_SOCK_H

#include <chrono>
#include <set>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
using socket_t = SOCKET;
#else
using socket_t = int;
#endif

/**
 * Socket event types for Sock::Wait()
 */
enum class SocketEvent {
    RECV = 1,   // Ready to receive
    SEND = 2,   // Ready to send
    ERR = 4     // Error condition
};

/**
 * CSock - Low-level socket utilities
 *
 * Provides cross-platform socket operations for event-driven I/O:
 * - select()/poll() wrappers with proper timeout handling
 * - Non-blocking socket configuration
 * - Error handling for all platforms
 */
class CSock {
public:
    //
    // Socket configuration
    //

    /**
     * Set socket to non-blocking mode
     * @param sock Socket handle
     * @return true on success
     */
    static bool SetNonBlocking(socket_t sock);

    /**
     * Set socket receive timeout
     * @param sock Socket handle
     * @param timeout Timeout duration
     * @return true on success
     */
    static bool SetRecvTimeout(socket_t sock, std::chrono::milliseconds timeout);

    /**
     * Set socket send timeout
     * @param sock Socket handle
     * @param timeout Timeout duration
     * @return true on success
     */
    static bool SetSendTimeout(socket_t sock, std::chrono::milliseconds timeout);

    /**
     * Set TCP_NODELAY (disable Nagle's algorithm)
     * @param sock Socket handle
     * @param enable Enable or disable
     * @return true on success
     */
    static bool SetNoDelay(socket_t sock, bool enable = true);

    /**
     * Set SO_REUSEADDR
     * @param sock Socket handle
     * @param enable Enable or disable
     * @return true on success
     */
    static bool SetReuseAddr(socket_t sock, bool enable = true);

    //
    // Socket state
    //

    /**
     * Check if socket is valid
     */
    static bool IsValid(socket_t sock);

    /**
     * Close socket
     * @param sock Socket handle
     */
    static void Close(socket_t& sock);

    //
    // Event waiting
    //

    /**
     * Wait for socket events using select()
     * @param sock Socket to wait on
     * @param events Events to wait for (SocketEvent flags)
     * @param timeout Timeout duration
     * @return Events that occurred (0 on timeout, -1 on error)
     */
    static int Wait(socket_t sock, int events, std::chrono::milliseconds timeout);

    /**
     * Wait for events on multiple sockets using select()
     * @param recv_set Sockets to check for read readiness (modified to ready set)
     * @param send_set Sockets to check for write readiness (modified to ready set)
     * @param error_set Sockets to check for errors (modified to ready set)
     * @param timeout Timeout duration
     * @return Number of ready sockets, 0 on timeout, -1 on error
     */
    static int WaitMany(std::set<socket_t>& recv_set, std::set<socket_t>& send_set,
                        std::set<socket_t>& error_set, std::chrono::milliseconds timeout);

    //
    // Error handling
    //

    /**
     * Get last socket error code
     * @return Platform-specific error code
     */
    static int GetLastError();

    /**
     * Get human-readable error message
     * @param error Error code (or 0 for last error)
     * @return Error message string
     */
    static std::string GetErrorString(int error = 0);

    /**
     * Check if error is "would block" (EAGAIN/EWOULDBLOCK)
     * @param error Error code (or 0 for last error)
     * @return true if this is a non-fatal blocking condition
     */
    static bool IsWouldBlock(int error = 0);

    /**
     * Check if error is connection refused
     * @param error Error code (or 0 for last error)
     * @return true if connection was refused
     */
    static bool IsConnectionRefused(int error = 0);

    //
    // Constants
    //

    static constexpr socket_t INVALID_SOCKET_VALUE =
#ifdef _WIN32
        INVALID_SOCKET;
#else
        -1;
#endif
};

#endif // DILITHION_NET_SOCK_H
