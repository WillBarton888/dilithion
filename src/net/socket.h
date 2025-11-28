// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NET_SOCKET_H
#define DILITHION_NET_SOCKET_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

/**
 * CSocket - Cross-platform socket wrapper for TCP connections
 *
 * Provides a simple interface for network I/O, abstracting platform differences
 * between POSIX sockets (Linux, macOS) and Winsock (Windows).
 */
class CSocket {
public:
    CSocket();
    ~CSocket();

    // Disable copy, enable move
    CSocket(const CSocket&) = delete;
    CSocket& operator=(const CSocket&) = delete;
    CSocket(CSocket&& other) noexcept;
    CSocket& operator=(CSocket&& other) noexcept;

    // Connection
    bool Connect(const std::string& host, uint16_t port, int timeout_ms = 5000);
    bool Bind(uint16_t port);
    bool Listen(int backlog = 10);
    std::unique_ptr<CSocket> Accept();
    void Close();

    // I/O operations
    int Send(const void* data, size_t len);
    int Recv(void* buffer, size_t len);
    int SendAll(const void* data, size_t len);  // Guaranteed to send all or fail
    int RecvAll(void* buffer, size_t len);      // Guaranteed to recv all or fail

    // Socket options
    bool SetNonBlocking(bool non_blocking = true);
    bool SetReuseAddr(bool reuse = true);
    bool SetNoDelay(bool no_delay = true);  // Disable Nagle's algorithm
    bool SetRecvTimeout(int timeout_ms);
    bool SetSendTimeout(int timeout_ms);

    // Status
    bool IsValid() const { return sock_fd >= 0; }
    bool IsConnected() const { return connected; }
    std::string GetPeerAddress() const;
    uint16_t GetPeerPort() const;
    std::string GetLocalAddress() const;
    uint16_t GetLocalPort() const;

    // Error handling
    int GetLastError() const;
    std::string GetLastErrorString() const;

private:
#ifdef _WIN32
    using socket_t = uintptr_t;  // SOCKET on Windows
    static const socket_t INVALID_SOCKET_FD = (socket_t)(~0);
#else
    using socket_t = int;
    static const socket_t INVALID_SOCKET_FD = -1;
#endif

    socket_t sock_fd;
    bool connected;
    std::string peer_address;
    uint16_t peer_port;

    // Platform-specific initialization
    static bool InitializeSocketLayer();
    static void CleanupSocketLayer();
    static bool socket_layer_initialized;

    void Reset();
};

/**
 * Network address resolution helper
 *
 * Note: This is a simple DNS/address resolution struct.
 * For Bitcoin Core-style network addresses (for AddrMan, P2P),
 * use CNetAddr/CService from netaddress.h instead.
 */
struct CResolvedAddr {
    std::string hostname;
    std::string ip;
    uint16_t port;
    bool ipv6;

    CResolvedAddr() : port(0), ipv6(false) {}
    CResolvedAddr(const std::string& host, uint16_t p)
        : hostname(host), port(p), ipv6(false) {}

    std::string ToString() const;
};

/**
 * Socket initialization guard (RAII)
 * Ensures proper cleanup on Windows (WSACleanup)
 */
class CSocketInit {
public:
    CSocketInit();
    ~CSocketInit();
    static bool IsInitialized() { return initialized; }

private:
    static bool initialized;
};

#endif // DILITHION_NET_SOCKET_H
