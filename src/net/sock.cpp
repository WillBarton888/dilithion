// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// Socket utilities implementation
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#include <net/sock.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#endif

#include <algorithm>

bool CSock::SetNonBlocking(socket_t sock) {
    if (!IsValid(sock)) return false;

#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool CSock::SetRecvTimeout(socket_t sock, std::chrono::milliseconds timeout) {
    if (!IsValid(sock)) return false;

#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout.count());
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                      reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#else
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

bool CSock::SetSendTimeout(socket_t sock, std::chrono::milliseconds timeout) {
    if (!IsValid(sock)) return false;

#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout.count());
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                      reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#else
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    return setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

bool CSock::SetNoDelay(socket_t sock, bool enable) {
    if (!IsValid(sock)) return false;

    int flag = enable ? 1 : 0;
    return setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&flag), sizeof(flag)) == 0;
}

bool CSock::SetReuseAddr(socket_t sock, bool enable) {
    if (!IsValid(sock)) return false;

    int flag = enable ? 1 : 0;
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<const char*>(&flag), sizeof(flag)) == 0;
}

bool CSock::IsValid(socket_t sock) {
#ifdef _WIN32
    return sock != INVALID_SOCKET;
#else
    return sock >= 0;
#endif
}

void CSock::Close(socket_t& sock) {
    if (!IsValid(sock)) return;

#ifdef _WIN32
    closesocket(sock);
    sock = INVALID_SOCKET;
#else
    close(sock);
    sock = -1;
#endif
}

int CSock::Wait(socket_t sock, int events, std::chrono::milliseconds timeout) {
    if (!IsValid(sock)) return -1;

    fd_set fd_recv, fd_send, fd_error;
    FD_ZERO(&fd_recv);
    FD_ZERO(&fd_send);
    FD_ZERO(&fd_error);

    if (events & static_cast<int>(SocketEvent::RECV)) {
        FD_SET(sock, &fd_recv);
    }
    if (events & static_cast<int>(SocketEvent::SEND)) {
        FD_SET(sock, &fd_send);
    }
    if (events & static_cast<int>(SocketEvent::ERR)) {
        FD_SET(sock, &fd_error);
    }

    struct timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

#ifdef _WIN32
    int result = select(0, &fd_recv, &fd_send, &fd_error, &tv);
#else
    int result = select(sock + 1, &fd_recv, &fd_send, &fd_error, &tv);
#endif

    if (result <= 0) {
        return result;  // 0 = timeout, -1 = error
    }

    int ready = 0;
    if (FD_ISSET(sock, &fd_recv)) ready |= static_cast<int>(SocketEvent::RECV);
    if (FD_ISSET(sock, &fd_send)) ready |= static_cast<int>(SocketEvent::SEND);
    if (FD_ISSET(sock, &fd_error)) ready |= static_cast<int>(SocketEvent::ERR);

    return ready;
}

int CSock::WaitMany(std::set<socket_t>& recv_set, std::set<socket_t>& send_set,
                    std::set<socket_t>& error_set, std::chrono::milliseconds timeout) {
    if (recv_set.empty() && send_set.empty() && error_set.empty()) {
        return 0;
    }

    fd_set fd_recv, fd_send, fd_error;
    FD_ZERO(&fd_recv);
    FD_ZERO(&fd_send);
    FD_ZERO(&fd_error);

    socket_t max_fd = 0;

    for (socket_t sock : recv_set) {
        FD_SET(sock, &fd_recv);
#ifndef _WIN32
        if (sock > max_fd) max_fd = sock;
#endif
    }
    for (socket_t sock : send_set) {
        FD_SET(sock, &fd_send);
#ifndef _WIN32
        if (sock > max_fd) max_fd = sock;
#endif
    }
    for (socket_t sock : error_set) {
        FD_SET(sock, &fd_error);
#ifndef _WIN32
        if (sock > max_fd) max_fd = sock;
#endif
    }

    struct timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

#ifdef _WIN32
    int result = select(0, &fd_recv, &fd_send, &fd_error, &tv);
#else
    int result = select(max_fd + 1, &fd_recv, &fd_send, &fd_error, &tv);
#endif

    if (result <= 0) {
        recv_set.clear();
        send_set.clear();
        error_set.clear();
        return result;
    }

    // Filter to only ready sockets
    std::set<socket_t> ready_recv, ready_send, ready_error;

    for (socket_t sock : recv_set) {
        if (FD_ISSET(sock, &fd_recv)) ready_recv.insert(sock);
    }
    for (socket_t sock : send_set) {
        if (FD_ISSET(sock, &fd_send)) ready_send.insert(sock);
    }
    for (socket_t sock : error_set) {
        if (FD_ISSET(sock, &fd_error)) ready_error.insert(sock);
    }

    recv_set = std::move(ready_recv);
    send_set = std::move(ready_send);
    error_set = std::move(ready_error);

    return result;
}

int CSock::GetLastError() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string CSock::GetErrorString(int error) {
    if (error == 0) {
        error = GetLastError();
    }

#ifdef _WIN32
    char buf[256] = {0};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, error, 0, buf, sizeof(buf), nullptr);
    return std::string(buf);
#else
    return std::string(strerror(error));
#endif
}

bool CSock::IsWouldBlock(int error) {
    if (error == 0) {
        error = GetLastError();
    }

#ifdef _WIN32
    return error == WSAEWOULDBLOCK;
#else
    return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

bool CSock::IsConnectionRefused(int error) {
    if (error == 0) {
        error = GetLastError();
    }

#ifdef _WIN32
    return error == WSAECONNREFUSED;
#else
    return error == ECONNREFUSED;
#endif
}
