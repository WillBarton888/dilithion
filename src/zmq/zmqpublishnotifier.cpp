// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Ported from Bitcoin Core v28.0 src/zmq/zmqpublishnotifier.cpp
// PR-Z-1: skeleton. Only the CZMQAbstractPublishNotifier base class lives
// here. Per-topic publishers (hashblock, hashtx, rawblock, rawtx, sequence)
// land in PR-Z-2.

#include <zmq/zmqpublishnotifier.h>

#include <util/logging.h>
#include <zmq/zmqutil.h>

#include <zmq.h>

#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <utility>

// Module-local map of address -> notifier so multiple publishers can share a
// single bound socket. Matches Bitcoin Core's behaviour: when two publishers
// configure the same address, the second reuses the first's socket and is
// added to the multimap with the same key. Shutdown teardown only closes
// the socket when the last publisher for an address is gone.
//
// TODO(PR-Z-2): wrap in a mutex when chainstate / mempool callbacks invoke
// SendZmqMessage / Initialize / Shutdown from arbitrary threads.
// std::multimap find/insert/erase are NOT thread-safe. PR-Z-2's per-topic
// publishers will be the first thing that exercises this map from non-main
// threads, so the lock must land before that wiring goes in.
//
// PR-Z-1 contract: Initialize() and Shutdown() are called only from the
// node's main / startup-shutdown thread (the lifecycle test enforces this).
// Debug-only assertion is at the head of each function that touches the map.
static std::multimap<std::string, CZMQAbstractPublishNotifier*> mapPublishNotifiers;

// PR-Z-1: capture the thread that first touches mapPublishNotifiers and
// assert all subsequent touches come from that same thread. Cheap insurance
// against accidental misuse from PR-Z-2 wiring; flips to a real mutex in
// PR-Z-2 (see TODO above).
namespace {
std::thread::id g_map_owner_thread{};
bool g_map_owner_set{false};

void AssertMapOwnerThread()
{
    if (!g_map_owner_set) {
        g_map_owner_thread = std::this_thread::get_id();
        g_map_owner_set = true;
        return;
    }
    assert(g_map_owner_thread == std::this_thread::get_id() &&
           "mapPublishNotifiers touched from non-owning thread; "
           "PR-Z-2 must add a mutex before wiring multi-thread callbacks");
}
}  // namespace

// Internal helper: send a variable-length sequence of frames as one multipart
// ZMQ message. Caller passes (data, size) pairs terminated by a nullptr data
// argument.
//
// On any failure the message is closed and -1 is returned. The caller's
// multipart message may be partially flushed at this point; the publisher's
// per-message sequence counter must NOT advance in that case.
static int zmq_send_multipart(void* sock, const void* data, size_t size, ...)
{
    va_list args;
    va_start(args, size);

    while (true) {
        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, size);
        if (rc != 0) {
            zmq_util::zmqError("Unable to initialize ZMQ msg");
            va_end(args);
            return -1;
        }

        void* buf = zmq_msg_data(&msg);
        std::memcpy(buf, data, size);

        data = va_arg(args, const void*);

        rc = zmq_msg_send(&msg, sock, data ? ZMQ_SNDMORE : 0);
        if (rc == -1) {
            zmq_util::zmqError("Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            va_end(args);
            return -1;
        }

        zmq_msg_close(&msg);

        if (!data) break;

        size = va_arg(args, size_t);
    }
    va_end(args);
    return 0;
}

bool CZMQAbstractPublishNotifier::Initialize(void* pcontext)
{
    assert(!psocket);
    assert(pcontext);
    AssertMapOwnerThread();

    // Reuse an existing socket if another publisher already bound this
    // address. This is the normal case when an operator passes both
    // -zmqpubhashblock=tcp://... and -zmqpubhashtx=tcp://... pointing at the
    // same endpoint.
    auto i = mapPublishNotifiers.find(address);

    if (i == mapPublishNotifiers.end()) {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket) {
            zmq_util::zmqError("Failed to create socket");
            return false;
        }

        LogPrintZMQ(INFO, "[zmq] init publisher type=%s addr=%s hwm=%d",
                    type.c_str(), address.c_str(), outbound_message_high_water_mark);

        int rc = zmq_setsockopt(psocket, ZMQ_SNDHWM,
                                &outbound_message_high_water_mark,
                                sizeof(outbound_message_high_water_mark));
        if (rc != 0) {
            zmq_util::zmqError("Failed to set outbound message high water mark");
            zmq_close(psocket);
            psocket = nullptr;
            return false;
        }

        const int so_keepalive_option{1};
        rc = zmq_setsockopt(psocket, ZMQ_TCP_KEEPALIVE,
                            &so_keepalive_option, sizeof(so_keepalive_option));
        if (rc != 0) {
            zmq_util::zmqError("Failed to set SO_KEEPALIVE");
            zmq_close(psocket);
            psocket = nullptr;
            return false;
        }

        // ZMQ_IPV6 must only be enabled if the address is actually IPv6;
        // some platforms (notably OpenBSD) refuse otherwise. See zmq_util::
        // IsZMQAddressIPV6 for the heuristic and its rationale.
        const int enable_ipv6{zmq_util::IsZMQAddressIPV6(address) ? 1 : 0};
        rc = zmq_setsockopt(psocket, ZMQ_IPV6, &enable_ipv6, sizeof(enable_ipv6));
        if (rc != 0) {
            zmq_util::zmqError("Failed to set ZMQ_IPV6");
            zmq_close(psocket);
            psocket = nullptr;
            return false;
        }

        rc = zmq_bind(psocket, address.c_str());
        if (rc != 0) {
            zmq_util::zmqError("Failed to bind address");
            zmq_close(psocket);
            psocket = nullptr;
            return false;
        }

        LogPrintZMQ(INFO, "[zmq] bound type=%s addr=%s", type.c_str(), address.c_str());
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    } else {
        LogPrintZMQ(INFO, "[zmq] reusing socket for addr=%s (type=%s)",
                    address.c_str(), type.c_str());
        psocket = i->second->psocket;
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    }
}

void CZMQAbstractPublishNotifier::Shutdown()
{
    // Idempotent: Shutdown() is callable when Initialize() failed or was
    // never invoked. Bitcoin Core relies on this in its construction-time
    // error paths.
    if (!psocket) return;

    AssertMapOwnerThread();

    int count = mapPublishNotifiers.count(address);

    using iterator = std::multimap<std::string, CZMQAbstractPublishNotifier*>::iterator;
    std::pair<iterator, iterator> iterpair = mapPublishNotifiers.equal_range(address);

    for (iterator it = iterpair.first; it != iterpair.second; ++it) {
        if (it->second == this) {
            mapPublishNotifiers.erase(it);
            break;
        }
    }

    if (count == 1) {
        LogPrintZMQ(INFO, "[zmq] close socket addr=%s (type=%s)",
                    address.c_str(), type.c_str());
        // ZMQ_LINGER=0: drop any queued messages instead of blocking the
        // shutdown thread waiting for slow subscribers. Required for clean
        // node exit.
        int linger = 0;
        zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(psocket);
    }

    psocket = nullptr;
}

bool CZMQAbstractPublishNotifier::SendZmqMessage(const char* command, const void* data, size_t size)
{
    assert(psocket);

    // Frame layout: [command][data][LE32 sequence].
    // The sequence counter is a publisher-local strictly monotonic uint32_t.
    // It does NOT cross process restarts and is independent of mempool /
    // chainstate sequence numbers (which PR-Z-2's sequence publisher will
    // expose separately).
    unsigned char msgseq[sizeof(uint32_t)];
    msgseq[0] = static_cast<unsigned char>(nSequence & 0xff);
    msgseq[1] = static_cast<unsigned char>((nSequence >> 8) & 0xff);
    msgseq[2] = static_cast<unsigned char>((nSequence >> 16) & 0xff);
    msgseq[3] = static_cast<unsigned char>((nSequence >> 24) & 0xff);

    int rc = zmq_send_multipart(psocket, command, std::strlen(command),
                                data, size,
                                msgseq, static_cast<size_t>(sizeof(uint32_t)),
                                nullptr);
    if (rc == -1) {
        // zmqError() has already logged. Slow-subscriber drops surface as
        // EAGAIN; libzmq returns -1 on the partial send. We do NOT advance
        // nSequence on failure -- PR-Z-2's reorg / sequence test depends on
        // gap-free numbering across successful publishes only.
        return false;
    }

    nSequence++;
    return true;
}
