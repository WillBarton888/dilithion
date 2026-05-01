// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// PR-Z-1: lifecycle round-trip for the abstract publish notifier base via a
// loopback subscriber. Per-topic publishers and chainstate / mempool wiring
// are PR-Z-2 territory, so this file deliberately exercises only:
//
//   * Initialize() -> bind a tcp:// PUB socket on 127.0.0.1
//   * SendZmqMessage() -> 3-frame multipart with strictly monotonic nSequence
//   * Shutdown() -> idempotent close, multimap cleanup
//
// The subscriber lives in this same process on a separate thread and uses
// inproc:// loopback at the libzmq layer (we still bind tcp:// so the
// server-side code path is identical to production).

#include <boost/test/unit_test.hpp>

#include <zmq/zmqabstractnotifier.h>
#include <zmq/zmqpublishnotifier.h>
#include <zmq/zmqutil.h>

#include <primitives/transaction.h>

#include <zmq.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

BOOST_AUTO_TEST_SUITE(zmq_tests)

// IPv6 detection heuristic -- exercises zmq_util::IsZMQAddressIPV6 against the
// red-team's 10-address corpus from the F1 finding. The heuristic strips
// tcp:// then any trailing :digits port, and treats remaining colons (or any
// '[') as IPv6. See zmq_util::IsZMQAddressIPV6 for the design rationale.
BOOST_AUTO_TEST_CASE(zmq_util_ipv6_detection)
{
    // Bracketed IPv6 -- canonical form.
    BOOST_CHECK(zmq_util::IsZMQAddressIPV6("tcp://[::1]:28332"));
    BOOST_CHECK(zmq_util::IsZMQAddressIPV6("tcp://[2001:db8::1]:5555"));
    BOOST_CHECK(zmq_util::IsZMQAddressIPV6("tcp://[fe80::1]:8332"));

    // Bare IPv6 -- the case F1 calls out as silently mis-classified by the
    // old textual '[' check.
    BOOST_CHECK(zmq_util::IsZMQAddressIPV6("tcp://2001:db8::1:5555"));
    BOOST_CHECK(zmq_util::IsZMQAddressIPV6("tcp://fe80::1:5555"));
    BOOST_CHECK(zmq_util::IsZMQAddressIPV6("tcp://::1:5555"));

    // IPv4 dotted-quad with port.
    BOOST_CHECK(!zmq_util::IsZMQAddressIPV6("tcp://127.0.0.1:28332"));
    BOOST_CHECK(!zmq_util::IsZMQAddressIPV6("tcp://0.0.0.0:8332"));

    // Hostname with port -- after stripping :port there are 0 colons in host.
    BOOST_CHECK(!zmq_util::IsZMQAddressIPV6("tcp://localhost:5555"));
    BOOST_CHECK(!zmq_util::IsZMQAddressIPV6("tcp://example.com:8332"));

    // Non-tcp prefix -- IsZMQAddressIPV6 only handles tcp://, returns false.
    BOOST_CHECK(!zmq_util::IsZMQAddressIPV6("ipc:///tmp/dilithion.sock"));
    BOOST_CHECK(!zmq_util::IsZMQAddressIPV6("inproc://test"));
}

namespace {

// Pick a high TCP port for the test bind. Hardcoding works for a single-
// threaded boost run because Initialize() / Shutdown() each test cleans up.
// If we ever parallelise these tests, swap in a per-test port allocator.
constexpr const char* kTestEndpoint = "tcp://127.0.0.1:28333";

// Read a full ZMQ multipart message from a SUB socket as a vector of frames.
// Returns an empty vector on timeout.
std::vector<std::vector<unsigned char>> RecvAllFrames(void* sub_sock, int timeout_ms)
{
    std::vector<std::vector<unsigned char>> frames;

    zmq_pollitem_t item{};
    item.socket = sub_sock;
    item.events = ZMQ_POLLIN;
    int rc = zmq_poll(&item, 1, timeout_ms);
    if (rc <= 0) return frames;

    while (true) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        int n = zmq_msg_recv(&msg, sub_sock, 0);
        if (n < 0) {
            zmq_msg_close(&msg);
            break;
        }
        const unsigned char* p = static_cast<const unsigned char*>(zmq_msg_data(&msg));
        frames.emplace_back(p, p + n);
        int more = 0;
        size_t more_size = sizeof(more);
        zmq_getsockopt(sub_sock, ZMQ_RCVMORE, &more, &more_size);
        zmq_msg_close(&msg);
        if (!more) break;
    }
    return frames;
}

}  // namespace

// Minimal concrete subclass for testing -- exposes the protected interface
// without dragging in the per-topic publishers (which are PR-Z-2).
class TestNotifier : public CZMQAbstractPublishNotifier
{
};

// 1. Default-constructed notifier exposes the BC-compatible defaults.
BOOST_AUTO_TEST_CASE(zmq_abstract_defaults)
{
    TestNotifier n;
    BOOST_CHECK_EQUAL(n.GetOutboundMessageHighWaterMark(),
                      CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM);
    BOOST_CHECK_EQUAL(n.GetType(), std::string{});
    BOOST_CHECK_EQUAL(n.GetAddress(), std::string{});

    // Negative HWM values must be rejected (BC behaviour).
    n.SetOutboundMessageHighWaterMark(-5);
    BOOST_CHECK_EQUAL(n.GetOutboundMessageHighWaterMark(),
                      CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM);

    n.SetOutboundMessageHighWaterMark(2000);
    BOOST_CHECK_EQUAL(n.GetOutboundMessageHighWaterMark(), 2000);
}

// 2. All default Notify*() overloads on the abstract base return true (no-op
// base). Exercises both the CBlockIndex* overloads with nullptr (no upstream
// dereference happens in the no-op base) and the CTransaction& overloads
// with a default-constructed transaction (CTransaction has a public default
// ctor at primitives/transaction.h:120, so no real mempool object is
// required for the base-class no-op contract). PR-Z-2 will exercise these
// again from the per-topic publishers with real chainstate / mempool data.
BOOST_AUTO_TEST_CASE(zmq_abstract_notifications_default_noop)
{
    TestNotifier n;
    BOOST_CHECK(n.NotifyBlock(nullptr));
    BOOST_CHECK(n.NotifyBlockConnect(nullptr));
    BOOST_CHECK(n.NotifyBlockDisconnect(nullptr));

    CTransaction tx;
    BOOST_CHECK(n.NotifyTransaction(tx));
    BOOST_CHECK(n.NotifyTransactionAcceptance(tx, 0));
    BOOST_CHECK(n.NotifyTransactionRemoval(tx, 0));
}

// 3. Full lifecycle: bind PUB, connect SUB, publish, receive, shut down.
BOOST_AUTO_TEST_CASE(zmq_publish_lifecycle_roundtrip)
{
    void* ctx = zmq_ctx_new();
    BOOST_REQUIRE(ctx != nullptr);

    TestNotifier pub;
    pub.SetType("hashblock");
    pub.SetAddress(kTestEndpoint);
    pub.SetOutboundMessageHighWaterMark(1000);

    BOOST_REQUIRE(pub.Initialize(ctx));

    // Set up a subscriber on the same context.
    void* sub = zmq_socket(ctx, ZMQ_SUB);
    BOOST_REQUIRE(sub != nullptr);
    BOOST_REQUIRE_EQUAL(zmq_connect(sub, kTestEndpoint), 0);
    BOOST_REQUIRE_EQUAL(zmq_setsockopt(sub, ZMQ_SUBSCRIBE, "", 0), 0);

    // libzmq's PUB/SUB has a slow-joiner problem: messages sent before the
    // SUB has finished its handshake are silently dropped. The previous
    // test slept a fixed 100ms (with a comment claiming 50ms -- another
    // bug); that is fragile on Windows CI under load.
    //
    // Replaced with a warmup loop that publishes throwaway "warmup"
    // messages on a distinct topic until the SUB drains one, proving the
    // handshake completed. This bounds the wait at roughly the actual
    // handshake time instead of a worst-case constant. zmq_socket_monitor
    // would be marginally cleaner but adds >20 LOC for the event-API
    // boilerplate; the warmup loop hits the same goal.
    //
    // Each warmup send DOES advance the publisher's nSequence (the publisher
    // has no way to know which messages were dropped vs delivered). We
    // therefore probe the post-warmup sequence number directly off the
    // wire and use that as the baseline for the real-message assertions.
    constexpr int kWarmupAttempts = 50;            // ~5s worst case
    constexpr int kWarmupPollMs = 100;
    bool warmed = false;
    for (int i = 0; i < kWarmupAttempts && !warmed; ++i) {
        BOOST_REQUIRE(pub.SendZmqMessage("warmup", nullptr, 0));
        auto frames = RecvAllFrames(sub, kWarmupPollMs);
        if (!frames.empty()) {
            warmed = true;
        }
    }
    BOOST_REQUIRE(warmed);

    // Drain any additional warmup frames still queued at the SUB so the
    // real-message asserts below start from a clean queue.
    while (!RecvAllFrames(sub, 10).empty()) {
        // discard
    }

    // Probe the publisher's current sequence by sending one marker message
    // and reading the seq frame off the wire. The next real message must
    // have sequence == marker_seq + 1.
    uint32_t seq_baseline = 0;
    {
        unsigned char marker[1] = {0xff};
        BOOST_REQUIRE(pub.SendZmqMessage("marker", marker, 1));
        auto frames = RecvAllFrames(sub, 1000);
        BOOST_REQUIRE_EQUAL(frames.size(), 3u);
        BOOST_REQUIRE_EQUAL(frames[2].size(), 4u);
        seq_baseline = static_cast<uint32_t>(frames[2][0])
                     | (static_cast<uint32_t>(frames[2][1]) << 8)
                     | (static_cast<uint32_t>(frames[2][2]) << 16)
                     | (static_cast<uint32_t>(frames[2][3]) << 24);
        seq_baseline += 1;  // next expected
    }

    // Send 3 messages and assert the subscriber receives each with the
    // expected 3-frame layout and strictly increasing nSequence starting at
    // seq_baseline.
    const char kTopic[] = "hashblock";
    unsigned char payload[32];
    for (unsigned i = 0; i < 32; ++i) payload[i] = static_cast<unsigned char>(i);

    for (int i = 0; i < 3; ++i) {
        BOOST_REQUIRE(pub.SendZmqMessage(kTopic, payload, sizeof(payload)));
    }

    std::vector<uint32_t> got_sequences;
    for (int i = 0; i < 3; ++i) {
        auto frames = RecvAllFrames(sub, 1000);
        BOOST_REQUIRE_EQUAL(frames.size(), 3u);

        // Frame 0: topic.
        BOOST_CHECK_EQUAL(std::string(frames[0].begin(), frames[0].end()),
                          std::string(kTopic));
        // Frame 1: payload.
        BOOST_REQUIRE_EQUAL(frames[1].size(), 32u);
        BOOST_CHECK_EQUAL(std::memcmp(frames[1].data(), payload, 32), 0);
        // Frame 2: 4-byte LE sequence.
        BOOST_REQUIRE_EQUAL(frames[2].size(), 4u);
        uint32_t seq = static_cast<uint32_t>(frames[2][0])
                     | (static_cast<uint32_t>(frames[2][1]) << 8)
                     | (static_cast<uint32_t>(frames[2][2]) << 16)
                     | (static_cast<uint32_t>(frames[2][3]) << 24);
        got_sequences.push_back(seq);
    }

    BOOST_REQUIRE_EQUAL(got_sequences.size(), 3u);
    BOOST_CHECK_EQUAL(got_sequences[0], seq_baseline);
    BOOST_CHECK_EQUAL(got_sequences[1], seq_baseline + 1u);
    BOOST_CHECK_EQUAL(got_sequences[2], seq_baseline + 2u);

    // Tear down. ZMQ_LINGER=0 in Shutdown() ensures we don't hang.
    int linger = 0;
    zmq_setsockopt(sub, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_close(sub);

    pub.Shutdown();
    BOOST_CHECK(true);  // Shutdown returned without crashing.

    // Calling Shutdown twice must be a no-op (idempotency).
    pub.Shutdown();

    zmq_ctx_term(ctx);
}

// 4. Address sharing: notifiers on the same address share one socket and
// Shutdown() of one MUST NOT break the others. Mirrors the BC behaviour for
// operators who route hashblock + hashtx + rawtx to a single endpoint.
//
// Mutation-test contract: a regression that closed the underlying socket on
// the FIRST Shutdown() (instead of refcounting via the multimap) MUST cause
// this test to fail, because we send through the surviving notifier b AFTER
// a is shut down, and again through c after b is shut down.
BOOST_AUTO_TEST_CASE(zmq_publish_shared_address)
{
    void* ctx = zmq_ctx_new();
    BOOST_REQUIRE(ctx != nullptr);

    TestNotifier a;
    a.SetType("hashblock");
    a.SetAddress("tcp://127.0.0.1:28334");

    TestNotifier b;
    b.SetType("hashtx");
    b.SetAddress("tcp://127.0.0.1:28334");

    TestNotifier c;
    c.SetType("rawtx");
    c.SetAddress("tcp://127.0.0.1:28334");

    BOOST_REQUIRE(a.Initialize(ctx));
    BOOST_REQUIRE(b.Initialize(ctx));
    BOOST_REQUIRE(c.Initialize(ctx));

    // Sending from each must succeed without needing its own bind.
    unsigned char payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    BOOST_CHECK(a.SendZmqMessage("hashblock", payload, sizeof(payload)));
    BOOST_CHECK(b.SendZmqMessage("hashtx", payload, sizeof(payload)));
    BOOST_CHECK(c.SendZmqMessage("rawtx", payload, sizeof(payload)));

    // Tear down a; b and c must still be able to publish on the shared
    // socket. This is the load-bearing assertion that fails if anything
    // regresses to closing the socket on the first Shutdown().
    a.Shutdown();
    BOOST_CHECK(b.SendZmqMessage("hashtx", payload, sizeof(payload)));
    BOOST_CHECK(c.SendZmqMessage("rawtx", payload, sizeof(payload)));

    // Tear down b; c must still be able to publish.
    b.Shutdown();
    BOOST_CHECK(c.SendZmqMessage("rawtx", payload, sizeof(payload)));

    // Final shutdown closes the underlying socket (refcount-by-multimap).
    c.Shutdown();

    zmq_ctx_term(ctx);
}

// 5. Shutdown without Initialize is a no-op (matches BC -- error paths in
// the init-time wiring rely on this).
BOOST_AUTO_TEST_CASE(zmq_publish_shutdown_without_initialize)
{
    TestNotifier n;
    n.SetAddress(kTestEndpoint);
    n.Shutdown();  // must not crash, must not assert.
    BOOST_CHECK(true);
}

// 6. Bind failure: malformed address must return false from Initialize, must
// not leave a dangling socket, and must leave the notifier in a state where
// a subsequent SetAddress + Initialize works. Also confirms the global
// mapPublishNotifiers is not polluted by the failed init (re-using the same
// good address from a prior successful Initialize would otherwise hand back
// a stale fd).
BOOST_AUTO_TEST_CASE(zmq_publish_bind_failure_clean_state)
{
    void* ctx = zmq_ctx_new();
    BOOST_REQUIRE(ctx != nullptr);

    TestNotifier n;
    n.SetType("hashblock");
    n.SetAddress("tcp://this-is-not-a-valid-address::99999999");

    BOOST_CHECK(!n.Initialize(ctx));
    // Subsequent Shutdown must not crash even though Initialize failed.
    n.Shutdown();

    // Re-initialize against a valid address. If the failed Initialize had
    // polluted mapPublishNotifiers or left psocket non-null, this would
    // either assert (assert(!psocket) at the top of Initialize) or fail to
    // bind. Use a fresh port distinct from the other tests in this suite.
    n.SetAddress("tcp://127.0.0.1:28335");
    BOOST_REQUIRE(n.Initialize(ctx));

    // Sanity-check the recovered notifier actually publishes.
    unsigned char payload[4] = {0xde, 0xad, 0xbe, 0xef};
    BOOST_CHECK(n.SendZmqMessage("hashblock", payload, sizeof(payload)));

    n.Shutdown();

    zmq_ctx_term(ctx);
}

BOOST_AUTO_TEST_SUITE_END()
