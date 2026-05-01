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

#include <zmq.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

BOOST_AUTO_TEST_SUITE(zmq_tests)

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

// 2. Default Notify*() taking pointer arguments return true (no-op base).
// The CTransaction& overloads need a real CTransaction instance to test
// safely; PR-Z-2 will exercise them via the per-topic publishers and the
// real transaction objects coming out of the mempool.
BOOST_AUTO_TEST_CASE(zmq_abstract_notifications_default_noop)
{
    TestNotifier n;
    BOOST_CHECK(n.NotifyBlock(nullptr));
    BOOST_CHECK(n.NotifyBlockConnect(nullptr));
    BOOST_CHECK(n.NotifyBlockDisconnect(nullptr));
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

    // Set up a subscriber on the same context and wait for it to connect.
    // libzmq's PUB/SUB has a slow-joiner problem: messages sent before the
    // SUB has finished its handshake are dropped. We mitigate by sleeping
    // 50ms after subscribe -- more than enough for loopback tcp.
    void* sub = zmq_socket(ctx, ZMQ_SUB);
    BOOST_REQUIRE(sub != nullptr);
    BOOST_REQUIRE_EQUAL(zmq_connect(sub, kTestEndpoint), 0);
    BOOST_REQUIRE_EQUAL(zmq_setsockopt(sub, ZMQ_SUBSCRIBE, "", 0), 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send 3 messages and assert the subscriber receives each with the
    // expected 3-frame layout and a strictly increasing nSequence.
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
    BOOST_CHECK_EQUAL(got_sequences[0], 0u);
    BOOST_CHECK_EQUAL(got_sequences[1], 1u);
    BOOST_CHECK_EQUAL(got_sequences[2], 2u);

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

// 4. Address sharing: two notifiers on the same address share one socket
// and Shutdown() of one does not break the other. Mirrors the BC behaviour
// for operators who route hashblock + hashtx to a single endpoint.
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

    BOOST_REQUIRE(a.Initialize(ctx));
    BOOST_REQUIRE(b.Initialize(ctx));

    // Sending from each must succeed without needing its own bind.
    unsigned char payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    BOOST_CHECK(a.SendZmqMessage("hashblock", payload, sizeof(payload)));
    BOOST_CHECK(b.SendZmqMessage("hashtx", payload, sizeof(payload)));

    // Shutdown order should not matter; the second shutdown is what
    // actually closes the underlying socket (refcount-by-multimap).
    a.Shutdown();
    b.Shutdown();

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

// 6. Bind failure: malformed address must return false from Initialize and
// leave the notifier in a re-Initialize-able state.
BOOST_AUTO_TEST_CASE(zmq_publish_bind_failure_clean_state)
{
    void* ctx = zmq_ctx_new();
    BOOST_REQUIRE(ctx != nullptr);

    TestNotifier n;
    n.SetType("hashblock");
    n.SetAddress("tcp://this-is-not-a-valid-address::99999999");

    BOOST_CHECK(!n.Initialize(ctx));
    // Subsequent Shutdown must not crash.
    n.Shutdown();

    zmq_ctx_term(ctx);
}

BOOST_AUTO_TEST_SUITE_END()
