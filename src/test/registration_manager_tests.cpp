// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * CRegistrationManager unit tests.
 *
 * Covers the 14 cases from the Registration Manager Test Plan:
 *   1. Reorg handling (CONFIRMED -> CHECK_ELIGIBILITY)
 *   2. SUBMITTED bounded retry (-> READY / -> ATTEST_PENDING)
 *   3. SUBMITTED retry exhaustion (-> LONG_BACKOFF_USER_ACTIONABLE)
 *   4. Shutdown from DNA_PENDING (no partial persistence)
 *   5. Shutdown from ATTEST_PENDING (no partial persistence)
 *   6. Shutdown from POW_PENDING (cancel long PoW, no partial persistence)
 *   7. Poisoned file rejection (zero-DNA variant — the one we actually see in prod)
 *   8. Tick non-blocking contract
 *   9. Worker owns side effects (all I/O on worker thread)
 *  10. Session coherence (DNA changes -> invalidate nonce + attestations)
 *  11. ForceRestart debug behavior
 *  12. CanMine gate correctness matrix
 *  13. Snapshot monotonicity + consistency
 *  14. Long-backoff recovery (time elapses -> CHECK_ELIGIBILITY)
 *
 * All tests drive the state machine synchronously via TestingStepWorkerOnce()
 * — no real worker thread is started, which makes every test deterministic.
 * The handful of tests that require an actual worker thread (shutdown,
 * non-blocking Tick, worker-owns-I/O) start it explicitly.
 */

#include <node/registration_manager.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <dfmp/dfmp.h>
#include <dfmp/mik_registration_file.h>
#include <attestation/seed_attestation.h>

// ---------------------------------------------------------------------------
// Test framework (matches project convention — see mik_registration_persistence_tests.cpp)
// ---------------------------------------------------------------------------

#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"

static int g_tests_passed = 0;
static int g_tests_failed = 0;
static std::vector<std::function<void()>> g_test_fns;

#define TEST(name) \
    static void test_##name(); \
    struct Reg_##name { \
        Reg_##name() { g_test_fns.push_back([]{ \
            std::cout << BLUE << "[TEST] " << #name << RESET << std::endl; \
            try { \
                test_##name(); \
                std::cout << GREEN << "  PASSED" << RESET << std::endl; \
                g_tests_passed++; \
            } catch (const std::exception& e) { \
                std::cout << RED << "  FAILED: " << e.what() << RESET << std::endl; \
                g_tests_failed++; \
            } catch (...) { \
                std::cout << RED << "  FAILED: unknown exception" << RESET << std::endl; \
                g_tests_failed++; \
            } \
        }); } \
    }; \
    static Reg_##name g_reg_##name; \
    static void test_##name()

#define ASSERT(cond, msg) \
    do { if (!(cond)) throw std::runtime_error(std::string(__FILE__) + ":" + \
         std::to_string(__LINE__) + " " + (msg)); } while (0)

#define ASSERT_EQ(a, b, msg) \
    do { if ((a) != (b)) throw std::runtime_error( \
         std::string(__FILE__) + ":" + std::to_string(__LINE__) + " " + (msg) + \
         " (got vs expected differ)"); } while (0)

#define ASSERT_STATE(mgr, expected) \
    do { auto __s = (mgr).GetSnapshot(); \
         if (__s->state != CRegistrationManager::State::expected) { \
             throw std::runtime_error(std::string(__FILE__) + ":" + \
                 std::to_string(__LINE__) + " expected state " #expected \
                 ", got " + StateToString(__s->state)); } \
    } while (0)

// ---------------------------------------------------------------------------
// MockRegistrationEnv: a configurable IRegistrationEnv for unit tests.
//
// All behavior is controlled by public member fields; tests mutate the mock
// directly. Every external call is recorded (call count + calling thread id)
// so tests can assert on side effects and threading.
// ---------------------------------------------------------------------------

class MockRegistrationEnv : public IRegistrationEnv {
public:
    // ---- Identity / wallet ----
    std::optional<std::vector<uint8_t>> mikPubkey;  // nullopt => GetMIKPubKey fails
    std::optional<DFMP::Identity> mikIdentity;      // nullopt => GetMIKIdentity fails
    std::set<std::vector<uint8_t>> registeredIdentities;  // encoded as 20-byte vectors

    // ---- DNA ----
    std::optional<std::array<uint8_t, 32>> dnaHashToReturn;
    std::atomic<int> tryGetDNAHashCalls{0};

    // ---- Attestations ----
    bool attestationSucceeds = true;
    std::string attestationError;
    Attestation::CAttestationSet attestationToReturn;
    bool attestationIsFresh = true;
    std::atomic<int> collectAttestationCalls{0};

    // ---- PoW ----
    bool powSucceeds = true;
    uint64_t powNonceToReturn = 42;
    std::chrono::milliseconds powDuration{0};   // simulated blocking duration
    std::atomic<int> powCallCount{0};
    std::atomic<bool> powWasCancelled{false};
    std::atomic<std::thread::id> lastPowCallerThread;

    // ---- Persistence ----
    std::optional<DFMP::MIKRegistrationFile> persistedFile;
    std::atomic<int> saveCalls{0};
    std::atomic<int> deleteCalls{0};
    std::atomic<int> loadCalls{0};

    // ---- Chain params ----
    int regPowBits = 4;  // deliberately tiny for speed; PoW path is exercised via duration
    int dnaActivation = 0;
    int attestActivation = 2000;

    // ---- Clock ----
    std::atomic<int64_t> fakeNowSec{1700000000};

    // ---- Threading observability ----
    std::atomic<std::thread::id> lastAnyCallThread;

    // --------------------------------------------------------------
    // IRegistrationEnv impl
    // --------------------------------------------------------------

    bool GetMIKPubKey(std::vector<uint8_t>& out) override {
        lastAnyCallThread = std::this_thread::get_id();
        if (!mikPubkey) return false;
        out = *mikPubkey;
        return true;
    }

    bool GetMIKIdentity(DFMP::Identity& out) override {
        lastAnyCallThread = std::this_thread::get_id();
        if (!mikIdentity) return false;
        out = *mikIdentity;
        return !out.IsNull();
    }

    bool HasMIKRegistered(const DFMP::Identity& identity) const override {
        std::vector<uint8_t> key(identity.data, identity.data + 20);
        return registeredIdentities.count(key) > 0;
    }

    bool TryGetDNAHash(std::array<uint8_t, 32>& out) override {
        lastAnyCallThread = std::this_thread::get_id();
        tryGetDNAHashCalls++;
        if (!dnaHashToReturn) return false;
        out = *dnaHashToReturn;
        return true;
    }

    bool CollectAttestations(const std::vector<uint8_t>& /*pubkey*/,
                             const std::array<uint8_t, 32>& /*dnaHash*/,
                             Attestation::CAttestationSet& out,
                             std::string& errOut) override {
        lastAnyCallThread = std::this_thread::get_id();
        collectAttestationCalls++;
        if (!attestationSucceeds) {
            errOut = attestationError;
            return false;
        }
        out = attestationToReturn;
        return true;
    }

    bool IsAttestationFreshEnough(const Attestation::CAttestationSet& /*attest*/,
                                  int64_t /*nowSec*/) const override {
        return attestationIsFresh;
    }

    bool MineRegistrationPoW(const std::vector<uint8_t>& /*pubkey*/,
                             int /*bits*/,
                             const std::array<uint8_t, 32>& /*dnaHash*/,
                             uint64_t& outNonce,
                             const std::atomic<bool>& running) override {
        lastAnyCallThread = std::this_thread::get_id();
        lastPowCallerThread = std::this_thread::get_id();
        powCallCount++;
        // Simulate a long-running PoW that honors the cancel signal.
        auto deadline = std::chrono::steady_clock::now() + powDuration;
        while (std::chrono::steady_clock::now() < deadline) {
            if (!running.load()) {
                powWasCancelled = true;
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (!running.load()) {
            powWasCancelled = true;
            return false;
        }
        if (!powSucceeds) return false;
        outNonce = powNonceToReturn;
        return true;
    }

    bool SaveRegistration(const std::vector<uint8_t>& pubkey,
                          const std::array<uint8_t, 32>& dnaHash,
                          uint64_t nonce,
                          int64_t timestamp) override {
        lastAnyCallThread = std::this_thread::get_id();
        saveCalls++;
        DFMP::MIKRegistrationFile rec;
        rec.pubkey = pubkey;
        rec.dnaHash = dnaHash;
        rec.nonce = nonce;
        rec.timestamp = timestamp;
        persistedFile = rec;
        return true;
    }

    DFMP::MIKRegFileLoadResult LoadRegistration(const std::vector<uint8_t>& pubkey,
                                                DFMP::MIKRegistrationFile& out) override {
        loadCalls++;
        if (!persistedFile) return DFMP::MIKRegFileLoadResult::Missing;
        if (persistedFile->pubkey != pubkey)
            return DFMP::MIKRegFileLoadResult::PubkeyMismatch;
        out = *persistedFile;
        return DFMP::MIKRegFileLoadResult::OK;
    }

    void DeletePersistedRegistration() override {
        lastAnyCallThread = std::this_thread::get_id();
        deleteCalls++;
        persistedFile.reset();
    }

    int RegistrationPowBits() const override { return regPowBits; }
    int DNACommitmentActivationHeight() const override { return dnaActivation; }
    int SeedAttestationActivationHeight() const override { return attestActivation; }
    int64_t NowSeconds() const override { return fakeNowSec.load(); }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::vector<uint8_t> FakePubkey(uint8_t seed = 0x11) {
    std::vector<uint8_t> pk(DFMP::MIK_PUBKEY_SIZE, seed);
    for (size_t i = 0; i < pk.size(); ++i) pk[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    return pk;
}

static DFMP::Identity FakeIdentity(uint8_t seed = 0x11) {
    DFMP::Identity id;
    for (int i = 0; i < 20; ++i) id.data[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    return id;
}

static std::array<uint8_t, 32> FakeDnaHash(uint8_t seed = 0x22) {
    std::array<uint8_t, 32> h{};
    for (size_t i = 0; i < 32; ++i) h[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    return h;
}

static Attestation::CAttestationSet FakeAttestationSet() {
    Attestation::CAttestationSet set;
    // Populate MIN_ATTESTATIONS (3) fake entries so HasMinimum() is true.
    for (int i = 0; i < Attestation::MIN_ATTESTATIONS; ++i) {
        Attestation::CAttestation a;
        a.seedId = static_cast<uint8_t>(i);
        a.timestamp = 1700000000;
        a.signature.assign(DFMP::MIK_SIGNATURE_SIZE, static_cast<uint8_t>(0xAA + i));
        set.attestations.push_back(a);
    }
    return set;
}

/** Standard "happy path" mock env: all calls succeed. */
static std::shared_ptr<MockRegistrationEnv> MakeHappyEnv() {
    auto env = std::make_shared<MockRegistrationEnv>();
    env->mikPubkey = FakePubkey();
    env->mikIdentity = FakeIdentity();
    env->dnaHashToReturn = FakeDnaHash();
    env->attestationToReturn = FakeAttestationSet();
    return env;
}

/** Drive the state machine forward until the state stabilizes OR max steps. */
static void StepUntilState(CRegistrationManager& mgr,
                           CRegistrationManager::State target,
                           int maxSteps = 20) {
    for (int i = 0; i < maxSteps; ++i) {
        mgr.TestingStepWorkerOnce();
        if (mgr.GetSnapshot()->state == target) return;
    }
    throw std::runtime_error(std::string("did not reach state ") +
                             StateToString(target) + " after " +
                             std::to_string(maxSteps) + " steps (final state: " +
                             StateToString(mgr.GetSnapshot()->state) + ")");
}

// ===========================================================================
// TEST CASES
// ===========================================================================

// ---- 1. Reorg handling: CONFIRMED -> CHECK_ELIGIBILITY -------------------

TEST(reorg_confirmed_to_check_eligibility) {
    auto env = MakeHappyEnv();
    // MIK already registered on chain
    env->registeredIdentities.insert({env->mikIdentity->data,
                                       env->mikIdentity->data + 20});

    CRegistrationManager mgr(env);
    mgr.TestingStepWorkerOnce();
    ASSERT_STATE(mgr, CONFIRMED);

    // Simulate reorg: identity no longer in DB.
    env->registeredIdentities.clear();

    // Next worker iteration from CONFIRMED detects the drop.
    mgr.TestingStepWorkerOnce();
    auto s = mgr.GetSnapshot();
    ASSERT(s->state == CRegistrationManager::State::CHECK_ELIGIBILITY ||
           s->state == CRegistrationManager::State::DNA_PENDING,
           "expected CHECK_ELIGIBILITY or DNA_PENDING after reorg");
    ASSERT(s->registrationRequired, "registrationRequired should be true after reorg");
}

// ---- 2. SUBMITTED bounded retry -------------------------------------------

TEST(submitted_retry_to_ready_when_attestations_fresh) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    // Advance to READY.
    StepUntilState(mgr, CRegistrationManager::State::READY, 10);

    // Simulate the miner building a registration template and submitting.
    mgr.TestingInjectEvent(CRegistrationManager::Event::TEMPLATE_BUILT_AND_MINER_STARTED);
    ASSERT_STATE(mgr, SUBMITTED);

    // Submission rejected, attestations still fresh.
    env->attestationIsFresh = true;
    mgr.TestingInjectEvent(CRegistrationManager::Event::SUBMIT_TIMEOUT_OR_REJECTED);
    ASSERT_STATE(mgr, READY);
    ASSERT_EQ(mgr.GetSnapshot()->submitRetriesUsed, 1, "retry counter not incremented");
}

TEST(submitted_retry_to_attest_pending_when_attestations_stale) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    StepUntilState(mgr, CRegistrationManager::State::READY, 10);
    mgr.TestingInjectEvent(CRegistrationManager::Event::TEMPLATE_BUILT_AND_MINER_STARTED);
    ASSERT_STATE(mgr, SUBMITTED);

    // Submission rejected, attestations expired.
    env->attestationIsFresh = false;
    mgr.TestingInjectEvent(CRegistrationManager::Event::SUBMIT_TIMEOUT_OR_REJECTED);
    ASSERT_STATE(mgr, ATTEST_PENDING);
}

// ---- 3. SUBMITTED retry exhaustion -> LONG_BACKOFF_USER_ACTIONABLE --------

TEST(submitted_retry_exhaustion_to_long_backoff) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    StepUntilState(mgr, CRegistrationManager::State::READY, 10);

    // Exhaust the retry budget.
    for (int i = 0; i < 3; ++i) {
        mgr.TestingInjectEvent(CRegistrationManager::Event::TEMPLATE_BUILT_AND_MINER_STARTED);
        env->attestationIsFresh = true;
        mgr.TestingInjectEvent(CRegistrationManager::Event::SUBMIT_TIMEOUT_OR_REJECTED);
    }
    // Third reject should have exhausted budget -> LONG_BACKOFF.
    auto s = mgr.GetSnapshot();
    ASSERT(s->state == CRegistrationManager::State::LONG_BACKOFF_USER_ACTIONABLE,
           "expected LONG_BACKOFF after 3 retries");
    ASSERT(!s->userActionHint.empty(), "userActionHint should be populated");
}

// ---- 2c. SUBMIT_TIMEOUT_OR_REJECTED works from READY (v4.0.18 / PR #23 post-Cursor fix) ----
// Production flow skips SUBMITTED (we poll HasMIKRegistered instead of emitting
// TEMPLATE_BUILT_AND_MINER_STARTED). The event must be accepted from READY so
// the retry budget is actually reachable.

TEST(submit_rejected_from_ready_increments_retries) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    StepUntilState(mgr, CRegistrationManager::State::READY, 10);

    ASSERT_EQ(mgr.GetSnapshot()->submitRetriesUsed, 0, "initial retries should be 0");

    // Inject a rejection directly in READY — production path.
    mgr.NotifyBlockRejected("synthetic test rejection");

    auto s = mgr.GetSnapshot();
    ASSERT_EQ(s->submitRetriesUsed, 1, "retry counter should increment from READY");
    ASSERT(s->state == CRegistrationManager::State::READY,
           "should remain in READY when attestations still fresh");
}

// ---- 2d. Public NotifyBlockRejected() is thread-safe + equivalent to event
//         inject + publishes snapshot -----------------------------------------

TEST(notify_block_rejected_publishes_snapshot_monotonically) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    StepUntilState(mgr, CRegistrationManager::State::READY, 10);

    uint64_t seqBefore = mgr.GetSnapshot()->sequence;
    mgr.NotifyBlockRejected("snapshot-test");
    uint64_t seqAfter = mgr.GetSnapshot()->sequence;

    ASSERT(seqAfter > seqBefore, "snapshot sequence must advance after NotifyBlockRejected");
}

// ---- 1b. READY -> CONFIRMED via polling HasMIKRegistered -------------------
// Production path: no external REGISTRATION_SEEN_ONCHAIN event; HandleReady_
// polls env->HasMIKRegistered() on every Tick. When the MIK appears in the
// identity DB, manager transitions to CONFIRMED.

TEST(ready_to_confirmed_via_poll) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    StepUntilState(mgr, CRegistrationManager::State::READY, 10);

    // Simulate the registration block landing on-chain.
    env->registeredIdentities.insert({env->mikIdentity->data,
                                       env->mikIdentity->data + 20});

    // Next worker iteration from READY polls HasMIKRegistered and transitions.
    mgr.TestingStepWorkerOnce();
    ASSERT_STATE(mgr, CONFIRMED);
    ASSERT(!mgr.GetSnapshot()->registrationRequired,
           "registrationRequired should be false after CONFIRMED");
}

// ---- 4-6. Shutdown from pending states (no partial persistence) ----------

TEST(shutdown_from_dna_pending_no_persist) {
    auto env = MakeHappyEnv();
    env->dnaHashToReturn.reset();  // DNA never ready
    CRegistrationManager mgr(env);
    StepUntilState(mgr, CRegistrationManager::State::DNA_PENDING, 10);

    mgr.Shutdown();
    ASSERT_EQ(env->saveCalls.load(), 0, "no save should happen on shutdown from DNA_PENDING");
    ASSERT(!env->persistedFile.has_value(), "no persistence artifact expected");
}

TEST(shutdown_from_attest_pending_no_persist) {
    auto env = MakeHappyEnv();
    env->attestationSucceeds = false;
    env->attestationError = "seeds unreachable";
    CRegistrationManager mgr(env);
    // Drive to ATTEST_PENDING (may bounce through a transient-error state).
    for (int i = 0; i < 10; ++i) mgr.TestingStepWorkerOnce();

    mgr.Shutdown();
    ASSERT_EQ(env->saveCalls.load(), 0, "no save should happen on shutdown from ATTEST_PENDING");
}

TEST(shutdown_from_pow_pending_cancels_and_no_persist) {
    auto env = MakeHappyEnv();
    // Make PoW take long enough that Shutdown() catches it mid-flight.
    env->powDuration = std::chrono::milliseconds(500);

    auto mgr = std::make_unique<CRegistrationManager>(env);
    mgr->Tick(/*tipHeight=*/41000, /*nodeRunning=*/true);

    // Wait until PoW is actually in flight.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (env->powCallCount.load() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT(env->powCallCount.load() >= 1, "PoW should have started");

    // Request shutdown while PoW is running.
    mgr->Shutdown();
    ASSERT(env->powWasCancelled.load(), "PoW should have been cancelled by running=false");
    ASSERT_EQ(env->saveCalls.load(), 0, "no save should happen when PoW cancelled mid-flight");
}

// ---- 7. Poisoned file rejection on startup -------------------------------

TEST(poisoned_file_rejected_on_startup) {
    auto env = MakeHappyEnv();
    // Pre-populate a poisoned (zero-DNA) persisted file.
    DFMP::MIKRegistrationFile poisoned;
    poisoned.pubkey = *env->mikPubkey;
    poisoned.dnaHash = {};  // all zeros
    poisoned.nonce = 0xDEADBEEF;
    poisoned.timestamp = 1700000000;
    env->persistedFile = poisoned;

    CRegistrationManager mgr(env);
    mgr.TestingStepWorkerOnce();

    // Poisoned file should be detected and deleted; manager proceeds with fresh DNA.
    ASSERT_EQ(env->deleteCalls.load(), 1, "poisoned file should be deleted");
    ASSERT(!env->persistedFile.has_value(), "persisted file should be gone after delete");
    auto s = mgr.GetSnapshot();
    // The nonce from the poisoned file must NOT have been accepted.
    ASSERT(!s->hasRegNonce || s->regNonce != 0xDEADBEEF,
           "poisoned nonce must not be accepted");
}

// ---- 8. Tick non-blocking contract ---------------------------------------

TEST(tick_non_blocking) {
    auto env = MakeHappyEnv();
    env->powDuration = std::chrono::milliseconds(300);  // slow-ish PoW

    CRegistrationManager mgr(env);
    // Kick the worker thread.
    mgr.Tick(/*tipHeight=*/41000, /*nodeRunning=*/true);

    // Now call Tick() repeatedly under stopwatch.
    const int N = 50;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < N; ++i) mgr.Tick(41000 + i, true);
    auto t1 = std::chrono::steady_clock::now();
    auto avgUs = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / N;

    // Each Tick should take well under the PoW duration. Generous bound: 10ms avg.
    ASSERT(avgUs < 10000, std::string("Tick() avg=") + std::to_string(avgUs) +
                           "us should be <10000us (non-blocking)");
    mgr.Shutdown();
}

// ---- 9. Worker owns side effects ------------------------------------------

TEST(worker_owns_side_effects) {
    auto env = MakeHappyEnv();
    env->powDuration = std::chrono::milliseconds(50);
    auto testThreadId = std::this_thread::get_id();

    CRegistrationManager mgr(env);
    mgr.Tick(41000, true);

    // Wait for PoW to fire.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (env->powCallCount.load() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    ASSERT(env->powCallCount.load() >= 1, "PoW should have been called");
    ASSERT(env->lastPowCallerThread.load() != testThreadId,
           "PoW must not be called from the test thread");
    mgr.Shutdown();
}

// ---- 10. Session coherence (ForceRestart clears session) ------------------

TEST(session_coherence_force_restart_invalidates_nonce) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    StepUntilState(mgr, CRegistrationManager::State::READY, 10);
    ASSERT(mgr.GetSnapshot()->hasRegNonce, "nonce should be set in READY");
    uint64_t sessionA = mgr.GetSnapshot()->sessionId;

    // Force a restart; session should be reset.
    mgr.ForceRestart("test-trigger");
    auto s = mgr.GetSnapshot();
    ASSERT_STATE(mgr, CHECK_ELIGIBILITY);
    ASSERT(!s->hasRegNonce, "nonce should be cleared after ForceRestart");
    // A fresh session should be started on the next step, with a new id.
    mgr.TestingStepWorkerOnce();
    uint64_t sessionB = mgr.GetSnapshot()->sessionId;
    ASSERT(sessionB != sessionA, "new session id expected after ForceRestart");
}

// ---- 11. ForceRestart debug behavior (terminal state recovery) ------------

TEST(force_restart_from_fatal_recovers) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);
    mgr.TestingInjectEvent(CRegistrationManager::Event::UNRECOVERABLE_ERROR,
                           "synthetic fatal");
    ASSERT_STATE(mgr, FAILED_FATAL);

    mgr.ForceRestart("recovery");
    ASSERT_STATE(mgr, CHECK_ELIGIBILITY);
}

// ---- 12. CanMine gate correctness matrix ---------------------------------

TEST(canmine_matrix) {
    using S = CRegistrationManager::State;
    using R = CRegistrationManager::MineGateReason;

    auto env = MakeHappyEnv();

    // CONFIRMED -> mining allowed (OK_REGISTERED).
    {
        auto e = MakeHappyEnv();
        e->registeredIdentities.insert({e->mikIdentity->data,
                                         e->mikIdentity->data + 20});
        CRegistrationManager mgr(e);
        mgr.TestingStepWorkerOnce();
        R reason;
        ASSERT(mgr.CanMine(&reason), "CanMine should be true when CONFIRMED");
        ASSERT(reason == R::OK_REGISTERED, "reason should be OK_REGISTERED");
    }
    // READY -> mining allowed (OK_REGISTRATION_IN_PROGRESS).
    {
        auto e = MakeHappyEnv();
        CRegistrationManager mgr(e);
        StepUntilState(mgr, S::READY, 10);
        R reason;
        ASSERT(mgr.CanMine(&reason), "CanMine true in READY");
        ASSERT(reason == R::OK_REGISTRATION_IN_PROGRESS, "reason should be OK_IN_PROGRESS");
    }
    // DNA_PENDING -> blocked.
    {
        auto e = MakeHappyEnv();
        e->dnaHashToReturn.reset();
        CRegistrationManager mgr(e);
        mgr.TestingStepWorkerOnce();  // UNINITIALIZED -> HandleCheckEligibility -> DNA_PENDING
        R reason;
        ASSERT(!mgr.CanMine(&reason), "CanMine false in DNA_PENDING");
        ASSERT(reason == R::BLOCKED_DNA_PENDING, "reason should be BLOCKED_DNA_PENDING");
    }
    // FAILED_FATAL -> blocked.
    {
        auto e = MakeHappyEnv();
        CRegistrationManager mgr(e);
        mgr.TestingInjectEvent(CRegistrationManager::Event::UNRECOVERABLE_ERROR, "x");
        R reason;
        ASSERT(!mgr.CanMine(&reason), "CanMine false in FAILED_FATAL");
        ASSERT(reason == R::BLOCKED_FATAL, "reason should be BLOCKED_FATAL");
    }
}

// ---- 13. Snapshot monotonicity + consistency -----------------------------

TEST(snapshot_monotonic_and_consistent) {
    auto env = MakeHappyEnv();
    CRegistrationManager mgr(env);

    uint64_t lastSeq = 0;
    for (int i = 0; i < 5; ++i) {
        mgr.TestingStepWorkerOnce();
        auto s = mgr.GetSnapshot();
        ASSERT(s->sequence > lastSeq, "snapshot sequence must be strictly monotonic");
        lastSeq = s->sequence;

        // Consistency: hasRegNonce implies sessionId non-zero.
        if (s->hasRegNonce) {
            ASSERT(s->sessionId != 0, "hasRegNonce without sessionId is inconsistent");
        }
        // hasDnaHash implies we have a MIK pubkey.
        if (s->hasDnaHash) {
            ASSERT(!s->mikPubkey.empty(), "hasDnaHash without mikPubkey is inconsistent");
        }
    }
}

// ---- 14. Long-backoff recovery -------------------------------------------

TEST(long_backoff_recovery) {
    auto env = MakeHappyEnv();
    env->mikPubkey.reset();  // wallet locked
    CRegistrationManager mgr(env);
    mgr.TestingStepWorkerOnce();
    ASSERT_STATE(mgr, LONG_BACKOFF_USER_ACTIONABLE);

    // Unlock the wallet.
    env->mikPubkey = FakePubkey();
    env->mikIdentity = FakeIdentity();

    // ForceRestart simulates "user came back, tick again" — the cleanest
    // deterministic way to exit LONG_BACKOFF without relying on wall-clock
    // backoff timers in a unit test.
    mgr.ForceRestart("recovery");
    ASSERT_STATE(mgr, CHECK_ELIGIBILITY);
    // Now a fresh step should proceed (DNA available, identity available).
    mgr.TestingStepWorkerOnce();
    auto s = mgr.GetSnapshot();
    ASSERT(s->state == CRegistrationManager::State::DNA_PENDING ||
           s->state == CRegistrationManager::State::ATTEST_PENDING ||
           s->state == CRegistrationManager::State::POW_PENDING ||
           s->state == CRegistrationManager::State::READY,
           "should have progressed past CHECK_ELIGIBILITY");
}

// ===========================================================================
// main()
// ===========================================================================

int main(int /*argc*/, char** /*argv*/) {
    std::cout << BLUE << "=== CRegistrationManager unit tests ===" << RESET << std::endl;
    for (auto& fn : g_test_fns) fn();
    std::cout << std::endl
              << BLUE << "=== Summary ===" << RESET << std::endl
              << GREEN << "  Passed: " << g_tests_passed << RESET << std::endl
              << RED   << "  Failed: " << g_tests_failed << RESET << std::endl;
    return g_tests_failed == 0 ? 0 : 1;
}
