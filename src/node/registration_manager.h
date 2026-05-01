// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_REGISTRATION_MANAGER_H
#define DILITHION_NODE_REGISTRATION_MANAGER_H

/**
 * First-time MIK Registration State Machine.
 *
 * Owns the complete registration workflow for a new miner:
 *   1. Collect Digital DNA fingerprint (waits for collector)
 *   2. Request seed attestations (3-of-4 quorum)
 *   3. Mine the DNA-bound registration PoW
 *   4. Persist the solved nonce atomically
 *   5. Gate vdf_miner.Start() until registration is ready
 *
 * Design invariants (these are load-bearing — do not remove):
 *   - BuildMiningTemplate is a pure function of the published Snapshot.
 *     It NEVER mines PoW, collects DNA, requests attestations, or mutates state.
 *   - A single immutable (sessionId, mikPubkey, dnaHash) triple anchors each
 *     registration attempt. If any input changes, the session is abandoned
 *     and a fresh one is started. No partial-state reuse.
 *   - Persistence only ever writes a fully-coherent (pubkey, dnaHash, nonce).
 *     Zero-DNA saves are refused; zero-DNA files on load are auto-deleted.
 *   - Tick() is non-blocking. All I/O and PoW happen on an internal worker
 *     thread. Tick() just publishes fresh inputs and wakes the worker.
 *
 * This header is designed for testability via IRegistrationEnv — the state
 * machine's external dependencies (wallet, identity DB, DNA collector,
 * attestation RPC, PoW miner, persistence, clock) are all dispatched through
 * an interface so unit tests can inject deterministic fakes.
 */

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <dfmp/dfmp.h>
#include <dfmp/mik_registration_file.h>
#include <attestation/seed_attestation.h>

// ============================================================================
// Environment interface (production impl wraps the real subsystems;
// test impl returns deterministic fakes)
// ============================================================================

class IRegistrationEnv {
public:
    virtual ~IRegistrationEnv() = default;

    // ---- Identity / wallet ----

    /** Fetch the miner's MIK public key. Returns false if wallet is locked
     *  or MIK is not yet generated. */
    virtual bool GetMIKPubKey(std::vector<uint8_t>& out) = 0;

    /** Fetch the miner's MIK identity (20-byte hash used as DB key). Returns
     *  false if wallet has no MIK. */
    virtual bool GetMIKIdentity(DFMP::Identity& out) = 0;

    /** True if this MIK identity is already recorded in the identity DB
     *  as registered on the current canonical chain. */
    virtual bool HasMIKRegistered(const DFMP::Identity& identity) const = 0;

    // ---- DNA collection ----

    /** Try to get a complete DNA hash. Returns false if the collector does
     *  not yet have enough samples (get_dna() returned nullopt). */
    virtual bool TryGetDNAHash(std::array<uint8_t, 32>& out) = 0;

    // ---- Seed attestations ----

    /** Synchronously request attestations from the configured seed nodes.
     *  Returns true iff >= MIN_ATTESTATIONS valid signatures were collected.
     *  errOut is populated on failure (e.g. "seeds unreachable", "datacenter IP"). */
    virtual bool CollectAttestations(
        const std::vector<uint8_t>& pubkey,
        const std::array<uint8_t, 32>& dnaHash,
        Attestation::CAttestationSet& out,
        std::string& errOut) = 0;

    /** True if the attestation set is still within the validity window
     *  (ATTESTATION_VALIDITY_WINDOW - refresh_threshold). */
    virtual bool IsAttestationFreshEnough(
        const Attestation::CAttestationSet& attest,
        int64_t nowSec) const = 0;

    // ---- Registration PoW ----

    /** Mine the registration PoW bound to (pubkey, dnaHash). Must honor the
     *  running flag (true = keep going, false = abort); long-running call
     *  (minutes). Signature matches DFMP::MineRegistrationPoW. */
    virtual bool MineRegistrationPoW(
        const std::vector<uint8_t>& pubkey,
        int bits,
        const std::array<uint8_t, 32>& dnaHash,
        uint64_t& outNonce,
        const std::atomic<bool>& running) = 0;

    // ---- Persistence ----

    /** Save a coherent (pubkey, dnaHash, nonce). The real impl calls
     *  DFMP::SaveMIKRegistration; the manager guarantees dnaHash is non-zero. */
    virtual bool SaveRegistration(
        const std::vector<uint8_t>& pubkey,
        const std::array<uint8_t, 32>& dnaHash,
        uint64_t nonce,
        int64_t timestamp) = 0;

    /** Load the persisted registration for this MIK. */
    virtual DFMP::MIKRegFileLoadResult LoadRegistration(
        const std::vector<uint8_t>& pubkey,
        DFMP::MIKRegistrationFile& out) = 0;

    /** Delete any poisoned-file artifact (zero DNA hash etc.) from disk. */
    virtual void DeletePersistedRegistration() = 0;

    // ---- Chain params ----

    virtual int RegistrationPowBits() const = 0;
    virtual int DNACommitmentActivationHeight() const = 0;
    virtual int SeedAttestationActivationHeight() const = 0;

    // ---- Clock (injectable for tests) ----

    virtual int64_t NowSeconds() const = 0;
};

// ============================================================================
// RegistrationManager
// ============================================================================

class CRegistrationManager {
public:
    // ------------------------------------------------------------------
    // States
    // ------------------------------------------------------------------
    enum class State : uint8_t {
        UNINITIALIZED,                    // created, waiting for first Tick
        CHECK_ELIGIBILITY,                // examining wallet/DB/persisted state
        DNA_PENDING,                      // waiting for collector to produce a hash
        ATTEST_PENDING,                   // requesting seed attestations
        POW_PENDING,                      // mining registration PoW
        READY,                            // coherent (pubkey, dna, attest, nonce) held
        SUBMITTED,                        // miner building/mining reg template
        CONFIRMED,                        // MIK observed as registered on-chain
        LONG_BACKOFF_USER_ACTIONABLE,     // recoverable error (wallet locked, seeds unreachable)
        FAILED_FATAL,                     // unrecoverable invariant violation
        SHUTTING_DOWN,                    // clean-up in progress, no new work
        STOPPED                           // worker thread has exited
    };

    // ------------------------------------------------------------------
    // Events (internal state-machine input)
    // ------------------------------------------------------------------
    enum class Event : uint8_t {
        STARTUP,
        TIP_UPDATED,
        SESSION_STARTED,
        DNA_READY,
        ATTEST_READY,
        POW_READY,
        TEMPLATE_BUILT_AND_MINER_STARTED,
        REGISTRATION_SEEN_ONCHAIN,
        REGISTRATION_MISSING_ONCHAIN,      // reorg pulled us back
        SUBMIT_TIMEOUT_OR_REJECTED,
        SUBMIT_RETRY_BUDGET_EXHAUSTED,
        TRANSIENT_ERROR,
        USER_ACTION_REQUIRED,
        UNRECOVERABLE_ERROR,
        SHUTDOWN_REQUESTED,
        WORKER_STOPPED,
        FORCE_RESTART
    };

    // ------------------------------------------------------------------
    // Reason codes for CanMine() — lets callers log precisely WHY mining
    // is blocked without parsing state enum.
    // ------------------------------------------------------------------
    enum class MineGateReason : uint8_t {
        OK_REGISTERED,                    // MIK is registered; mine normally
        OK_REGISTRATION_IN_PROGRESS,      // READY/SUBMITTED — allowed to build reg template
        BLOCKED_UNINITIALIZED,
        BLOCKED_DNA_PENDING,
        BLOCKED_ATTEST_PENDING,
        BLOCKED_POW_PENDING,
        BLOCKED_RETRYING_SUBMISSION,
        BLOCKED_LONG_BACKOFF_USER_ACTIONABLE,
        BLOCKED_FATAL,
        BLOCKED_SHUTTING_DOWN
    };

    // ------------------------------------------------------------------
    // Session data (mutated only by the worker; copied into Snapshot
    // under the snapshot mutex).
    // ------------------------------------------------------------------
    struct SessionData {
        uint64_t sessionId = 0;
        uint32_t startHeight = 0;
        std::vector<uint8_t> mikPubkey;                              // immutable for session
        DFMP::Identity mikIdentity;                                  // immutable for session
        std::array<uint8_t, 32> dnaHash{};                           // immutable after set
        bool hasDnaHash = false;
        std::unique_ptr<Attestation::CAttestationSet> attestations;  // may be null
        bool hasValidAttestations = false;
        uint64_t regNonce = 0;
        bool hasRegNonce = false;
        int submitRetries = 0;
        int attestationRetries = 0;
        int dnaPolls = 0;
    };

    // ------------------------------------------------------------------
    // Published snapshot — returned by GetSnapshot(), safe to read
    // concurrently from any thread. Copy-on-publish via atomic shared_ptr.
    // ------------------------------------------------------------------
    struct Snapshot {
        State state = State::UNINITIALIZED;
        uint64_t sequence = 0;                  // monotonic version counter
        uint32_t tipHeight = 0;
        bool registrationRequired = true;       // false once CONFIRMED at this tip
        bool canBuildRegistrationTemplate = false; // only true in READY/SUBMITTED

        // Session progress (copies, so Snapshot is self-contained)
        uint64_t sessionId = 0;
        std::vector<uint8_t> mikPubkey;
        std::array<uint8_t, 32> dnaHash{};
        bool hasDnaHash = false;
        bool hasAttestations = false;
        uint64_t regNonce = 0;
        bool hasRegNonce = false;
        std::unique_ptr<Attestation::CAttestationSet> attestations; // nullptr if !hasAttestations

        int submitRetriesUsed = 0;
        int submitRetriesMax = 0;
        std::chrono::system_clock::time_point nextRetryAt{};
        std::string lastError;
        std::string userActionHint;
        MineGateReason mineGate = MineGateReason::BLOCKED_UNINITIALIZED;

        Snapshot() = default;
        Snapshot(const Snapshot& other) { *this = other; }
        Snapshot& operator=(const Snapshot& other);
    };

    // ------------------------------------------------------------------
    // UI-facing condensed status (for the FTUX log lines)
    // ------------------------------------------------------------------
    struct StatusForUI {
        std::string phase;       // "DNA", "ATTEST", "POW", "READY", "CONFIRMED", ...
        std::string message;     // concise human-readable status
        int percent = 0;         // phase-local progress estimate (0-100)
        int retryUsed = 0;
        int retryMax = 0;
        std::string etaText;     // "about 10-20 min"
        std::string actionHint;  // populated for LONG_BACKOFF_USER_ACTIONABLE only
    };

public:
    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /** Construct with an environment implementation. The env must outlive
     *  this manager (typically a shared_ptr held by the node). */
    explicit CRegistrationManager(std::shared_ptr<IRegistrationEnv> env);

    /** Destructor. Joins the worker thread after a clean shutdown. */
    ~CRegistrationManager();

    // Non-copyable, non-movable (owns a worker thread)
    CRegistrationManager(const CRegistrationManager&) = delete;
    CRegistrationManager& operator=(const CRegistrationManager&) = delete;

    // ------------------------------------------------------------------
    // Driver API — called from the node's main loop and tip callback
    // ------------------------------------------------------------------

    /** Advance the state machine with the latest chain tip.
     *  Non-blocking: just publishes inputs and nudges the worker.
     *  Safe to call concurrently from multiple threads.
     *
     *  @param tipHeight    Current canonical chain tip height.
     *  @param nodeRunning  False if the node is shutting down.
     */
    void Tick(uint32_t tipHeight, bool nodeRunning);

    /** Request graceful shutdown and join the worker thread. Idempotent. */
    void Shutdown();

    // ------------------------------------------------------------------
    // Read-only query API — callable from any thread, never blocks the worker
    // ------------------------------------------------------------------

    /** Get the latest published snapshot. Thread-safe. */
    std::shared_ptr<const Snapshot> GetSnapshot() const;

    /** Decide if mining is currently allowed. If mining is blocked, the
     *  reason code is returned via the optional out-param so the caller
     *  can log a concise reason without pattern-matching on State. */
    bool CanMine(MineGateReason* reasonOut = nullptr) const;

    /** Condensed UI status for logs/RPC. */
    StatusForUI GetStatusForUI() const;

    // ------------------------------------------------------------------
    // Debug / test-only
    // ------------------------------------------------------------------

    /** Force the state machine back to CHECK_ELIGIBILITY, abandoning any
     *  in-progress session. For tests and emergency operator use only;
     *  logs a reason line. */
    void ForceRestart(const std::string& why);

    /** Called by the block-submission pipeline when a mined registration
     *  block was rejected by validation. Drives the manager's bounded
     *  submit-retry budget and falls back to READY or ATTEST_PENDING
     *  depending on attestation freshness. When the budget is exhausted,
     *  transitions to LONG_BACKOFF_USER_ACTIONABLE with a diagnostic hint. */
    void NotifyBlockRejected(const std::string& reason);

    // ------------------------------------------------------------------
    // Test hooks — only used by registration_manager_*_tests.cpp
    // ------------------------------------------------------------------

    /** Drive one worker iteration synchronously (tests only). Returns
     *  the post-iteration state for assertion. */
    State TestingStepWorkerOnce();

    /** Inject an event directly (tests only). */
    void TestingInjectEvent(Event ev, const std::string& detail = {});

private:
    // ------------------------------------------------------------------
    // Worker thread lifecycle
    // ------------------------------------------------------------------
    void EnsureWorkerStarted_();
    void RequestShutdown_();
    void WorkerMain_();
    void WorkerIterationLocked_(std::unique_lock<std::mutex>& lk);

    // ------------------------------------------------------------------
    // Event dispatch (worker thread only, holds stateMutex_)
    // ------------------------------------------------------------------
    void Transition_(Event ev, const std::string& detail = {});
    void EnterState_(State s);
    void PublishSnapshot_();

    // ------------------------------------------------------------------
    // State handlers (worker thread only)
    // ------------------------------------------------------------------
    void HandleCheckEligibility_();
    void HandleDnaPending_();
    void HandleAttestPending_();
    void HandlePowPending_();
    void HandleReady_();
    void HandleSubmitted_();
    void HandleConfirmed_();
    void HandleLongBackoff_();

    // ------------------------------------------------------------------
    // Phase 10 PR10.5b regtest fast-path helpers.
    //
    // Gate: pure activation-height comparison against latestTipHeight_.
    // No chain identity is checked. Mainnet/testnet at production heights
    // (DNA: 40000 / 0; Attest: 40000 / 2000) have activation in the past
    // and the requirement-checks return TRUE → fast-path NOT entered.
    // Regtest (inherited from Testnet's 999999999 / 999999999 sentinels)
    // has activation in the future indefinitely → fast-path entered.
    //
    // Layer-2 review (PR10.5b close) verifies (a) the gate excludes
    // mainnet/testnet at all production heights and (b) the placeholder
    // hash is non-confusable with a real DNA hash.
    // ------------------------------------------------------------------
    bool DnaCommitmentRequiredAtTip_() const;
    bool AttestationsRequiredAtTip_() const;
    static std::array<uint8_t, 32> ComputeRegtestPlaceholderDnaHash_();

    // ------------------------------------------------------------------
    // Session management
    // ------------------------------------------------------------------
    void StartNewSession_(uint32_t tipHeight);
    void AbandonSession_(const std::string& reason, bool persistNothing);
    void InvalidateSessionForReorg_();
    bool ValidateSessionCoherence_() const;

    // ------------------------------------------------------------------
    // Persistence wrappers (enforce "never zero-DNA" invariants)
    // ------------------------------------------------------------------
    bool TryRestorePersistedNonce_();
    bool PersistSolvedNonceAtomically_();
    void ClearPersistedNonceIfStale_();

    // ------------------------------------------------------------------
    // Error / backoff policy
    // ------------------------------------------------------------------
    void OnTransientError_(const std::string& err, std::chrono::seconds backoff);
    void OnUserActionRequired_(const std::string& err,
                               const std::string& hint,
                               std::chrono::minutes backoff);
    void OnFatalError_(const std::string& err);

    // ------------------------------------------------------------------
    // Config (can be tweaked for tests)
    // ------------------------------------------------------------------
    int maxSubmitRetries_ = 3;
    int maxAttestationRetries_ = 8;
    std::chrono::seconds dnaPollInterval_{1};
    std::chrono::seconds attestInitialBackoff_{5};
    std::chrono::seconds attestMaxBackoff_{60};
    std::chrono::seconds submitRetryBackoff_{15};
    std::chrono::minutes userActionBackoff_{10};
    int64_t attestRefreshThresholdSec_ = 600; // refresh within 10m of expiry

    // ------------------------------------------------------------------
    // Injected environment
    // ------------------------------------------------------------------
    std::shared_ptr<IRegistrationEnv> env_;

    // ------------------------------------------------------------------
    // Worker thread
    // ------------------------------------------------------------------
    std::thread worker_;
    std::atomic<bool> workerStarted_{false};
    std::atomic<bool> shutdownRequested_{false};
    std::atomic<bool> powRunning_{true};   // true = keep PoW running; set false to cancel

    // ------------------------------------------------------------------
    // Tick-fed context (latest)
    // ------------------------------------------------------------------
    std::atomic<uint32_t> latestTipHeight_{0};
    std::atomic<bool> latestNodeRunning_{true};

    // ------------------------------------------------------------------
    // Core state (owned by worker; mutated under stateMutex_)
    // ------------------------------------------------------------------
    mutable std::mutex stateMutex_;
    std::condition_variable stateCv_;
    State state_{State::UNINITIALIZED};
    SessionData session_;
    std::chrono::system_clock::time_point nextRetryAt_{};
    std::string lastError_;
    std::string userActionHint_;
    std::chrono::seconds currentAttestBackoff_{0};
    uint64_t nextSessionId_ = 1;

    // ------------------------------------------------------------------
    // Published snapshot (atomic shared_ptr for lock-free readers)
    // ------------------------------------------------------------------
    mutable std::mutex snapshotMutex_;
    std::shared_ptr<const Snapshot> publishedSnapshot_;
    uint64_t snapshotSeq_ = 0;
};

// ============================================================================
// Production environment implementation
// ============================================================================

class CWallet;
struct NodeContext;

/**
 * Concrete IRegistrationEnv backed by the live node subsystems.
 * Takes raw references; assumes the referenced objects outlive this env
 * (node lifecycle). Constructed once during mining init.
 */
class CProductionRegistrationEnv : public IRegistrationEnv {
public:
    CProductionRegistrationEnv(CWallet& wallet,
                               NodeContext& nodeContext,
                               const std::string& datadir,
                               int registrationPowBits,
                               int dnaCommitmentActivationHeight,
                               int seedAttestationActivationHeight);

    // IRegistrationEnv
    bool GetMIKPubKey(std::vector<uint8_t>& out) override;
    bool GetMIKIdentity(DFMP::Identity& out) override;
    bool HasMIKRegistered(const DFMP::Identity& identity) const override;
    bool TryGetDNAHash(std::array<uint8_t, 32>& out) override;
    bool CollectAttestations(const std::vector<uint8_t>& pubkey,
                             const std::array<uint8_t, 32>& dnaHash,
                             Attestation::CAttestationSet& out,
                             std::string& errOut) override;
    bool IsAttestationFreshEnough(const Attestation::CAttestationSet& attest,
                                  int64_t nowSec) const override;
    bool MineRegistrationPoW(const std::vector<uint8_t>& pubkey,
                             int bits,
                             const std::array<uint8_t, 32>& dnaHash,
                             uint64_t& outNonce,
                             const std::atomic<bool>& running) override;
    bool SaveRegistration(const std::vector<uint8_t>& pubkey,
                          const std::array<uint8_t, 32>& dnaHash,
                          uint64_t nonce,
                          int64_t timestamp) override;
    DFMP::MIKRegFileLoadResult LoadRegistration(const std::vector<uint8_t>& pubkey,
                                                DFMP::MIKRegistrationFile& out) override;
    void DeletePersistedRegistration() override;
    int RegistrationPowBits() const override { return registrationPowBits_; }
    int DNACommitmentActivationHeight() const override { return dnaCommitmentActivationHeight_; }
    int SeedAttestationActivationHeight() const override { return seedAttestationActivationHeight_; }
    int64_t NowSeconds() const override;

private:
    CWallet& wallet_;
    NodeContext& nodeContext_;
    std::string datadir_;
    int registrationPowBits_;
    int dnaCommitmentActivationHeight_;
    int seedAttestationActivationHeight_;
};

// ============================================================================
// Helpers (also useful in RPC / debug output)
// ============================================================================

const char* StateToString(CRegistrationManager::State s);
const char* MineGateReasonToString(CRegistrationManager::MineGateReason r);

#endif // DILITHION_NODE_REGISTRATION_MANAGER_H
