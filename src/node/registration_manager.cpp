// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/registration_manager.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

// Production-env dependencies (only pulled in when CProductionRegistrationEnv
// is instantiated; the pure state machine doesn't need any of this).
#include <attestation/seed_attestation.h>
#include <core/chainparams.h>
#include <core/node_context.h>
#include <dfmp/dfmp.h>
#include <dfmp/identity_db.h>
#include <dfmp/mik.h>
#include <dfmp/mik_registration_file.h>
#include <digital_dna/digital_dna.h>
#include <wallet/wallet.h>

// ============================================================================
// Helpers
// ============================================================================

const char* StateToString(CRegistrationManager::State s) {
    using S = CRegistrationManager::State;
    switch (s) {
        case S::UNINITIALIZED:                   return "UNINITIALIZED";
        case S::CHECK_ELIGIBILITY:               return "CHECK_ELIGIBILITY";
        case S::DNA_PENDING:                     return "DNA_PENDING";
        case S::ATTEST_PENDING:                  return "ATTEST_PENDING";
        case S::POW_PENDING:                     return "POW_PENDING";
        case S::READY:                           return "READY";
        case S::SUBMITTED:                       return "SUBMITTED";
        case S::CONFIRMED:                       return "CONFIRMED";
        case S::LONG_BACKOFF_USER_ACTIONABLE:    return "LONG_BACKOFF_USER_ACTIONABLE";
        case S::FAILED_FATAL:                    return "FAILED_FATAL";
        case S::SHUTTING_DOWN:                   return "SHUTTING_DOWN";
        case S::STOPPED:                         return "STOPPED";
    }
    return "UNKNOWN";
}

const char* MineGateReasonToString(CRegistrationManager::MineGateReason r) {
    using R = CRegistrationManager::MineGateReason;
    switch (r) {
        case R::OK_REGISTERED:                        return "registered";
        case R::OK_REGISTRATION_IN_PROGRESS:          return "registration-in-progress";
        case R::BLOCKED_UNINITIALIZED:                return "uninitialized";
        case R::BLOCKED_DNA_PENDING:                  return "collecting DNA";
        case R::BLOCKED_ATTEST_PENDING:               return "collecting attestations";
        case R::BLOCKED_POW_PENDING:                  return "mining registration PoW";
        case R::BLOCKED_RETRYING_SUBMISSION:          return "retrying registration block submission";
        case R::BLOCKED_LONG_BACKOFF_USER_ACTIONABLE: return "waiting on user action";
        case R::BLOCKED_FATAL:                        return "fatal registration error";
        case R::BLOCKED_SHUTTING_DOWN:                return "shutting down";
    }
    return "unknown";
}

// ============================================================================
// Snapshot copy (unique_ptr member requires explicit handling)
// ============================================================================

CRegistrationManager::Snapshot&
CRegistrationManager::Snapshot::operator=(const Snapshot& other) {
    if (this == &other) return *this;
    state = other.state;
    sequence = other.sequence;
    tipHeight = other.tipHeight;
    registrationRequired = other.registrationRequired;
    canBuildRegistrationTemplate = other.canBuildRegistrationTemplate;
    sessionId = other.sessionId;
    mikPubkey = other.mikPubkey;
    dnaHash = other.dnaHash;
    hasDnaHash = other.hasDnaHash;
    hasAttestations = other.hasAttestations;
    regNonce = other.regNonce;
    hasRegNonce = other.hasRegNonce;
    attestations = other.attestations
                       ? std::make_unique<Attestation::CAttestationSet>(*other.attestations)
                       : nullptr;
    submitRetriesUsed = other.submitRetriesUsed;
    submitRetriesMax = other.submitRetriesMax;
    nextRetryAt = other.nextRetryAt;
    lastError = other.lastError;
    userActionHint = other.userActionHint;
    mineGate = other.mineGate;
    return *this;
}

// ============================================================================
// Lifecycle
// ============================================================================

CRegistrationManager::CRegistrationManager(std::shared_ptr<IRegistrationEnv> env)
    : env_(std::move(env)) {
    // Publish initial snapshot so GetSnapshot() never returns null.
    auto snap = std::make_shared<Snapshot>();
    snap->state = State::UNINITIALIZED;
    snap->mineGate = MineGateReason::BLOCKED_UNINITIALIZED;
    {
        std::lock_guard<std::mutex> lk(snapshotMutex_);
        publishedSnapshot_ = snap;
    }
}

CRegistrationManager::~CRegistrationManager() {
    Shutdown();
}

void CRegistrationManager::EnsureWorkerStarted_() {
    // Idempotent — only starts the worker on the first call.
    bool expected = false;
    if (!workerStarted_.compare_exchange_strong(expected, true)) return;
    worker_ = std::thread([this] { WorkerMain_(); });
}

void CRegistrationManager::Shutdown() {
    if (!workerStarted_.load()) {
        // Worker was never started; nothing to clean up.
        return;
    }
    RequestShutdown_();
    if (worker_.joinable()) worker_.join();
}

void CRegistrationManager::RequestShutdown_() {
    shutdownRequested_.store(true);
    powRunning_.store(false);  // cancel any in-flight PoW
    latestNodeRunning_.store(false);
    stateCv_.notify_all();
}

// ============================================================================
// Driver API (thread-safe)
// ============================================================================

void CRegistrationManager::Tick(uint32_t tipHeight, bool nodeRunning) {
    latestTipHeight_.store(tipHeight);
    latestNodeRunning_.store(nodeRunning);
    if (!nodeRunning) RequestShutdown_();
    EnsureWorkerStarted_();
    stateCv_.notify_one();
}

// ============================================================================
// Read-only query API
// ============================================================================

std::shared_ptr<const CRegistrationManager::Snapshot>
CRegistrationManager::GetSnapshot() const {
    std::lock_guard<std::mutex> lk(snapshotMutex_);
    return publishedSnapshot_;
}

bool CRegistrationManager::CanMine(MineGateReason* reasonOut) const {
    auto snap = GetSnapshot();
    if (reasonOut) *reasonOut = snap->mineGate;
    return snap->mineGate == MineGateReason::OK_REGISTERED ||
           snap->mineGate == MineGateReason::OK_REGISTRATION_IN_PROGRESS;
}

CRegistrationManager::StatusForUI CRegistrationManager::GetStatusForUI() const {
    auto snap = GetSnapshot();
    StatusForUI s;
    s.retryUsed = snap->submitRetriesUsed;
    s.retryMax = snap->submitRetriesMax;
    s.actionHint = snap->userActionHint;

    switch (snap->state) {
        case State::UNINITIALIZED:
            s.phase = "INIT"; s.message = "Initializing registration manager"; break;
        case State::CHECK_ELIGIBILITY:
            s.phase = "CHECK"; s.message = "Checking miner registration status"; break;
        case State::DNA_PENDING:
            s.phase = "DNA";
            s.message = "Collecting hardware fingerprint (Digital DNA)";
            s.etaText = "up to 30 min on a fresh node";
            break;
        case State::ATTEST_PENDING:
            s.phase = "ATTEST";
            s.message = "Requesting seed attestations (need 3 of 4)";
            s.etaText = "a few seconds";
            break;
        case State::POW_PENDING:
            s.phase = "POW";
            s.message = "Solving registration proof-of-work";
            s.etaText = "about 15-30 min (CPU dependent)";
            break;
        case State::READY:
            s.phase = "READY"; s.message = "Registration material ready, mining registration block"; break;
        case State::SUBMITTED:
            s.phase = "SUBMITTED"; s.message = "Registration block building/mining"; break;
        case State::CONFIRMED:
            s.phase = "CONFIRMED"; s.message = "Registered — mining normally"; break;
        case State::LONG_BACKOFF_USER_ACTIONABLE:
            s.phase = "BACKOFF";
            s.message = snap->lastError.empty() ? "Waiting on user action" : snap->lastError;
            break;
        case State::FAILED_FATAL:
            s.phase = "FATAL"; s.message = snap->lastError; break;
        case State::SHUTTING_DOWN:
            s.phase = "SHUTDOWN"; s.message = "Shutting down cleanly"; break;
        case State::STOPPED:
            s.phase = "STOPPED"; s.message = "Registration manager stopped"; break;
    }
    return s;
}

void CRegistrationManager::ForceRestart(const std::string& why) {
    std::lock_guard<std::mutex> lk(stateMutex_);
    AbandonSession_(std::string("ForceRestart: ") + why, /*persistNothing=*/true);
    EnterState_(State::CHECK_ELIGIBILITY);
    PublishSnapshot_();
    stateCv_.notify_all();
}

void CRegistrationManager::NotifyBlockRejected(const std::string& reason) {
    std::lock_guard<std::mutex> lk(stateMutex_);
    Transition_(Event::SUBMIT_TIMEOUT_OR_REJECTED, reason);
    PublishSnapshot_();
    stateCv_.notify_all();
}

// ============================================================================
// Test hooks
// ============================================================================

CRegistrationManager::State CRegistrationManager::TestingStepWorkerOnce() {
    std::unique_lock<std::mutex> lk(stateMutex_);
    WorkerIterationLocked_(lk);
    return state_;
}

void CRegistrationManager::TestingInjectEvent(Event ev, const std::string& detail) {
    std::lock_guard<std::mutex> lk(stateMutex_);
    Transition_(ev, detail);
    PublishSnapshot_();
}

// ============================================================================
// Worker main loop
// ============================================================================

void CRegistrationManager::WorkerMain_() {
    std::unique_lock<std::mutex> lk(stateMutex_);

    // Initial transition: UNINITIALIZED -> CHECK_ELIGIBILITY
    Transition_(Event::STARTUP);
    PublishSnapshot_();

    while (!shutdownRequested_.load()) {
        // If we have a scheduled retry, sleep until then or until woken.
        auto now = std::chrono::system_clock::now();
        if (nextRetryAt_ > now) {
            stateCv_.wait_until(lk, nextRetryAt_, [this] {
                return shutdownRequested_.load();
            });
            if (shutdownRequested_.load()) break;
            now = std::chrono::system_clock::now();
            if (nextRetryAt_ > now) continue; // spurious wake
            nextRetryAt_ = {};
        }

        // Dispatch to appropriate handler. Handlers may release/re-acquire
        // the lock for long-running ops.
        WorkerIterationLocked_(lk);

        // If we have no scheduled retry and no pending transition,
        // wait for the next Tick() to wake us.
        if (nextRetryAt_ == std::chrono::system_clock::time_point{}) {
            // No timed work. Wait for Tick() or shutdown.
            // But only wait if we're in a terminal-for-now state.
            if (state_ == State::CONFIRMED ||
                state_ == State::READY ||
                state_ == State::SUBMITTED ||
                state_ == State::LONG_BACKOFF_USER_ACTIONABLE ||
                state_ == State::FAILED_FATAL ||
                state_ == State::DNA_PENDING) {
                stateCv_.wait_for(lk, std::chrono::seconds(1), [this] {
                    return shutdownRequested_.load();
                });
            }
        }
    }

    // Clean shutdown: abandon any in-progress session, no partial persistence.
    Transition_(Event::SHUTDOWN_REQUESTED);
    AbandonSession_("shutdown", /*persistNothing=*/true);
    EnterState_(State::STOPPED);
    Transition_(Event::WORKER_STOPPED);
    PublishSnapshot_();
}

void CRegistrationManager::WorkerIterationLocked_(std::unique_lock<std::mutex>& /*lk*/) {
    switch (state_) {
        case State::UNINITIALIZED:
        case State::CHECK_ELIGIBILITY:           HandleCheckEligibility_(); break;
        case State::DNA_PENDING:                 HandleDnaPending_(); break;
        case State::ATTEST_PENDING:              HandleAttestPending_(); break;
        case State::POW_PENDING:                 HandlePowPending_(); break;
        case State::READY:                       HandleReady_(); break;
        case State::SUBMITTED:                   HandleSubmitted_(); break;
        case State::CONFIRMED:                   HandleConfirmed_(); break;
        case State::LONG_BACKOFF_USER_ACTIONABLE: HandleLongBackoff_(); break;
        case State::FAILED_FATAL:                break; // terminal; wait for Shutdown or ForceRestart
        case State::SHUTTING_DOWN:               break;
        case State::STOPPED:                     break;
    }
    PublishSnapshot_();
}

// ============================================================================
// State handlers (worker thread only; stateMutex_ is held on entry/exit)
// ============================================================================

void CRegistrationManager::HandleCheckEligibility_() {
    // Need MIK pubkey + identity to proceed.
    std::vector<uint8_t> pubkey;
    DFMP::Identity identity;
    if (!env_->GetMIKPubKey(pubkey) || !env_->GetMIKIdentity(identity) ||
        identity.IsNull()) {
        OnUserActionRequired_(
            "Wallet locked or MIK not yet generated",
            "Unlock the wallet; mining will resume automatically.",
            userActionBackoff_);
        return;
    }

    // Already registered on the canonical chain?
    if (env_->HasMIKRegistered(identity)) {
        // Fast path — nothing to do.
        session_.mikPubkey = pubkey;
        session_.mikIdentity = identity;
        EnterState_(State::CONFIRMED);
        Transition_(Event::REGISTRATION_SEEN_ONCHAIN);
        return;
    }

    // Start a fresh session.
    StartNewSession_(latestTipHeight_.load());
    session_.mikPubkey = pubkey;
    session_.mikIdentity = identity;

    // Can we short-circuit with a valid persisted nonce?
    if (TryRestorePersistedNonce_()) {
        // Still need fresh attestations (expire after 1h) before submitting.
        EnterState_(State::ATTEST_PENDING);
        return;
    }

    // Normal path: collect DNA first.
    EnterState_(State::DNA_PENDING);
}

void CRegistrationManager::HandleDnaPending_() {
    session_.dnaPolls++;
    std::array<uint8_t, 32> hash{};
    if (env_->TryGetDNAHash(hash)) {
        // Verify non-zero (defense in depth against env returning a cleared array).
        bool allZero = std::all_of(hash.begin(), hash.end(),
                                   [](uint8_t b) { return b == 0; });
        if (!allZero) {
            session_.dnaHash = hash;
            session_.hasDnaHash = true;
            Transition_(Event::DNA_READY);
            EnterState_(State::ATTEST_PENDING);
            return;
        }
    }
    // Not ready yet — wake again in dnaPollInterval_.
    nextRetryAt_ = std::chrono::system_clock::now() + dnaPollInterval_;
}

void CRegistrationManager::HandleAttestPending_() {
    if (!session_.hasDnaHash) {
        // Sanity: should never happen per transition rules.
        OnFatalError_("ATTEST_PENDING without DNA hash — invariant violated");
        return;
    }

    // Snapshot inputs so the long-running RPC runs without holding state.
    std::vector<uint8_t> pubkey = session_.mikPubkey;
    std::array<uint8_t, 32> dnaHash = session_.dnaHash;
    uint64_t sessionId = session_.sessionId;

    stateMutex_.unlock();
    Attestation::CAttestationSet fresh;
    std::string err;
    bool ok = env_->CollectAttestations(pubkey, dnaHash, fresh, err);
    stateMutex_.lock();

    // Session may have been abandoned while the lock was released (reorg,
    // DNA change, shutdown). Discard stale results.
    if (session_.sessionId != sessionId || shutdownRequested_.load()) return;

    if (ok) {
        session_.attestations =
            std::make_unique<Attestation::CAttestationSet>(std::move(fresh));
        session_.hasValidAttestations = true;
        session_.attestationRetries = 0;
        currentAttestBackoff_ = std::chrono::seconds(0);
        Transition_(Event::ATTEST_READY);
        EnterState_(State::POW_PENDING);
        return;
    }

    // Transient failure — exponential backoff up to maxAttestationRetries_.
    session_.attestationRetries++;
    if (session_.attestationRetries >= maxAttestationRetries_) {
        OnUserActionRequired_(
            "Could not reach enough seed nodes (" + err + ")",
            "Check firewall/router for outbound TCP to seed nodes.",
            userActionBackoff_);
        return;
    }
    currentAttestBackoff_ = currentAttestBackoff_.count() == 0
        ? attestInitialBackoff_
        : std::chrono::seconds(std::min<int64_t>(currentAttestBackoff_.count() * 2,
                                                 attestMaxBackoff_.count()));
    OnTransientError_("Attestation RPC failed: " + err, currentAttestBackoff_);
}

void CRegistrationManager::HandlePowPending_() {
    if (!session_.hasDnaHash) {
        OnFatalError_("POW_PENDING without DNA hash — invariant violated");
        return;
    }

    // Snapshot inputs; release state lock for the ~15-30 min PoW.
    std::vector<uint8_t> pubkey = session_.mikPubkey;
    std::array<uint8_t, 32> dnaHash = session_.dnaHash;
    uint64_t sessionId = session_.sessionId;
    int bits = env_->RegistrationPowBits();

    powRunning_.store(true);
    stateMutex_.unlock();
    uint64_t nonce = 0;
    bool ok = env_->MineRegistrationPoW(pubkey, bits, dnaHash, nonce, powRunning_);
    stateMutex_.lock();

    if (session_.sessionId != sessionId || shutdownRequested_.load()) {
        // Session abandoned (reorg, shutdown, FORCE_RESTART). Do NOT persist.
        return;
    }

    if (ok) {
        session_.regNonce = nonce;
        session_.hasRegNonce = true;
        // Persist only once we have a fully coherent (pubkey, dna, nonce).
        if (!PersistSolvedNonceAtomically_()) {
            // Persistence failed — not fatal; we keep the in-memory nonce and
            // just log. Worst case, a restart redoes the PoW.
            lastError_ = "Failed to persist registration PoW to disk (non-fatal)";
        }
        Transition_(Event::POW_READY);
        EnterState_(State::READY);
    } else {
        // Either shutdown cancelled us (handled above) or PoW genuinely failed.
        OnTransientError_("Registration PoW failed", std::chrono::seconds(5));
    }
}

void CRegistrationManager::HandleReady_() {
    // READY is a quiescent state. The VDF miner reads our snapshot and mines
    // a registration template, then submits the block. We detect on-chain
    // registration by polling the identity DB — when our MIK appears there,
    // we transition to CONFIRMED. This matches the reorg-detection poll that
    // HandleConfirmed_ does, and avoids needing an external
    // REGISTRATION_SEEN_ONCHAIN event emission from the block pipeline.
    if (!session_.mikIdentity.IsNull() &&
        env_->HasMIKRegistered(session_.mikIdentity)) {
        lastError_.clear();
        userActionHint_.clear();
        EnterState_(State::CONFIRMED);
        return;
    }

    // Check that attestations are still fresh. If they're about to expire,
    // proactively refresh so the next registration block doesn't get rejected.
    if (session_.attestations && !env_->IsAttestationFreshEnough(
            *session_.attestations, env_->NowSeconds())) {
        session_.hasValidAttestations = false;
        session_.attestations.reset();
        EnterState_(State::ATTEST_PENDING);
        return;
    }
    // Nothing to do right now — snooze until the next Tick() or event.
    // (Worker main loop sleeps us back into the cv_wait.)
}

void CRegistrationManager::HandleSubmitted_() {
    // Same as READY for now — we're waiting for the chain to confirm us.
    // The submission retry machinery is driven by external events
    // (SUBMIT_TIMEOUT_OR_REJECTED / REGISTRATION_SEEN_ONCHAIN) from the
    // block submission pipeline.
    HandleReady_();
}

void CRegistrationManager::HandleConfirmed_() {
    // Quiescent. Wait for a TIP_UPDATED event that might indicate a reorg
    // has pulled the registration out of the canonical chain.
    if (!session_.mikIdentity.IsNull() &&
        !env_->HasMIKRegistered(session_.mikIdentity)) {
        // Reorg — we're no longer registered on the canonical chain.
        InvalidateSessionForReorg_();
        EnterState_(State::CHECK_ELIGIBILITY);
        Transition_(Event::REGISTRATION_MISSING_ONCHAIN);
    }
}

void CRegistrationManager::HandleLongBackoff_() {
    // Just waiting for nextRetryAt_ to elapse. When it does, the main loop
    // will call us again and we'll transition back to CHECK_ELIGIBILITY.
    if (std::chrono::system_clock::now() >= nextRetryAt_) {
        EnterState_(State::CHECK_ELIGIBILITY);
        nextRetryAt_ = {};
    }
}

// ============================================================================
// Event + state transitions
// ============================================================================

void CRegistrationManager::Transition_(Event ev, const std::string& detail) {
    // The vast majority of state changes happen via EnterState_. Transition_
    // exists to capture named events for logging and to gate certain
    // conditional transitions. Most handlers call EnterState_ directly; this
    // function is used mainly for events that come from OUTSIDE the worker
    // thread (REGISTRATION_SEEN_ONCHAIN, SUBMIT_TIMEOUT_OR_REJECTED etc.)
    // or from state handlers for bookkeeping.
    switch (ev) {
        case Event::REGISTRATION_MISSING_ONCHAIN:
            if (state_ == State::CONFIRMED ||
                state_ == State::READY ||
                state_ == State::SUBMITTED) {
                InvalidateSessionForReorg_();
                EnterState_(State::CHECK_ELIGIBILITY);
            }
            break;
        case Event::REGISTRATION_SEEN_ONCHAIN:
            EnterState_(State::CONFIRMED);
            lastError_.clear();
            userActionHint_.clear();
            break;
        case Event::TEMPLATE_BUILT_AND_MINER_STARTED:
            if (state_ == State::READY) EnterState_(State::SUBMITTED);
            break;
        case Event::SUBMIT_TIMEOUT_OR_REJECTED: {
            // v4.0.18: production flow reaches READY and stays there — we
            // poll HasMIKRegistered() instead of emitting
            // TEMPLATE_BUILT_AND_MINER_STARTED + REGISTRATION_SEEN_ONCHAIN.
            // So this event must also be accepted from READY, otherwise the
            // submit retry budget is unreachable in practice. SUBMITTED is
            // still valid for test cases that drive the original flow.
            if (state_ != State::SUBMITTED && state_ != State::READY) break;
            session_.submitRetries++;
            if (session_.submitRetries >= maxSubmitRetries_) {
                Transition_(Event::SUBMIT_RETRY_BUDGET_EXHAUSTED);
                break;
            }
            // Decide which state to fall back to based on attestation freshness.
            bool attestFresh = session_.attestations &&
                env_->IsAttestationFreshEnough(*session_.attestations, env_->NowSeconds());
            EnterState_(attestFresh ? State::READY : State::ATTEST_PENDING);
            if (!attestFresh) session_.attestations.reset();
            nextRetryAt_ = std::chrono::system_clock::now() + submitRetryBackoff_;
            break;
        }
        case Event::SUBMIT_RETRY_BUDGET_EXHAUSTED:
            OnUserActionRequired_(
                "Registration block submission failed " + std::to_string(maxSubmitRetries_) + " times",
                "Check logs for rejection reason.",
                userActionBackoff_);
            break;
        case Event::FORCE_RESTART:
            AbandonSession_("force-restart: " + detail, /*persistNothing=*/true);
            EnterState_(State::CHECK_ELIGIBILITY);
            break;
        case Event::UNRECOVERABLE_ERROR:
            OnFatalError_(detail);
            break;
        case Event::SHUTDOWN_REQUESTED:
            EnterState_(State::SHUTTING_DOWN);
            break;
        case Event::WORKER_STOPPED:
            EnterState_(State::STOPPED);
            break;
        case Event::STARTUP:
            if (state_ == State::UNINITIALIZED) {
                EnterState_(State::CHECK_ELIGIBILITY);
            }
            break;
        // Event-only markers (no transition, used for logging)
        case Event::TIP_UPDATED:
        case Event::SESSION_STARTED:
        case Event::DNA_READY:
        case Event::ATTEST_READY:
        case Event::POW_READY:
        case Event::TRANSIENT_ERROR:
        case Event::USER_ACTION_REQUIRED:
            break;
    }
}

void CRegistrationManager::EnterState_(State s) {
    if (state_ == s) return;
    state_ = s;
    // Clear retry timer when transitioning to a non-backoff state.
    if (s != State::LONG_BACKOFF_USER_ACTIONABLE &&
        s != State::SHUTTING_DOWN &&
        s != State::STOPPED) {
        // Leave nextRetryAt_ as-is for DNA_PENDING polls etc.; handlers set it.
    }
}

// ============================================================================
// Snapshot publishing
// ============================================================================

void CRegistrationManager::PublishSnapshot_() {
    auto snap = std::make_shared<Snapshot>();
    snap->state = state_;
    snap->sequence = ++snapshotSeq_;
    snap->tipHeight = latestTipHeight_.load();
    snap->registrationRequired = (state_ != State::CONFIRMED);
    snap->canBuildRegistrationTemplate = (state_ == State::READY ||
                                           state_ == State::SUBMITTED);
    snap->sessionId = session_.sessionId;
    snap->mikPubkey = session_.mikPubkey;
    snap->dnaHash = session_.dnaHash;
    snap->hasDnaHash = session_.hasDnaHash;
    snap->hasAttestations = session_.hasValidAttestations;
    snap->regNonce = session_.regNonce;
    snap->hasRegNonce = session_.hasRegNonce;
    if (session_.attestations) {
        snap->attestations =
            std::make_unique<Attestation::CAttestationSet>(*session_.attestations);
    }
    snap->submitRetriesUsed = session_.submitRetries;
    snap->submitRetriesMax = maxSubmitRetries_;
    snap->nextRetryAt = nextRetryAt_;
    snap->lastError = lastError_;
    snap->userActionHint = userActionHint_;

    // Mine-gate decision
    switch (state_) {
        case State::CONFIRMED:                snap->mineGate = MineGateReason::OK_REGISTERED; break;
        case State::READY:
        case State::SUBMITTED:                snap->mineGate = MineGateReason::OK_REGISTRATION_IN_PROGRESS; break;
        case State::UNINITIALIZED:            snap->mineGate = MineGateReason::BLOCKED_UNINITIALIZED; break;
        case State::CHECK_ELIGIBILITY:
        case State::DNA_PENDING:              snap->mineGate = MineGateReason::BLOCKED_DNA_PENDING; break;
        case State::ATTEST_PENDING:           snap->mineGate = MineGateReason::BLOCKED_ATTEST_PENDING; break;
        case State::POW_PENDING:              snap->mineGate = MineGateReason::BLOCKED_POW_PENDING; break;
        case State::LONG_BACKOFF_USER_ACTIONABLE:
            snap->mineGate = MineGateReason::BLOCKED_LONG_BACKOFF_USER_ACTIONABLE; break;
        case State::FAILED_FATAL:             snap->mineGate = MineGateReason::BLOCKED_FATAL; break;
        case State::SHUTTING_DOWN:
        case State::STOPPED:                  snap->mineGate = MineGateReason::BLOCKED_SHUTTING_DOWN; break;
    }

    {
        std::lock_guard<std::mutex> lk(snapshotMutex_);
        publishedSnapshot_ = snap;
    }
}

// ============================================================================
// Session management
// ============================================================================

void CRegistrationManager::StartNewSession_(uint32_t tipHeight) {
    session_ = SessionData{};
    session_.sessionId = nextSessionId_++;
    session_.startHeight = tipHeight;
    currentAttestBackoff_ = std::chrono::seconds(0);
    lastError_.clear();
    userActionHint_.clear();
}

void CRegistrationManager::AbandonSession_(const std::string& reason,
                                           bool persistNothing) {
    if (session_.sessionId == 0) return; // no session active
    if (!reason.empty()) lastError_ = reason;
    if (persistNothing) {
        // Intentional: do NOT call PersistSolvedNonceAtomically_ here.
        // Partial sessions must never poison the mik_registration.dat file.
    }
    session_ = SessionData{};
    powRunning_.store(false);  // cancel any in-flight PoW for this session
}

void CRegistrationManager::InvalidateSessionForReorg_() {
    AbandonSession_("registration reorged out of canonical chain",
                    /*persistNothing=*/true);
    // On the next CHECK_ELIGIBILITY, we may also want to delete the stale
    // persisted file since its nonce corresponds to a now-stale chain
    // history. But the file is keyed by (pubkey, dnaHash), not height, so
    // it's still cryptographically valid — leave it, it may be reusable.
}

bool CRegistrationManager::ValidateSessionCoherence_() const {
    if (session_.sessionId == 0) return false;
    if (session_.mikPubkey.empty()) return false;
    if (session_.hasRegNonce && !session_.hasDnaHash) return false;
    if (session_.hasValidAttestations && !session_.hasDnaHash) return false;
    return true;
}

// ============================================================================
// Persistence (with zero-DNA safety)
// ============================================================================

bool CRegistrationManager::TryRestorePersistedNonce_() {
    if (session_.mikPubkey.empty()) return false;
    DFMP::MIKRegistrationFile rec;
    auto res = env_->LoadRegistration(session_.mikPubkey, rec);
    if (res != DFMP::MIKRegFileLoadResult::OK) {
        if (res == DFMP::MIKRegFileLoadResult::Corrupt ||
            res == DFMP::MIKRegFileLoadResult::PubkeyMismatch) {
            // Best-effort cleanup; LoadMIKRegistration has already renamed
            // the file to .corrupt/.stale on these paths.
        }
        return false;
    }

    // Poisoned-file check: refuse to load a zero-DNA record.
    bool allZero = std::all_of(rec.dnaHash.begin(), rec.dnaHash.end(),
                               [](uint8_t b) { return b == 0; });
    if (allZero) {
        env_->DeletePersistedRegistration();
        lastError_ = "Deleted poisoned mik_registration.dat (zero DNA hash)";
        return false;
    }

    session_.dnaHash = rec.dnaHash;
    session_.hasDnaHash = true;
    session_.regNonce = rec.nonce;
    session_.hasRegNonce = true;
    return true;
}

bool CRegistrationManager::PersistSolvedNonceAtomically_() {
    if (!session_.hasDnaHash || !session_.hasRegNonce ||
        session_.mikPubkey.empty()) {
        return false;
    }
    // Second-line defense: never write a zero-DNA record.
    bool allZero = std::all_of(session_.dnaHash.begin(), session_.dnaHash.end(),
                               [](uint8_t b) { return b == 0; });
    if (allZero) return false;
    return env_->SaveRegistration(session_.mikPubkey,
                                   session_.dnaHash,
                                   session_.regNonce,
                                   env_->NowSeconds());
}

void CRegistrationManager::ClearPersistedNonceIfStale_() {
    env_->DeletePersistedRegistration();
}

// ============================================================================
// Error / backoff helpers
// ============================================================================

void CRegistrationManager::OnTransientError_(const std::string& err,
                                             std::chrono::seconds backoff) {
    lastError_ = err;
    nextRetryAt_ = std::chrono::system_clock::now() + backoff;
}

void CRegistrationManager::OnUserActionRequired_(const std::string& err,
                                                  const std::string& hint,
                                                  std::chrono::minutes backoff) {
    lastError_ = err;
    userActionHint_ = hint;
    nextRetryAt_ = std::chrono::system_clock::now() + backoff;
    EnterState_(State::LONG_BACKOFF_USER_ACTIONABLE);
}

void CRegistrationManager::OnFatalError_(const std::string& err) {
    lastError_ = err;
    EnterState_(State::FAILED_FATAL);
}

// ============================================================================
// CProductionRegistrationEnv — wraps the live node subsystems
// ============================================================================

CProductionRegistrationEnv::CProductionRegistrationEnv(
    CWallet& wallet,
    NodeContext& nodeContext,
    const std::string& datadir,
    int registrationPowBits,
    int dnaCommitmentActivationHeight,
    int seedAttestationActivationHeight)
    : wallet_(wallet),
      nodeContext_(nodeContext),
      datadir_(datadir),
      registrationPowBits_(registrationPowBits),
      dnaCommitmentActivationHeight_(dnaCommitmentActivationHeight),
      seedAttestationActivationHeight_(seedAttestationActivationHeight) {}

bool CProductionRegistrationEnv::GetMIKPubKey(std::vector<uint8_t>& out) {
    if (!wallet_.HasMIK()) return false;
    return wallet_.GetMIKPubKey(out);
}

bool CProductionRegistrationEnv::GetMIKIdentity(DFMP::Identity& out) {
    if (!wallet_.HasMIK()) return false;
    out = wallet_.GetMIKIdentity();
    return !out.IsNull();
}

bool CProductionRegistrationEnv::HasMIKRegistered(
    const DFMP::Identity& identity) const {
    if (!DFMP::g_identityDb) return false;
    return DFMP::g_identityDb->HasMIKPubKey(identity);
}

bool CProductionRegistrationEnv::TryGetDNAHash(std::array<uint8_t, 32>& out) {
    auto collector = nodeContext_.GetDNACollector();
    if (!collector) return false;
    auto dna = collector->get_dna();
    if (!dna) return false;
    out = dna->hash();
    return true;
}

bool CProductionRegistrationEnv::CollectAttestations(
    const std::vector<uint8_t>& pubkey,
    const std::array<uint8_t, 32>& dnaHash,
    Attestation::CAttestationSet& out,
    std::string& errOut) {
    if (!Dilithion::g_chainParams ||
        Dilithion::g_chainParams->seedAttestationIPs.empty()) {
        errOut = "no seed attestation IPs configured";
        return false;
    }
    std::string mikHex = /* HexStr(pubkey) */ [&pubkey] {
        static const char* const hex = "0123456789abcdef";
        std::string s; s.reserve(pubkey.size() * 2);
        for (uint8_t b : pubkey) { s.push_back(hex[b >> 4]); s.push_back(hex[b & 0xF]); }
        return s;
    }();
    std::string dnaHex = [&dnaHash] {
        static const char* const hex = "0123456789abcdef";
        std::string s; s.reserve(64);
        for (uint8_t b : dnaHash) { s.push_back(hex[b >> 4]); s.push_back(hex[b & 0xF]); }
        return s;
    }();
    return Attestation::CollectAttestations(
        Dilithion::g_chainParams->seedAttestationIPs,
        Dilithion::g_chainParams->seedAttestationRPCPort,
        mikHex, dnaHex, out, errOut);
}

bool CProductionRegistrationEnv::IsAttestationFreshEnough(
    const Attestation::CAttestationSet& attest,
    int64_t nowSec) const {
    if (attest.attestations.empty()) return false;
    int64_t age = nowSec - static_cast<int64_t>(attest.attestations[0].timestamp);
    // Refresh within 10 minutes of expiry.
    return age < (Attestation::ATTESTATION_VALIDITY_WINDOW - 600);
}

bool CProductionRegistrationEnv::MineRegistrationPoW(
    const std::vector<uint8_t>& pubkey,
    int bits,
    const std::array<uint8_t, 32>& dnaHash,
    uint64_t& outNonce,
    const std::atomic<bool>& running) {
    // DFMP API takes a non-const pointer to const atomic<bool>; our signature
    // is const ref for clean ownership. It reads only; cast is safe.
    auto* runningPtr = const_cast<std::atomic<bool>*>(&running);
    return DFMP::MineRegistrationPoW(pubkey, bits, outNonce, runningPtr, &dnaHash);
}

bool CProductionRegistrationEnv::SaveRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::array<uint8_t, 32>& dnaHash,
    uint64_t nonce,
    int64_t timestamp) {
    return DFMP::SaveMIKRegistration(datadir_, pubkey, dnaHash, nonce, timestamp);
}

DFMP::MIKRegFileLoadResult CProductionRegistrationEnv::LoadRegistration(
    const std::vector<uint8_t>& pubkey,
    DFMP::MIKRegistrationFile& out) {
    return DFMP::LoadMIKRegistration(datadir_, pubkey, out);
}

void CProductionRegistrationEnv::DeletePersistedRegistration() {
    // Best-effort: remove the canonical file path.
    try {
        std::filesystem::remove(
            std::filesystem::path(datadir_) / DFMP::MIK_REGISTRATION_FILENAME);
    } catch (...) {
        // Ignore — file may not exist.
    }
}

int64_t CProductionRegistrationEnv::NowSeconds() const {
    return static_cast<int64_t>(std::time(nullptr));
}
