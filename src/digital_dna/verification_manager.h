// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_VERIFICATION_MANAGER_H
#define DILITHION_VERIFICATION_MANAGER_H

#include <digital_dna/dna_verification.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <vector>

// Forward declarations
namespace digital_dna {
    class DNARegistryDB;
    class TrustScoreManager;
}

namespace digital_dna {
namespace verification {

/**
 * VerificationManager — Phase 2 DNA Verification & Attestation
 *
 * Manages the lifecycle of DNA verifications:
 * 1. Detects new DNA registrations and determines if this node is a selected verifier
 * 2. Sends VDF challenges to targets (as verifier)
 * 3. Responds to VDF challenges (as target)
 * 4. Creates and signs attestations from measurement results
 * 5. Validates and stores attestations from other verifiers
 * 6. Updates verification status when quorum is reached
 */
class VerificationManager {
public:
    // Callback types for sending P2P messages
    using SendMessageFn = std::function<void(int peer_id, const std::vector<uint8_t>& data)>;
    using BroadcastMessageFn = std::function<void(const std::vector<uint8_t>& data)>;
    using FindPeerByMikFn = std::function<int(const std::array<uint8_t, 20>& mik)>;

    VerificationManager(DNARegistryDB* registry, TrustScoreManager* trust);

    // --- Configuration ---

    /** Set this node's MIK identity (required for signing attestations) */
    void SetMyMIK(const std::array<uint8_t, 20>& mik,
                  const std::vector<uint8_t>& pubkey,
                  const void* privkey_ptr);  // CMiningIdentityKey* (avoid header dep)

    /** Set message sending callbacks */
    void SetSendChallenge(SendMessageFn fn) { send_challenge_ = std::move(fn); }
    void SetSendResponse(SendMessageFn fn) { send_response_ = std::move(fn); }
    void SetBroadcastAttestation(BroadcastMessageFn fn) { broadcast_attestation_ = std::move(fn); }
    void SetFindPeerByMik(FindPeerByMikFn fn) { find_peer_by_mik_ = std::move(fn); }

    // --- Event handlers (called from P2P layer) ---

    /**
     * Called when a new DNA registration is confirmed in a block.
     * Checks if this node is a selected verifier and initiates verification if so.
     */
    void OnNewRegistration(const std::array<uint8_t, 20>& target_mik,
                           uint32_t reg_height,
                           const std::array<uint8_t, 32>& block_hash);

    /** Handle incoming verification challenge (we are the target) */
    void OnChallengeReceived(int peer_id, const std::vector<uint8_t>& data);

    /** Handle incoming verification response (we are the verifier) */
    void OnResponseReceived(int peer_id, const std::vector<uint8_t>& data);

    /** Handle incoming attestation broadcast */
    void OnAttestationReceived(int peer_id, const std::vector<uint8_t>& data);

    // --- Periodic maintenance ---

    /** Called periodically to handle timeouts and queued verifications */
    void Tick(uint32_t current_height);

    // --- Queries ---

    /** Get verification status for a MIK */
    VerificationStatus GetStatus(const std::array<uint8_t, 20>& mik) const;

    /** Get all attestations for a MIK */
    std::vector<DNAAttestation> GetAttestations(const std::array<uint8_t, 20>& mik) const;

    /** Check if this node is a selected verifier for a target */
    bool IsVerifierFor(const std::array<uint8_t, 20>& target_mik,
                       const std::array<uint8_t, 32>& block_hash) const;

    /** Get count of pending verifications */
    size_t PendingCount() const;

private:
    DNARegistryDB* registry_;
    TrustScoreManager* trust_;

    // This node's MIK identity
    std::array<uint8_t, 20> my_mik_{};
    std::vector<uint8_t> my_pubkey_;
    const void* my_mik_key_{nullptr};  // CMiningIdentityKey* for signing
    bool has_mik_{false};

    // P2P callbacks
    SendMessageFn send_challenge_;
    SendMessageFn send_response_;
    BroadcastMessageFn broadcast_attestation_;
    FindPeerByMikFn find_peer_by_mik_;

    // State machine for pending verifications (as verifier)
    struct PendingVerification {
        std::array<uint8_t, 20> target_mik;
        uint32_t registration_height;
        std::array<uint8_t, 32> block_hash;
        std::array<uint8_t, 32> vdf_seed;
        uint64_t nonce;
        int peer_id;
        int64_t challenge_sent_time;

        enum State { WAITING_VDF, COMPLETE };
        State state = WAITING_VDF;

        // Collected measurements
        double measured_vdf_iters_per_sec = 0.0;
        bool vdf_proof_valid = false;
        double claimed_vdf_iters_per_sec = 0.0;
    };
    mutable std::mutex mutex_;
    std::map<uint64_t, PendingVerification> pending_;  // nonce → state

    // Rate limiting: (my_mik, target_mik) → last verification time
    std::map<std::pair<std::array<uint8_t,20>, std::array<uint8_t,20>>, int64_t> last_verification_time_;
    std::atomic<int> active_verifications_{0};

    // Queue for verifications waiting for a free slot
    struct QueuedVerification {
        std::array<uint8_t, 20> target_mik;
        uint32_t registration_height;
        std::array<uint8_t, 32> block_hash;
    };
    std::vector<QueuedVerification> queued_;

    // --- Internal helpers ---

    /** Generate a random nonce */
    static uint64_t RandomNonce();

    /** Compute VDF seed for a challenge */
    static std::array<uint8_t, 32> ComputeVDFSeed(
        const std::array<uint8_t, 32>& block_hash,
        const std::array<uint8_t, 20>& verifier_mik,
        const std::array<uint8_t, 20>& target_mik);

    /** Check if rate-limited for this (verifier, target) pair */
    bool IsRateLimited(const std::array<uint8_t, 20>& target_mik) const;

    /** Send a VDF challenge to the target */
    void SendVDFChallenge(const PendingVerification& pv);

    /** Create and broadcast attestation from completed verification */
    void FinalizeAttestation(PendingVerification& pv);

    /** Update verification status after receiving a new attestation */
    void UpdateVerificationStatus(const std::array<uint8_t, 20>& target_mik);
};

} // namespace verification
} // namespace digital_dna

#endif // DILITHION_VERIFICATION_MANAGER_H
