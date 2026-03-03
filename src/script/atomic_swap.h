// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_SCRIPT_ATOMIC_SWAP_H
#define DILITHION_SCRIPT_ATOMIC_SWAP_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <amount.h>

/**
 * Cross-chain atomic swap state machine.
 *
 * Implements the HTLC-based atomic swap protocol:
 *   Initiator: generates preimage, creates HTLC on our chain
 *   Responder: sees initiator's HTLC, creates matching HTLC on our chain
 *   Claim:     initiator reveals preimage to claim responder's HTLC
 *   Complete:  responder uses revealed preimage to claim initiator's HTLC
 */

enum class SwapRole {
    INITIATOR = 0,   // Created the swap, holds the preimage
    RESPONDER = 1    // Accepted the swap, matching the hash_lock
};

enum class SwapState {
    CREATED           = 0,  // Preimage generated, HTLC not yet broadcast
    HTLC_FUNDED       = 1,  // Our HTLC is on-chain
    COUNTERPARTY_FUNDED = 2,  // Their HTLC is on-chain
    CLAIMED           = 3,  // We claimed their HTLC (preimage revealed)
    COMPLETED         = 4,  // Both sides claimed
    REFUNDED          = 5,  // Timeout expired, funds refunded
    EXPIRED           = 6   // Swap abandoned
};

struct SwapInfo {
    std::string swap_id;             // Unique identifier (hex, 32 chars)
    SwapRole role;                   // Our role in this swap
    SwapState state;                 // Current swap state

    // Our side
    std::string our_chain;           // "dilv" or "dil"
    CAmount our_amount;              // Amount we locked (in smallest unit)
    std::string our_htlc_txid;       // Our HTLC transaction ID
    uint32_t our_timeout;            // Our refund timeout (absolute block height)

    // Their side
    std::string their_chain;         // "dilv" or "dil"
    CAmount their_amount;            // Amount they promised to lock
    std::string their_htlc_txid;     // Their HTLC transaction ID (may be on other chain)
    uint32_t their_htlc_vout;        // Their HTLC output index
    uint32_t their_timeout;          // Their refund timeout

    // Cryptographic material
    std::vector<uint8_t> preimage;   // 32-byte secret (initiator only, until claimed)
    std::vector<uint8_t> hash_lock;  // SHA3-256(preimage)

    // Addresses
    std::string our_refund_address;    // Our address on our chain (for refund)
    std::string our_claim_address;     // Our address on their chain (metadata)
    std::string their_claim_address;   // Their address on our chain (claim pubkey hash)

    // Timestamps
    int64_t created_at;              // Unix timestamp when swap was created

    SwapInfo()
        : role(SwapRole::INITIATOR)
        , state(SwapState::CREATED)
        , our_amount(0)
        , our_timeout(0)
        , their_amount(0)
        , their_htlc_vout(0)
        , their_timeout(0)
        , created_at(0)
    {}
};

/**
 * Thread-safe swap store.
 * Persists swap state to {datadir}/swaps.json using nlohmann::json.
 */
class SwapStore {
public:
    SwapStore() = default;

    /** Set the file path for persistence (must be called before Load). */
    void SetPath(const std::string& path);

    /** Load swaps from disk. Silently succeeds if file doesn't exist. */
    void Load();

    /** Persist all swaps to disk. */
    void Save() const;

    /** Add a new swap, returns swap_id. */
    std::string AddSwap(const SwapInfo& info);

    /** Get swap by ID. Returns false if not found. */
    bool GetSwap(const std::string& swap_id, SwapInfo& out) const;

    /** Update swap state. Returns false if not found. */
    bool UpdateSwap(const std::string& swap_id, const SwapInfo& info);

    /** Get all swaps, optionally filtered by state (-1 = all). */
    std::vector<SwapInfo> ListSwaps(int state_filter = -1) const;

    /** Number of swaps. */
    size_t Size() const;

private:
    std::string m_path;
    std::map<std::string, SwapInfo> m_swaps;
    mutable std::mutex m_mutex;
};

/** Convert SwapRole to string */
const char* SwapRoleStr(SwapRole role);

/** Convert SwapState to string */
const char* SwapStateStr(SwapState state);

/** Parse SwapState from string. Returns SwapState::CREATED on unknown. */
SwapState ParseSwapState(const std::string& s);

#endif // DILITHION_SCRIPT_ATOMIC_SWAP_H
