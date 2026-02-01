// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
// Bitcoin Core-style ban manager with persistence

#ifndef DILITHION_NET_BANMAN_H
#define DILITHION_NET_BANMAN_H

#include <string>
#include <map>
#include <mutex>
#include <cstdint>
#include <vector>
#include <fstream>

/**
 * Ban reason codes (Bitcoin Core compatible)
 */
enum class BanReason : uint8_t {
    Unknown = 0,
    NodeMisbehaving = 1,     // Accumulated misbehavior score exceeded threshold
    ManuallyBanned = 2,      // Manually banned by operator via RPC
};

/**
 * Detailed misbehavior types for logging and diagnostics
 * Score guidelines:
 *   1-10:  Minor violations (rate limiting, unknown messages)
 *   20:    Moderate violations (truncated messages, parse errors)
 *   100:   Severe violations (invalid blocks, immediate ban)
 */
enum class MisbehaviorType : uint16_t {
    NONE = 0,

    // Protocol violations (10-20 points)
    INVALID_MESSAGE_SIZE = 100,      // Payload size exceeds limit
    TRUNCATED_MESSAGE = 101,         // Message truncated/incomplete
    PARSE_FAILURE = 102,             // Failed to deserialize message
    INVALID_CHECKSUM = 103,          // Message checksum mismatch
    UNKNOWN_MESSAGE_TYPE = 104,      // Unrecognized message command
    INVALID_PROTOCOL_VERSION = 105,  // Protocol version too old/invalid

    // Rate limiting violations (10 points each)
    INV_RATE_EXCEEDED = 200,         // Too many INV messages
    ADDR_RATE_EXCEEDED = 201,        // Too many ADDR messages
    GETDATA_RATE_EXCEEDED = 202,     // Too many GETDATA requests
    GETBLOCKS_RATE_EXCEEDED = 203,   // Too many GETBLOCKS requests
    PING_RATE_EXCEEDED = 204,        // Too many PING messages

    // Block violations (100 points - immediate ban)
    INVALID_BLOCK_HEADER = 300,      // Block header validation failed
    INVALID_MERKLE_ROOT = 301,       // Merkle root doesn't match transactions
    INVALID_BLOCK_POW = 302,         // Proof of work validation failed
    DUPLICATE_TRANSACTIONS = 303,    // Block contains duplicate txids
    DOUBLE_SPEND_IN_BLOCK = 304,     // Block contains double-spend
    INVALID_COINBASE = 305,          // Invalid coinbase transaction
    BLOCK_TOO_LARGE = 306,           // Block exceeds size limit
    INVALID_BLOCK_TIME = 307,        // Block timestamp invalid
    INVALID_BLOCK_VERSION = 308,     // Block version rejected

    // Transaction violations (20-100 points)
    INVALID_TRANSACTION = 400,       // Transaction validation failed
    TX_TOO_LARGE = 401,              // Transaction exceeds size limit
    TX_DUPLICATE_INPUTS = 402,       // Transaction has duplicate inputs
    TX_INVALID_SIGNATURE = 403,      // Signature verification failed
    TX_DOUBLE_SPEND = 404,           // Attempted double-spend
    TX_NON_STANDARD = 405,           // Non-standard transaction

    // Connection violations (20-100 points)
    SELF_CONNECTION = 500,           // Connected to self
    TOO_MANY_CONNECTIONS = 501,      // Exceeded connection limit attempts
    INVALID_HANDSHAKE = 502,         // Invalid version handshake
    DUPLICATE_VERSION = 503,         // Sent version message twice
    INVALID_GENESIS = 504,           // Peer on different blockchain (wrong genesis hash)
};

/**
 * Get human-readable description for misbehavior type
 */
inline const char* MisbehaviorTypeToString(MisbehaviorType type) {
    switch (type) {
        case MisbehaviorType::NONE: return "none";
        case MisbehaviorType::INVALID_MESSAGE_SIZE: return "invalid_message_size";
        case MisbehaviorType::TRUNCATED_MESSAGE: return "truncated_message";
        case MisbehaviorType::PARSE_FAILURE: return "parse_failure";
        case MisbehaviorType::INVALID_CHECKSUM: return "invalid_checksum";
        case MisbehaviorType::UNKNOWN_MESSAGE_TYPE: return "unknown_message_type";
        case MisbehaviorType::INVALID_PROTOCOL_VERSION: return "invalid_protocol_version";
        case MisbehaviorType::INV_RATE_EXCEEDED: return "inv_rate_exceeded";
        case MisbehaviorType::ADDR_RATE_EXCEEDED: return "addr_rate_exceeded";
        case MisbehaviorType::GETDATA_RATE_EXCEEDED: return "getdata_rate_exceeded";
        case MisbehaviorType::GETBLOCKS_RATE_EXCEEDED: return "getblocks_rate_exceeded";
        case MisbehaviorType::PING_RATE_EXCEEDED: return "ping_rate_exceeded";
        case MisbehaviorType::INVALID_BLOCK_HEADER: return "invalid_block_header";
        case MisbehaviorType::INVALID_MERKLE_ROOT: return "invalid_merkle_root";
        case MisbehaviorType::INVALID_BLOCK_POW: return "invalid_block_pow";
        case MisbehaviorType::DUPLICATE_TRANSACTIONS: return "duplicate_transactions";
        case MisbehaviorType::DOUBLE_SPEND_IN_BLOCK: return "double_spend_in_block";
        case MisbehaviorType::INVALID_COINBASE: return "invalid_coinbase";
        case MisbehaviorType::BLOCK_TOO_LARGE: return "block_too_large";
        case MisbehaviorType::INVALID_BLOCK_TIME: return "invalid_block_time";
        case MisbehaviorType::INVALID_BLOCK_VERSION: return "invalid_block_version";
        case MisbehaviorType::INVALID_TRANSACTION: return "invalid_transaction";
        case MisbehaviorType::TX_TOO_LARGE: return "tx_too_large";
        case MisbehaviorType::TX_DUPLICATE_INPUTS: return "tx_duplicate_inputs";
        case MisbehaviorType::TX_INVALID_SIGNATURE: return "tx_invalid_signature";
        case MisbehaviorType::TX_DOUBLE_SPEND: return "tx_double_spend";
        case MisbehaviorType::TX_NON_STANDARD: return "tx_non_standard";
        case MisbehaviorType::SELF_CONNECTION: return "self_connection";
        case MisbehaviorType::TOO_MANY_CONNECTIONS: return "too_many_connections";
        case MisbehaviorType::INVALID_HANDSHAKE: return "invalid_handshake";
        case MisbehaviorType::DUPLICATE_VERSION: return "duplicate_version";
        case MisbehaviorType::INVALID_GENESIS: return "invalid_genesis";
        default: return "unknown";
    }
}

/**
 * Get default score for misbehavior type
 */
inline int GetMisbehaviorScore(MisbehaviorType type) {
    switch (type) {
        // Minor violations (10 points)
        case MisbehaviorType::PARSE_FAILURE: return 10;
        case MisbehaviorType::UNKNOWN_MESSAGE_TYPE: return 10;
        case MisbehaviorType::INV_RATE_EXCEEDED: return 10;
        case MisbehaviorType::ADDR_RATE_EXCEEDED: return 10;
        case MisbehaviorType::GETDATA_RATE_EXCEEDED: return 10;
        case MisbehaviorType::GETBLOCKS_RATE_EXCEEDED: return 10;
        case MisbehaviorType::PING_RATE_EXCEEDED: return 10;

        // Moderate violations (20 points)
        case MisbehaviorType::INVALID_MESSAGE_SIZE: return 20;
        case MisbehaviorType::TRUNCATED_MESSAGE: return 20;
        case MisbehaviorType::INVALID_CHECKSUM: return 20;
        case MisbehaviorType::INVALID_PROTOCOL_VERSION: return 20;
        case MisbehaviorType::INVALID_TRANSACTION: return 20;
        case MisbehaviorType::TX_NON_STANDARD: return 20;
        case MisbehaviorType::INVALID_HANDSHAKE: return 20;
        case MisbehaviorType::DUPLICATE_VERSION: return 20;
        case MisbehaviorType::INVALID_GENESIS: return 20;  // Likely innocent - user hasn't updated binary

        // Severe violations (100 points - immediate ban)
        case MisbehaviorType::INVALID_BLOCK_HEADER: return 100;
        case MisbehaviorType::INVALID_MERKLE_ROOT: return 100;
        case MisbehaviorType::INVALID_BLOCK_POW: return 100;
        case MisbehaviorType::DUPLICATE_TRANSACTIONS: return 100;
        case MisbehaviorType::DOUBLE_SPEND_IN_BLOCK: return 100;
        case MisbehaviorType::INVALID_COINBASE: return 100;
        case MisbehaviorType::BLOCK_TOO_LARGE: return 100;
        case MisbehaviorType::INVALID_BLOCK_TIME: return 100;
        case MisbehaviorType::INVALID_BLOCK_VERSION: return 100;
        case MisbehaviorType::TX_TOO_LARGE: return 100;
        case MisbehaviorType::TX_DUPLICATE_INPUTS: return 100;
        case MisbehaviorType::TX_INVALID_SIGNATURE: return 100;
        case MisbehaviorType::TX_DOUBLE_SPEND: return 100;
        case MisbehaviorType::SELF_CONNECTION: return 100;
        case MisbehaviorType::TOO_MANY_CONNECTIONS: return 100;

        default: return 0;
    }
}

/**
 * Genesis mismatch rate limiting constants
 * Tracks repeated genesis failures by IP to detect probing attacks
 */
static const int GENESIS_FAILURE_BAN_THRESHOLD = 3;     // Ban after 3 failures in window
static const int64_t GENESIS_FAILURE_WINDOW = 300;      // 5-minute window (seconds)
static const int GENESIS_ALERT_THRESHOLD = 10;          // Alert after 10 failures total

/**
 * GenesisFailureEntry - Track genesis mismatch failures per IP
 */
struct GenesisFailureEntry {
    int64_t first_failure;      // Timestamp of first failure in current window
    int failure_count;          // Failures in current window
    int total_failures;         // Total failures (for alerting)
    std::string last_genesis;   // Last genesis hash they sent (for logging)

    GenesisFailureEntry() : first_failure(0), failure_count(0), total_failures(0) {}
};

/**
 * CBanEntry - Ban entry with full metadata (Bitcoin Core compatible)
 */
struct CBanEntry {
    int64_t nCreateTime;              // When the ban was created (Unix timestamp)
    int64_t nBanUntil;                // When the ban expires (0 = permanent)
    BanReason banReason;              // Why banned
    MisbehaviorType misbehaviorType;  // Specific violation (if NodeMisbehaving)
    int nMisbehaviorScore;            // Score at time of ban
    std::string strComment;           // Optional operator comment

    CBanEntry()
        : nCreateTime(0), nBanUntil(0), banReason(BanReason::Unknown),
          misbehaviorType(MisbehaviorType::NONE), nMisbehaviorScore(0) {}

    explicit CBanEntry(int64_t banUntil, BanReason reason = BanReason::NodeMisbehaving)
        : nCreateTime(time(nullptr)), nBanUntil(banUntil), banReason(reason),
          misbehaviorType(MisbehaviorType::NONE), nMisbehaviorScore(0) {}

    bool IsExpired() const {
        return nBanUntil > 0 && time(nullptr) >= nBanUntil;
    }

    bool IsPermanent() const {
        return nBanUntil == 0;
    }

    std::string ToString() const;
};

/**
 * CBanManager - Bitcoin Core-style ban manager with persistence
 *
 * Features:
 * - Persistent ban list (banlist.dat)
 * - Structured ban reasons and misbehavior types
 * - Automatic expiry sweep
 * - Thread-safe operations
 */
class CBanManager {
public:
    // File format constants
    static const uint32_t BANLIST_MAGIC = 0x44494C42;  // "DILB" - Dilithion Ban
    static const uint8_t BANLIST_VERSION = 1;

    // Limits
    static const size_t MAX_BANNED_IPS = 10000;
    static const int64_t DEFAULT_BAN_TIME = 1 * 60 * 60;  // 1 hour (temporary during DFMP transition)

private:
    mutable std::mutex cs_banned;
    std::map<std::string, CBanEntry> m_banned;  // IP -> BanEntry
    std::string m_ban_file_path;                // Path to banlist.dat
    bool m_is_dirty;                            // Needs saving

    // Genesis failure tracking (IP-based rate limiting for probing detection)
    mutable std::mutex cs_genesis_failures;
    std::map<std::string, GenesisFailureEntry> m_genesis_failures;

public:
    /**
     * Constructor
     * @param datadir Data directory containing banlist.dat
     */
    explicit CBanManager(const std::string& datadir = "");

    /**
     * Destructor - saves ban list if dirty
     */
    ~CBanManager();

    // Prevent copying
    CBanManager(const CBanManager&) = delete;
    CBanManager& operator=(const CBanManager&) = delete;

    /**
     * Ban an IP address
     * @param ip IP address to ban
     * @param entry Ban entry with metadata
     */
    void Ban(const std::string& ip, const CBanEntry& entry);

    /**
     * Ban an IP address with defaults
     * @param ip IP address to ban
     * @param duration_seconds Ban duration (0 = permanent)
     * @param reason Ban reason
     * @param type Specific misbehavior type
     * @param score Misbehavior score at time of ban
     */
    void Ban(const std::string& ip, int64_t duration_seconds,
             BanReason reason = BanReason::NodeMisbehaving,
             MisbehaviorType type = MisbehaviorType::NONE,
             int score = 0);

    /**
     * Unban an IP address
     */
    void Unban(const std::string& ip);

    /**
     * Check if IP is banned
     */
    bool IsBanned(const std::string& ip) const;

    /**
     * Check if IP is banned and get entry
     */
    bool IsBanned(const std::string& ip, CBanEntry& entryOut) const;

    /**
     * Clear all bans
     */
    void ClearBanned();

    /**
     * Get all banned IPs with entries
     */
    std::vector<std::pair<std::string, CBanEntry>> GetBanned() const;

    /**
     * Get count of banned IPs
     */
    size_t GetBannedCount() const;

    /**
     * Save ban list to banlist.dat
     * @return true if saved successfully
     */
    bool SaveBanList();

    /**
     * Load ban list from banlist.dat
     * @return true if loaded successfully
     */
    bool LoadBanList();

    /**
     * Remove expired bans
     * @return Number of bans removed
     */
    size_t SweepExpiredBans();

    /**
     * Ban list statistics
     */
    struct Stats {
        size_t total_banned;
        size_t permanent_bans;
        size_t temporary_bans;
        size_t expired_bans;  // Removed in last sweep
    };
    Stats GetStats() const;

    /**
     * Check if ban list needs saving
     */
    bool IsDirty() const { return m_is_dirty; }

    /**
     * Get path to banlist.dat
     */
    const std::string& GetBanFilePath() const { return m_ban_file_path; }

    /**
     * Record a genesis mismatch failure for an IP
     * @param ip IP address that sent wrong genesis
     * @param their_genesis The genesis hash they sent (for logging)
     * @return true if IP should be banned (exceeded threshold)
     */
    bool RecordGenesisFailure(const std::string& ip, const std::string& their_genesis);

    /**
     * Remove old genesis failure entries (call periodically)
     * Removes entries older than 2x GENESIS_FAILURE_WINDOW
     */
    void CleanupGenesisFailures();

    /**
     * Get count of IPs being tracked for genesis failures
     */
    size_t GetGenesisFailureCount() const;
};

#endif // DILITHION_NET_BANMAN_H
