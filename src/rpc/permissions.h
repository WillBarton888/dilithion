// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_PERMISSIONS_H
#define DILITHION_RPC_PERMISSIONS_H

#include <string>
#include <map>
#include <vector>
#include <cstdint>
#include <mutex>

/**
 * RPC Permission System (FIX-014: CWE-862 - Missing Authorization)
 *
 * Implements role-based access control (RBAC) for RPC methods.
 * Enforces principle of least privilege to prevent privilege escalation.
 *
 * Security Model:
 * - Each user assigned a permission bitmask (uint32_t)
 * - Each RPC method requires specific permissions
 * - Permission check performed after authentication, before execution
 * - Failed authorization attempts logged for audit
 *
 * Configuration:
 * - Users defined in rpc_permissions.json (multi-user mode)
 * - Legacy fallback: rpcuser/rpcpassword (single admin user)
 * - Backwards compatible with existing deployments
 *
 * Performance:
 * - O(1) permission checking via bitwise AND
 * - ~20ns overhead per request (negligible)
 * - ~88 bytes memory per user
 */

/**
 * Permission flags (bitfield design)
 *
 * Each permission is a single bit in a 32-bit unsigned integer.
 * This enables fast O(1) permission checking with bitwise operations
 * and supports up to 32 different permissions (10 currently defined,
 * 22 reserved for future expansion).
 */
enum class RPCPermission : uint32_t {
    // ========================================================================
    // Read Permissions (Bits 0-3) - Information Disclosure Only
    // ========================================================================

    /**
     * READ_BLOCKCHAIN (0x0001) - Bit 0
     *
     * Allows reading blockchain data (blocks, transactions, chain state).
     *
     * Methods:
     * - getblockcount, getblock, getblockhash, getbestblockhash
     * - getblockchaininfo, getchaintips, getrawtransaction
     * - decoderawtransaction, getnetworkinfo, getpeerinfo
     *
     * Risk: Low (public blockchain data, no privacy concern)
     */
    READ_BLOCKCHAIN   = 0x0001,

    /**
     * READ_WALLET (0x0002) - Bit 1
     *
     * Allows reading wallet data (balances, addresses, transactions).
     *
     * Methods:
     * - getbalance, getaddresses, listunspent
     * - gettransaction, listtransactions
     * - gethdwalletinfo, listhdaddresses
     *
     * Risk: Medium (privacy concern - reveals financial information)
     */
    READ_WALLET       = 0x0002,

    /**
     * READ_MEMPOOL (0x0004) - Bit 2
     *
     * Allows reading mempool contents (unconfirmed transactions).
     *
     * Methods:
     * - getmempoolinfo, getrawmempool
     *
     * Risk: Low (public mempool data)
     */
    READ_MEMPOOL      = 0x0004,

    /**
     * READ_MINING (0x0008) - Bit 3
     *
     * Allows reading mining status and statistics.
     *
     * Methods:
     * - getmininginfo
     *
     * Risk: Low (mining statistics, no privacy concern)
     */
    READ_MINING       = 0x0008,

    // ========================================================================
    // Write Permissions (Bits 4-5) - State Modification
    // ========================================================================

    /**
     * WRITE_WALLET (0x0010) - Bit 4
     *
     * Allows modifying wallet state (send funds, generate addresses, sign).
     *
     * Methods:
     * - getnewaddress, sendtoaddress, signrawtransaction
     * - createhdwallet, restorehdwallet
     *
     * Risk: High (can send transactions, deplete balance)
     * Note: Does NOT allow exporting master key (ADMIN_WALLET required)
     */
    WRITE_WALLET      = 0x0010,

    /**
     * WRITE_MEMPOOL (0x0020) - Bit 5
     *
     * Allows injecting transactions into mempool.
     *
     * Methods:
     * - sendrawtransaction
     *
     * Risk: Medium (can broadcast transactions, potential spam)
     */
    WRITE_MEMPOOL     = 0x0020,

    // ========================================================================
    // Control Permissions (Bits 6-7) - Node Operation Control
    // ========================================================================

    /**
     * CONTROL_MINING (0x0040) - Bit 6
     *
     * Allows controlling mining operations (start/stop).
     *
     * Methods:
     * - startmining, stopmining, generatetoaddress
     *
     * Risk: High (resource exhaustion, service disruption)
     */
    CONTROL_MINING    = 0x0040,

    /**
     * CONTROL_NETWORK (0x0080) - Bit 7
     *
     * Allows controlling network connectivity (future).
     *
     * Methods:
     * - addnode (future implementation)
     *
     * Risk: High (can isolate node, eclipse attacks)
     */
    CONTROL_NETWORK   = 0x0080,

    // ========================================================================
    // Admin Permissions (Bits 8-9) - Critical System Operations
    // ========================================================================

    /**
     * ADMIN_WALLET (0x0100) - Bit 8
     *
     * Allows critical wallet operations (encryption, key export).
     *
     * Methods:
     * - encryptwallet, walletpassphrase, walletlock
     * - walletpassphrasechange, exportmnemonic
     *
     * Risk: CRITICAL (can export master key, encrypt wallet)
     * Note: Requires admin role - never grant to automated systems
     */
    ADMIN_WALLET      = 0x0100,

    /**
     * ADMIN_SERVER (0x0200) - Bit 9
     *
     * Allows server control operations (shutdown, restart).
     *
     * Methods:
     * - stop
     *
     * Risk: CRITICAL (denial of service)
     * Note: Requires admin role - never grant to untrusted users
     */
    ADMIN_SERVER      = 0x0200,

    // ========================================================================
    // Reserved Permissions (Bits 10-31) - Future Expansion
    // ========================================================================

    // Potential future permissions:
    // ADMIN_CONFIG      = 0x0400,  // Bit 10 - Modify server configuration
    // WRITE_BLOCKCHAIN  = 0x0800,  // Bit 11 - Pruning, reindex operations
    // CONTROL_PEERS     = 0x1000,  // Bit 12 - Ban/unban peers
    // AUDIT_ACCESS      = 0x2000,  // Bit 13 - View audit logs
    // BACKUP_RESTORE    = 0x4000,  // Bit 14 - Backup/restore operations

    // ========================================================================
    // Standard Role Presets
    // ========================================================================

    /**
     * ROLE_READONLY (0x000F) - Bits 0-3
     *
     * Read-only access to all data (no state modification).
     *
     * Permissions:
     * - READ_BLOCKCHAIN | READ_WALLET | READ_MEMPOOL | READ_MINING
     *
     * Use Cases:
     * - Monitoring dashboards
     * - Analytics platforms
     * - Alerting systems
     *
     * Methods: ~18 read-only methods
     * Security: Low risk (information disclosure only)
     */
    ROLE_READONLY     = 0x000F,

    /**
     * ROLE_WALLET (0x003F) - Bits 0-5
     *
     * Wallet operations (read + write) but no server control.
     *
     * Permissions:
     * - ROLE_READONLY | WRITE_WALLET | WRITE_MEMPOOL
     *
     * Use Cases:
     * - Automated payment systems
     * - Trading bots
     * - E-commerce integrations
     *
     * Methods: ~30 methods (read + wallet write)
     * Security: Medium risk (can send funds but not export keys)
     *
     * Protection: Cannot stop server, cannot export mnemonic
     */
    ROLE_WALLET       = 0x003F,

    /**
     * ROLE_ADMIN (0xFFFFFFFF) - All bits set
     *
     * Full administrative access to all operations.
     *
     * Permissions: ALL
     *
     * Use Cases:
     * - System administrators
     * - Node operators
     * - Emergency operations
     *
     * Methods: All 45+ methods
     * Security: CRITICAL risk (full system access)
     *
     * WARNING: Only assign to trusted administrators
     * Recommendation: Require 2FA for admin role (future)
     */
    ROLE_ADMIN        = 0xFFFFFFFF
};

/**
 * Bitwise OR operator for combining permissions
 *
 * Example:
 *   uint32_t customRole = RPCPermission::READ_BLOCKCHAIN | RPCPermission::READ_WALLET;
 */
inline uint32_t operator|(RPCPermission a, RPCPermission b) {
    return static_cast<uint32_t>(a) | static_cast<uint32_t>(b);
}

/**
 * Bitwise AND operator for checking permissions
 *
 * Example:
 *   if (userPerms & RPCPermission::WRITE_WALLET) { ... }
 */
inline uint32_t operator&(uint32_t a, RPCPermission b) {
    return a & static_cast<uint32_t>(b);
}

inline uint32_t operator&(RPCPermission a, RPCPermission b) {
    return static_cast<uint32_t>(a) & static_cast<uint32_t>(b);
}

/**
 * User account with permissions
 *
 * Stores credentials and permission bitmask for a single RPC user.
 * Password stored as PBKDF2-HMAC-SHA3 hash with random salt.
 */
struct RPCUser {
    std::string username;                   // Unique username (max 64 chars)
    std::vector<uint8_t> passwordSalt;      // Random salt (32 bytes)
    std::vector<uint8_t> passwordHash;      // PBKDF2-HMAC-SHA3(password, salt, 100k iterations)
    uint32_t permissions;                   // Permission bitmask

    RPCUser() : permissions(0) {}
};

/**
 * Permission configuration manager
 *
 * Thread-safe singleton managing user permissions and authorization.
 * Loads configuration from JSON file or uses legacy single-user mode.
 */
class CRPCPermissions {
private:
    // User database (username -> RPCUser)
    std::map<std::string, RPCUser> m_users;

    // Method permission requirements (method name -> required permissions)
    std::map<std::string, uint32_t> m_methodPermissions;

    // Legacy mode flag (single user with admin permissions)
    bool m_legacyMode;

    // Configuration file path
    std::string m_configPath;

    // Thread safety
    mutable std::mutex m_mutex;

    /**
     * Initialize method permission mapping
     *
     * Called once during construction to populate m_methodPermissions
     * with the mapping of RPC method names to required permission bitmasks.
     *
     * See docs/rpc-permissions-model.md for complete mapping table.
     */
    void InitializeMethodPermissions();

    /**
     * Parse JSON configuration file (internal helper)
     *
     * @param json JSON string to parse
     * @return true if parsed successfully, false on error
     */
    bool ParseJSONConfig(const std::string& json);

    /**
     * CID 1675190 FIX: Internal unlocked version of GetMethodPermissions
     *
     * Called by CheckMethodPermission variants to avoid double lock.
     * Caller MUST hold m_mutex before calling this function.
     *
     * @param method RPC method name
     * @return required permission bitmask (0 if method unknown/public)
     */
    uint32_t GetMethodPermissionsUnlocked(const std::string& method) const;

public:
    /**
     * Constructor
     *
     * Initializes permission system with empty user database.
     * Call LoadFromFile() or InitializeLegacyMode() after construction.
     */
    CRPCPermissions();

    /**
     * Load permissions from configuration file
     *
     * Attempts to load user database from JSON configuration file.
     * If file doesn't exist or cannot be parsed, returns false
     * (caller should fall back to legacy mode).
     *
     * Expected format:
     * {
     *   "version": 1,
     *   "users": {
     *     "username": {
     *       "password_hash": "hex...",
     *       "salt": "hex...",
     *       "role": "admin|wallet|readonly"
     *     }
     *   }
     * }
     *
     * @param configPath Path to rpc_permissions.json
     * @return true if loaded successfully, false if file missing/invalid
     *
     * Thread-safe: Yes (mutex protected)
     */
    bool LoadFromFile(const std::string& configPath);

    /**
     * Initialize legacy mode (single user, all permissions)
     *
     * Backwards compatible with old rpcuser/rpcpassword configuration.
     * Creates single admin user with full permissions.
     *
     * @param username Legacy RPC username
     * @param password Legacy RPC password (plain text - will be hashed)
     * @return true if initialized successfully, false on error
     *
     * Thread-safe: Yes (mutex protected)
     */
    bool InitializeLegacyMode(const std::string& username, const std::string& password);

    /**
     * Authenticate user and return permissions
     *
     * Verifies username and password, returns user's permission bitmask.
     *
     * @param username Username to authenticate
     * @param password Password to verify (plain text)
     * @param permissionsOut Output: user's permission bitmask (if successful)
     * @return true if authenticated, false if invalid credentials
     *
     * Thread-safe: Yes (mutex protected)
     *
     * Time Complexity: O(log n) + O(PBKDF2 iterations)
     * - Map lookup: O(log n) where n = user count
     * - Password verification: ~100ms (intentionally slow)
     */
    bool AuthenticateUser(const std::string& username,
                         const std::string& password,
                         uint32_t& permissionsOut) const;

    /**
     * Check if user has permission to call RPC method
     *
     * Looks up user's permissions and checks against method requirements.
     *
     * @param username Username to check
     * @param method RPC method name (e.g., "sendtoaddress")
     * @return true if authorized, false if insufficient permissions
     *
     * Thread-safe: Yes (mutex protected)
     *
     * Time Complexity: O(log n) + O(log m)
     * - User lookup: O(log n) where n = user count
     * - Method lookup: O(log m) where m = method count (~45)
     * - Permission check: O(1) bitwise AND
     */
    bool CheckMethodPermission(const std::string& username,
                              const std::string& method) const;

    /**
     * Check if permission bitmask allows RPC method
     *
     * Directly checks permission bitmask against method requirements.
     * Use this variant when you already have the user's permissions
     * (e.g., after authentication).
     *
     * @param userPermissions User's permission bitmask
     * @param method RPC method name (e.g., "getbalance")
     * @return true if authorized, false if insufficient permissions
     *
     * Thread-safe: Yes (mutex protected for method lookup only)
     *
     * Time Complexity: O(log m) + O(1)
     * - Method lookup: O(log m) where m = method count
     * - Permission check: O(1) bitwise AND
     *
     * Example:
     *   uint32_t perms = static_cast<uint32_t>(RPCPermission::ROLE_WALLET);
     *   bool allowed = permissions.CheckMethodPermission(perms, "sendtoaddress");
     */
    bool CheckMethodPermission(uint32_t userPermissions,
                              const std::string& method) const;

    /**
     * Get required permissions for RPC method
     *
     * Returns the permission bitmask required to call specified method.
     * Returns 0 if method is unknown (treated as public).
     *
     * @param method RPC method name
     * @return required permission bitmask (0 if method unknown/public)
     *
     * Thread-safe: Yes (read-only after initialization, but mutex protected)
     *
     * Time Complexity: O(log m) where m = method count
     */
    uint32_t GetMethodPermissions(const std::string& method) const;

    /**
     * Get human-readable role name for permission bitmask
     *
     * Converts permission bitmask to friendly name for logging/display.
     *
     * @param permissions Permission bitmask
     * @return role name: "admin", "wallet", "readonly", or "custom"
     *
     * Thread-safe: Yes (static method, no shared state)
     */
    static std::string GetRoleName(uint32_t permissions);

    /**
     * Check if running in legacy mode
     *
     * @return true if legacy mode (single admin user), false if multi-user
     *
     * Thread-safe: Yes (read-only)
     */
    bool IsLegacyMode() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_legacyMode;
    }

    /**
     * Get number of users configured
     *
     * @return user count
     *
     * Thread-safe: Yes (mutex protected)
     */
    size_t GetUserCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_users.size();
    }
};

#endif // DILITHION_RPC_PERMISSIONS_H
