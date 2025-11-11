// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_WAL_H
#define DILITHION_WALLET_WAL_H

/**
 * PERSIST-008 FIX: Write-Ahead Log (WAL) for Atomic Multi-Step Wallet Operations
 *
 * PROBLEM:
 * Wallet initialization involves multiple steps (create HD wallet, encrypt, save).
 * If crash occurs between steps, wallet ends up in partial state → fund loss.
 *
 * Example crash scenario:
 *   1. User creates HD wallet with recovery phrase
 *   2. CRASH before encryption
 *   3. On restart: HD wallet exists but unencrypted (CRITICAL SECURITY ISSUE)
 *   4. Attacker can steal funds by reading unencrypted wallet file
 *
 * SOLUTION:
 * Write-Ahead Log (WAL) ensures atomic multi-step operations:
 *   1. Before operation: Write BEGIN entry to WAL
 *   2. After each step: Write CHECKPOINT entry
 *   3. After success: Write COMMIT entry and delete WAL
 *   4. On startup: Check for incomplete operations → rollback or complete
 *
 * WAL FILE FORMAT:
 * Location: wallet.dat.wal (same directory as wallet.dat)
 *
 * Header (16 bytes):
 *   [0-7]   Magic: "DILWWAL1" (8 bytes)
 *   [8-11]  Version: 1 (uint32_t little-endian)
 *   [12-15] Entry Count: N (uint32_t little-endian)
 *
 * Entry Format (variable length):
 *   [0]      Type: 1=BEGIN, 2=CHECKPOINT, 3=COMMIT, 4=ROLLBACK (uint8_t)
 *   [1-2]    Operation ID Length: L1 (uint16_t little-endian, max 256)
 *   [3...]   Operation ID: UUID string (L1 bytes)
 *   [...]    Step Name Length: L2 (uint16_t little-endian, max 256)
 *   [...]    Step Name: step identifier (L2 bytes, empty for BEGIN/COMMIT/ROLLBACK)
 *   [...]    Data Length: L3 (uint32_t little-endian, max 1MB)
 *   [...]    Data: serialized step data (L3 bytes)
 *   [...]    Timestamp: Unix timestamp (uint64_t little-endian)
 *   [...]    CRC32: Entry checksum (uint32_t little-endian)
 *
 * CRC32 is computed over all preceding bytes in the entry (Type through Timestamp).
 *
 * EXAMPLE WAL SEQUENCE:
 *   1. BEGIN_OPERATION(op_id="abc123-...", step="", data={})
 *   2. CHECKPOINT(op_id="abc123-...", step="create_hd_wallet", data={encrypted_mnemonic})
 *   3. CHECKPOINT(op_id="abc123-...", step="encrypt_wallet", data={})
 *   4. CHECKPOINT(op_id="abc123-...", step="save_wallet", data={})
 *   5. COMMIT(op_id="abc123-...", step="", data={})
 *
 * RECOVERY PROTOCOL:
 * On wallet startup, check for wallet.dat.wal:
 *   - If no WAL file: Continue normal startup
 *   - If WAL exists:
 *     1. Parse all entries
 *     2. Find incomplete operations (BEGIN without COMMIT/ROLLBACK)
 *     3. For each incomplete operation:
 *        - Analyze checkpoint history
 *        - Decision: ROLLBACK (delete partial state) or COMPLETE (finish operation)
 *        - Execute recovery action
 *     4. Delete WAL file if all operations recovered
 *
 * THREAD SAFETY:
 * - WAL operations use file locking (Windows: LockFileEx, Linux: flock)
 * - Only one process can write to WAL at a time
 * - WAL file opened with exclusive access during active operation
 *
 * PERFORMANCE:
 * - WAL writes are fsync'd immediately (durability over performance)
 * - Typical operation: 5-10 WAL writes (BEGIN + checkpoints + COMMIT)
 * - Each write: ~1-5ms (depends on disk)
 * - Total overhead: 25-50ms per multi-step operation (acceptable for wallet ops)
 */

#include <string>
#include <vector>
#include <functional>
#include <fstream>
#include <chrono>
#include <memory>
#include <cstdint>

// WAL Entry Types
enum class WALEntryType : uint8_t {
    BEGIN_OPERATION = 0x01,    // Start of atomic operation
    CHECKPOINT = 0x02,         // Completed sub-step within operation
    COMMIT = 0x03,             // All steps completed successfully
    ROLLBACK = 0x04            // Operation cancelled or failed
};

// WAL Operation Types (identifies which multi-step operation is being performed)
enum class WALOperation : uint8_t {
    WALLET_INITIALIZATION = 0x01,  // First-time wallet setup (wizard)
    WALLET_ENCRYPTION = 0x02,      // Encrypting existing wallet
    HD_WALLET_CREATION = 0x03,     // Creating HD wallet (mnemonic generation)
    HD_WALLET_RESTORE = 0x04       // Restoring wallet from recovery phrase
};

// Convert WALOperation to human-readable string (for logging)
const char* WALOperationToString(WALOperation op);

// Convert WALEntryType to human-readable string (for logging)
const char* WALEntryTypeToString(WALEntryType type);

/**
 * Single entry in the Write-Ahead Log
 *
 * Represents one event in a multi-step atomic operation:
 * - BEGIN: Operation started
 * - CHECKPOINT: Step completed
 * - COMMIT: Operation finished successfully
 * - ROLLBACK: Operation cancelled or failed
 */
struct WALEntry {
    WALEntryType type;              // Entry type (BEGIN/CHECKPOINT/COMMIT/ROLLBACK)
    std::string operation_id;       // Unique operation identifier (UUID format)
    std::string step_name;          // Name of completed step (empty for BEGIN/COMMIT/ROLLBACK)
    std::vector<uint8_t> data;      // Step-specific recovery data (optional)
    uint64_t timestamp;             // Unix timestamp (seconds since epoch)
    uint32_t crc32;                 // CRC32 checksum of entry (for corruption detection)

    WALEntry();

    /**
     * Serialize entry to bytes for writing to WAL file
     *
     * Format: [TYPE:1][OPID_LEN:2][OPID][STEP_LEN:2][STEP][DATA_LEN:4][DATA][TIMESTAMP:8][CRC32:4]
     *
     * @return Serialized bytes, or empty vector if serialization fails
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * Deserialize entry from bytes read from WAL file
     *
     * @param bytes Serialized entry bytes
     * @return true if deserialization successful and CRC32 valid, false otherwise
     */
    bool Deserialize(const std::vector<uint8_t>& bytes);

    /**
     * Calculate CRC32 checksum for this entry
     *
     * Checksum is computed over all fields except the crc32 field itself.
     * Used to detect corruption in WAL file.
     *
     * @return CRC32 checksum
     */
    uint32_t CalculateCRC32() const;

    /**
     * Verify that stored CRC32 matches calculated CRC32
     *
     * @return true if CRC32 valid, false if corrupted
     */
    bool VerifyCRC32() const;
};

/**
 * Write-Ahead Log Manager
 *
 * Manages WAL file for atomic multi-step wallet operations.
 *
 * USAGE EXAMPLE:
 *
 *   CWalletWAL wal;
 *   if (!wal.Initialize("/home/user/.dilithion/wallet.dat")) {
 *       // Error: Could not initialize WAL
 *       return false;
 *   }
 *
 *   std::string op_id;
 *   if (!wal.BeginOperation(WALOperation::WALLET_INITIALIZATION, op_id)) {
 *       // Error: Could not start operation
 *       return false;
 *   }
 *
 *   // Step 1: Create HD wallet
 *   if (!CreateHDWallet()) {
 *       wal.Rollback(op_id);
 *       return false;
 *   }
 *   wal.Checkpoint(op_id, "create_hd_wallet", encrypted_mnemonic_bytes);
 *
 *   // Step 2: Encrypt wallet
 *   if (!EncryptWallet()) {
 *       wal.Rollback(op_id);
 *       return false;
 *   }
 *   wal.Checkpoint(op_id, "encrypt_wallet");
 *
 *   // Step 3: Save wallet
 *   if (!SaveWallet()) {
 *       wal.Rollback(op_id);
 *       return false;
 *   }
 *   wal.Checkpoint(op_id, "save_wallet");
 *
 *   // Success - commit and cleanup WAL
 *   wal.Commit(op_id);
 *
 * THREAD SAFETY:
 * - Not thread-safe - caller must ensure single-threaded access
 * - Uses file locking to prevent multiple processes from conflicting
 */
class CWalletWAL {
private:
    std::string m_wal_file;            // Path to WAL file (wallet.dat.wal)
    std::string m_wallet_file;         // Path to wallet file (wallet.dat)
    bool m_wal_initialized;            // Whether WAL has been initialized
    std::string m_current_operation_id;// Currently active operation ID (empty if none)

    #ifdef _WIN32
    void* m_file_handle;               // Windows file handle for locking
    #else
    int m_file_descriptor;             // Linux file descriptor for locking
    #endif

    /**
     * Generate unique operation ID (UUID v4 format)
     *
     * Format: "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
     * Where x is random hex digit, y is 8/9/a/b
     *
     * @return UUID string (36 characters)
     */
    std::string GenerateOperationID() const;

    /**
     * Write entry to WAL file (append mode)
     *
     * Steps:
     *   1. Serialize entry
     *   2. Acquire file lock
     *   3. Append to WAL file
     *   4. fsync() to ensure durability
     *   5. Release file lock
     *
     * @param entry Entry to write
     * @return true if write successful, false on error
     */
    bool WriteEntry(const WALEntry& entry);

    /**
     * Read all entries from WAL file
     *
     * Parses WAL file header and all entries.
     * Verifies magic number, version, and CRC32 checksums.
     *
     * @param entries_out Output vector to store entries
     * @return true if read successful, false if file missing or corrupted
     */
    bool ReadEntries(std::vector<WALEntry>& entries_out) const;

    /**
     * Open WAL file for writing (exclusive access)
     *
     * Acquires file lock to prevent concurrent access.
     *
     * @return true if opened successfully, false on error
     */
    bool OpenWAL();

    /**
     * Close WAL file and release lock
     */
    void CloseWAL();

    /**
     * Securely delete file (overwrite with zeros before deletion)
     *
     * Security measure: Prevents recovery of sensitive data from disk.
     *
     * @param filepath Path to file to delete
     * @return true if deleted successfully, false on error
     */
    bool SecureDelete(const std::string& filepath);

    /**
     * Write WAL file header
     *
     * Header: [MAGIC:8][VERSION:4][ENTRY_COUNT:4]
     *
     * @param entry_count Number of entries in WAL
     * @return true if write successful, false on error
     */
    bool WriteHeader(uint32_t entry_count);

public:
    /**
     * Constructor
     */
    CWalletWAL();

    /**
     * Destructor - ensures WAL file is closed properly
     */
    ~CWalletWAL();

    /**
     * Initialize WAL for a wallet
     *
     * Sets up WAL file path (wallet_path + ".wal").
     * Does NOT create WAL file yet (created on first BeginOperation).
     *
     * @param wallet_path Path to wallet.dat file
     * @return true if initialization successful, false on error
     */
    bool Initialize(const std::string& wallet_path);

    /**
     * Begin atomic operation (writes BEGIN entry to WAL)
     *
     * Generates unique operation ID and writes BEGIN entry.
     * After this call, operation is "in progress" and will be
     * detected on recovery if crash occurs before COMMIT.
     *
     * @param op Operation type (WALLET_INITIALIZATION, etc.)
     * @param operation_id_out Output: Generated operation ID
     * @return true if BEGIN written successfully, false on error
     */
    bool BeginOperation(WALOperation op, std::string& operation_id_out);

    /**
     * Record checkpoint (completed sub-step within operation)
     *
     * Writes CHECKPOINT entry with step name and optional recovery data.
     * Recovery data can be used to rollback or complete the step if crash occurs.
     *
     * Example: After creating HD wallet, checkpoint with encrypted mnemonic
     *          so recovery can verify if mnemonic was saved correctly.
     *
     * @param operation_id Operation ID from BeginOperation()
     * @param step_name Name of completed step (e.g., "create_hd_wallet")
     * @param step_data Optional recovery data for this step
     * @return true if CHECKPOINT written successfully, false on error
     */
    bool Checkpoint(const std::string& operation_id,
                    const std::string& step_name,
                    const std::vector<uint8_t>& step_data = {});

    /**
     * Commit operation (all steps completed successfully)
     *
     * Writes COMMIT entry and deletes WAL file.
     * After this call, operation is complete and will NOT trigger recovery.
     *
     * @param operation_id Operation ID from BeginOperation()
     * @return true if COMMIT written and WAL deleted, false on error
     */
    bool Commit(const std::string& operation_id);

    /**
     * Rollback operation (operation cancelled or failed)
     *
     * Writes ROLLBACK entry and deletes WAL file.
     * Caller is responsible for rolling back wallet state.
     *
     * @param operation_id Operation ID from BeginOperation()
     * @return true if ROLLBACK written and WAL deleted, false on error
     */
    bool Rollback(const std::string& operation_id);

    /**
     * Check if WAL has incomplete operations
     *
     * Reads WAL file and finds operations with BEGIN but no COMMIT/ROLLBACK.
     * Called on wallet startup to detect crashes during previous operations.
     *
     * @param operations_out Output: List of incomplete operation IDs
     * @return true if check completed (even if no incomplete ops), false on error
     */
    bool HasIncompleteOperations(std::vector<std::string>& operations_out) const;

    /**
     * Get incomplete operation details
     *
     * Retrieves all entries for a specific operation ID.
     * Used by recovery system to determine how to recover.
     *
     * @param operation_id Operation ID to query
     * @param op_type_out Output: Operation type
     * @param steps_out Output: All entries for this operation
     * @return true if operation found, false if not found or error
     */
    bool GetOperationDetails(const std::string& operation_id,
                             WALOperation& op_type_out,
                             std::vector<WALEntry>& steps_out) const;

    /**
     * Get WAL file path
     *
     * @return Path to WAL file (wallet.dat.wal)
     */
    std::string GetWALPath() const { return m_wal_file; }

    /**
     * Check if WAL is initialized
     *
     * @return true if Initialize() was called successfully
     */
    bool IsInitialized() const { return m_wal_initialized; }

    /**
     * Check if WAL file exists
     *
     * @return true if wallet.dat.wal exists on disk
     */
    bool WALFileExists() const;

    /**
     * Delete WAL file (for testing or manual cleanup)
     *
     * WARNING: Only call if you're sure no operations are in progress!
     *
     * @return true if deleted successfully or file doesn't exist
     */
    bool DeleteWAL();
};

#endif // DILITHION_WALLET_WAL_H
