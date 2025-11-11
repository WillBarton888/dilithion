// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_WAL_RECOVERY_H
#define DILITHION_WALLET_WAL_RECOVERY_H

/**
 * PERSIST-008 FIX: WAL Recovery System
 *
 * RECOVERY PROTOCOL:
 * When wallet starts and detects incomplete WAL operations, the recovery system
 * analyzes the operation state and determines the safest recovery action.
 *
 * RECOVERY ACTIONS:
 * 1. ROLLBACK_AND_DELETE: Delete partial wallet state, force user to restart operation
 *    - Used when: Early-stage failure (before critical data committed)
 *    - Example: HD wallet created but not encrypted → DELETE wallet, user restarts wizard
 *    - Safety: Prevents leaving wallet in insecure state
 *
 * 2. COMPLETE_FORWARD: Continue operation from last checkpoint
 *    - Used when: Late-stage failure (most work done, just need to finish)
 *    - Example: Wallet encrypted and saved, just need to write COMMIT entry
 *    - Safety: Avoids forcing user to redo work
 *
 * 3. MANUAL_INTERVENTION: Cannot auto-recover, requires user decision
 *    - Used when: Ambiguous state or data corruption
 *    - Example: Checkpoint data corrupted, can't verify state
 *    - Safety: Doesn't risk making wrong decision
 *
 * RECOVERY DECISION MATRIX:
 *
 * WALLET_INITIALIZATION:
 *   - No checkpoints: ROLLBACK (delete wallet, restart wizard)
 *   - "create_hd_wallet" complete, no encryption: ROLLBACK (security risk)
 *   - "encrypt_wallet" complete, no save: COMPLETE (save wallet)
 *   - "save_wallet" complete: COMPLETE (write COMMIT, cleanup)
 *
 * WALLET_ENCRYPTION:
 *   - Master key created, not saved: ROLLBACK (revert to unencrypted)
 *   - Saved but no COMMIT: COMPLETE (write COMMIT)
 *
 * HD_WALLET_CREATION:
 *   - Mnemonic generated, not encrypted: ROLLBACK (delete HD state)
 *   - Encrypted but not saved: COMPLETE (save wallet)
 *
 * HD_WALLET_RESTORE:
 *   - Restore started, addresses not derived: ROLLBACK (cleanup partial state)
 *   - Addresses derived, not saved: COMPLETE (save wallet)
 *
 * CONSERVATIVE PRINCIPLE:
 * When in doubt, ROLLBACK. It's better to make user redo operation than to
 * leave wallet in potentially insecure or corrupted state.
 *
 * LOGGING:
 * All recovery actions are logged to stdout with detailed reasoning:
 *   [WAL RECOVERY] Analyzing operation abc123...
 *   [WAL RECOVERY] Found checkpoints: create_hd_wallet, encrypt_wallet
 *   [WAL RECOVERY] Decision: COMPLETE_FORWARD (wallet encrypted, just need save)
 *   [WAL RECOVERY] Executing: Save wallet and commit
 *   [WAL RECOVERY] Success: Operation completed
 */

#include <wallet/wal.h>
#include <string>
#include <vector>

// Forward declaration
class CWallet;

/**
 * Recovery action to take for incomplete operation
 */
enum class RecoveryAction {
    ROLLBACK_AND_DELETE,   // Delete partial state, force user to restart
    COMPLETE_FORWARD,      // Continue from last checkpoint
    MANUAL_INTERVENTION    // Cannot auto-recover, show error to user
};

/**
 * Recovery plan for an incomplete operation
 *
 * Created by AnalyzeOperation(), executed by ExecuteRecovery().
 */
struct RecoveryPlan {
    std::string operation_id;               // Operation being recovered
    WALOperation operation_type;            // Type of operation
    RecoveryAction action;                  // Recommended action
    std::vector<std::string> completed_steps;  // Steps that were completed
    std::string next_step;                  // Next step to execute (if COMPLETE_FORWARD)
    std::string reasoning;                  // Human-readable reasoning for decision
    std::string error_message;              // Error message for MANUAL_INTERVENTION
};

/**
 * WAL Recovery System
 *
 * Analyzes incomplete operations and executes recovery.
 * All methods are static - no instance needed.
 *
 * USAGE:
 *   // On wallet startup, check for incomplete operations
 *   CWalletWAL wal;
 *   wal.Initialize(wallet_path);
 *
 *   std::vector<std::string> incomplete_ops;
 *   if (wal.HasIncompleteOperations(incomplete_ops)) {
 *       for (const auto& op_id : incomplete_ops) {
 *           RecoveryPlan plan;
 *           if (CWalletRecovery::AnalyzeOperation(wal, op_id, plan)) {
 *               std::cout << "[RECOVERY] " << plan.reasoning << std::endl;
 *               if (!CWalletRecovery::ExecuteRecovery(wallet, wal, plan)) {
 *                   std::cerr << "[ERROR] Recovery failed!" << std::endl;
 *               }
 *           }
 *       }
 *   }
 */
class CWalletRecovery {
public:
    /**
     * Analyze incomplete operation and create recovery plan
     *
     * Examines operation type and completed checkpoints to determine
     * safest recovery action.
     *
     * @param wal WAL instance (must be initialized)
     * @param operation_id Operation ID to analyze
     * @param plan_out Output: Recovery plan
     * @return true if analysis successful, false if operation not found or corrupted
     */
    static bool AnalyzeOperation(const CWalletWAL& wal,
                                 const std::string& operation_id,
                                 RecoveryPlan& plan_out);

    /**
     * Execute recovery plan
     *
     * Performs recovery action (ROLLBACK, COMPLETE, or MANUAL).
     * For ROLLBACK: Deletes partial wallet state, writes ROLLBACK to WAL
     * For COMPLETE: Finishes pending steps, writes COMMIT to WAL
     * For MANUAL: Displays error message and returns false
     *
     * @param wallet Wallet instance (may be null for some operations)
     * @param wal WAL instance (must be initialized, non-const for writing)
     * @param plan Recovery plan from AnalyzeOperation()
     * @return true if recovery successful, false if recovery failed
     */
    static bool ExecuteRecovery(CWallet* wallet,
                                CWalletWAL& wal,
                                const RecoveryPlan& plan);

private:
    /**
     * Analyze WALLET_INITIALIZATION operation
     *
     * Decision logic:
     * - No checkpoints → ROLLBACK (nothing done yet)
     * - Only "create_hd_wallet" → ROLLBACK (unencrypted HD wallet is insecure)
     * - "create_hd_wallet" + "encrypt_wallet" → COMPLETE (just need save)
     * - All checkpoints → COMPLETE (just need COMMIT)
     *
     * @param steps All entries for this operation
     * @param plan_out Output: Recovery plan
     */
    static void AnalyzeInitialization(const std::vector<WALEntry>& steps,
                                      RecoveryPlan& plan_out);

    /**
     * Analyze WALLET_ENCRYPTION operation
     *
     * Decision logic:
     * - Master key created but not saved → ROLLBACK (unsafe partial encryption)
     * - Saved but no COMMIT → COMPLETE (just write COMMIT)
     *
     * @param steps All entries for this operation
     * @param plan_out Output: Recovery plan
     */
    static void AnalyzeEncryption(const std::vector<WALEntry>& steps,
                                  RecoveryPlan& plan_out);

    /**
     * Analyze HD_WALLET_CREATION operation
     *
     * Decision logic:
     * - Mnemonic generated but not encrypted → ROLLBACK (security risk)
     * - Encrypted but not saved → COMPLETE (save wallet)
     *
     * @param steps All entries for this operation
     * @param plan_out Output: Recovery plan
     */
    static void AnalyzeHDCreation(const std::vector<WALEntry>& steps,
                                  RecoveryPlan& plan_out);

    /**
     * Analyze HD_WALLET_RESTORE operation
     *
     * Decision logic:
     * - Restore started but addresses not derived → ROLLBACK (cleanup)
     * - Addresses derived but not saved → COMPLETE (save wallet)
     *
     * @param steps All entries for this operation
     * @param plan_out Output: Recovery plan
     */
    static void AnalyzeRestore(const std::vector<WALEntry>& steps,
                               RecoveryPlan& plan_out);

    /**
     * Rollback wallet initialization
     *
     * Deletes wallet.dat file, forces user to restart setup wizard.
     *
     * @param wallet Wallet instance (may be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being rolled back
     * @return true if rollback successful
     */
    static bool RollbackInitialization(CWallet* wallet,
                                       CWalletWAL& wal,
                                       const std::string& operation_id);

    /**
     * Complete wallet initialization
     *
     * Saves wallet and writes COMMIT to WAL.
     *
     * @param wallet Wallet instance (must not be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being completed
     * @param wallet_path Path to wallet.dat
     * @return true if completion successful
     */
    static bool CompleteInitialization(CWallet* wallet,
                                       CWalletWAL& wal,
                                       const std::string& operation_id,
                                       const std::string& wallet_path);

    /**
     * Rollback wallet encryption
     *
     * Reverts wallet to unencrypted state.
     * WARNING: This is destructive - encrypted keys will be lost!
     *
     * @param wallet Wallet instance (must not be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being rolled back
     * @return true if rollback successful
     */
    static bool RollbackEncryption(CWallet* wallet,
                                   CWalletWAL& wal,
                                   const std::string& operation_id);

    /**
     * Complete wallet encryption
     *
     * Writes COMMIT to WAL (wallet already encrypted and saved).
     *
     * @param wallet Wallet instance (must not be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being completed
     * @return true if completion successful
     */
    static bool CompleteEncryption(CWallet* wallet,
                                   CWalletWAL& wal,
                                   const std::string& operation_id);

    /**
     * Rollback HD wallet creation
     *
     * Clears HD wallet state from wallet (keeps regular keys).
     *
     * @param wallet Wallet instance (must not be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being rolled back
     * @return true if rollback successful
     */
    static bool RollbackHDCreation(CWallet* wallet,
                                   CWalletWAL& wal,
                                   const std::string& operation_id);

    /**
     * Complete HD wallet creation
     *
     * Saves wallet with HD state and writes COMMIT to WAL.
     *
     * @param wallet Wallet instance (must not be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being completed
     * @param wallet_path Path to wallet.dat
     * @return true if completion successful
     */
    static bool CompleteHDCreation(CWallet* wallet,
                                   CWalletWAL& wal,
                                   const std::string& operation_id,
                                   const std::string& wallet_path);

    /**
     * Rollback HD wallet restore
     *
     * Clears HD wallet state from wallet.
     *
     * @param wallet Wallet instance (must not be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being rolled back
     * @return true if rollback successful
     */
    static bool RollbackRestore(CWallet* wallet,
                                CWalletWAL& wal,
                                const std::string& operation_id);

    /**
     * Complete HD wallet restore
     *
     * Saves wallet with restored HD state and writes COMMIT to WAL.
     *
     * @param wallet Wallet instance (must not be null)
     * @param wal WAL instance
     * @param operation_id Operation ID being completed
     * @param wallet_path Path to wallet.dat
     * @return true if completion successful
     */
    static bool CompleteRestore(CWallet* wallet,
                                CWalletWAL& wal,
                                const std::string& operation_id,
                                const std::string& wallet_path);
};

#endif // DILITHION_WALLET_WAL_RECOVERY_H
