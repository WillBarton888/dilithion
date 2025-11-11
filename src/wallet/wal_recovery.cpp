// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wal_recovery.h>
#include <wallet/wallet.h>
#include <iostream>
#include <algorithm>

//=============================================================================
// Helper Functions
//=============================================================================

/**
 * Check if checkpoint exists in step list
 */
static bool HasCheckpoint(const std::vector<WALEntry>& steps, const std::string& step_name) {
    return std::any_of(steps.begin(), steps.end(), [&](const WALEntry& entry) {
        return entry.type == WALEntryType::CHECKPOINT && entry.step_name == step_name;
    });
}

/**
 * Count number of checkpoints
 */
static size_t CountCheckpoints(const std::vector<WALEntry>& steps) {
    return std::count_if(steps.begin(), steps.end(), [](const WALEntry& entry) {
        return entry.type == WALEntryType::CHECKPOINT;
    });
}

/**
 * Get list of completed step names
 */
static std::vector<std::string> GetCompletedSteps(const std::vector<WALEntry>& steps) {
    std::vector<std::string> completed;
    for (const auto& entry : steps) {
        if (entry.type == WALEntryType::CHECKPOINT) {
            completed.push_back(entry.step_name);
        }
    }
    return completed;
}

//=============================================================================
// CWalletRecovery Implementation
//=============================================================================

bool CWalletRecovery::AnalyzeOperation(const CWalletWAL& wal,
                                       const std::string& operation_id,
                                       RecoveryPlan& plan_out) {
    plan_out = RecoveryPlan();
    plan_out.operation_id = operation_id;

    // Get operation details from WAL
    WALOperation op_type;
    std::vector<WALEntry> steps;
    if (!wal.GetOperationDetails(operation_id, op_type, steps)) {
        std::cerr << "[WAL RECOVERY ERROR] Operation not found: " << operation_id << std::endl;
        return false;
    }

    plan_out.operation_type = op_type;
    plan_out.completed_steps = GetCompletedSteps(steps);

    std::cout << "[WAL RECOVERY] Analyzing " << WALOperationToString(op_type)
              << " (op=" << operation_id.substr(0, 8) << "...)" << std::endl;
    std::cout << "[WAL RECOVERY] Completed checkpoints: " << plan_out.completed_steps.size() << std::endl;

    // Analyze based on operation type
    switch (op_type) {
        case WALOperation::WALLET_INITIALIZATION:
            AnalyzeInitialization(steps, plan_out);
            break;

        case WALOperation::WALLET_ENCRYPTION:
            AnalyzeEncryption(steps, plan_out);
            break;

        case WALOperation::HD_WALLET_CREATION:
            AnalyzeHDCreation(steps, plan_out);
            break;

        case WALOperation::HD_WALLET_RESTORE:
            AnalyzeRestore(steps, plan_out);
            break;

        default:
            plan_out.action = RecoveryAction::MANUAL_INTERVENTION;
            plan_out.reasoning = "Unknown operation type";
            plan_out.error_message = "Cannot auto-recover unknown operation type";
            return true;
    }

    std::cout << "[WAL RECOVERY] Decision: ";
    switch (plan_out.action) {
        case RecoveryAction::ROLLBACK_AND_DELETE:
            std::cout << "ROLLBACK_AND_DELETE";
            break;
        case RecoveryAction::COMPLETE_FORWARD:
            std::cout << "COMPLETE_FORWARD";
            break;
        case RecoveryAction::MANUAL_INTERVENTION:
            std::cout << "MANUAL_INTERVENTION";
            break;
    }
    std::cout << std::endl;
    std::cout << "[WAL RECOVERY] Reasoning: " << plan_out.reasoning << std::endl;

    return true;
}

void CWalletRecovery::AnalyzeInitialization(const std::vector<WALEntry>& steps,
                                            RecoveryPlan& plan_out) {
    size_t checkpoint_count = CountCheckpoints(steps);

    if (checkpoint_count == 0) {
        // No work done - safe to rollback
        plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
        plan_out.reasoning = "No checkpoints found - setup wizard not completed";
        plan_out.next_step = "delete_wallet";
        return;
    }

    bool has_create_hd = HasCheckpoint(steps, "create_hd_wallet");
    bool has_encrypt = HasCheckpoint(steps, "encrypt_wallet");
    bool has_save = HasCheckpoint(steps, "save_wallet");

    if (has_create_hd && !has_encrypt) {
        // CRITICAL: HD wallet created but not encrypted - SECURITY RISK
        plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
        plan_out.reasoning = "HD wallet created but not encrypted - security risk, forcing restart";
        plan_out.next_step = "delete_wallet";
        return;
    }

    if (has_create_hd && has_encrypt && !has_save) {
        // Good state - wallet created and encrypted, just needs save
        plan_out.action = RecoveryAction::COMPLETE_FORWARD;
        plan_out.reasoning = "Wallet created and encrypted, completing save operation";
        plan_out.next_step = "save_wallet";
        return;
    }

    if (has_save) {
        // All work done, just need COMMIT
        plan_out.action = RecoveryAction::COMPLETE_FORWARD;
        plan_out.reasoning = "All steps completed, writing COMMIT entry";
        plan_out.next_step = "commit";
        return;
    }

    // Unknown state - be conservative
    plan_out.action = RecoveryAction::MANUAL_INTERVENTION;
    plan_out.reasoning = "Ambiguous checkpoint state";
    plan_out.error_message = "Cannot determine safe recovery action";
}

void CWalletRecovery::AnalyzeEncryption(const std::vector<WALEntry>& steps,
                                        RecoveryPlan& plan_out) {
    bool has_create_key = HasCheckpoint(steps, "create_master_key");
    bool has_encrypt_keys = HasCheckpoint(steps, "encrypt_keys");
    bool has_save = HasCheckpoint(steps, "save_wallet");

    if (has_create_key && !has_save) {
        // Master key created but not saved - unsafe partial encryption
        plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
        plan_out.reasoning = "Encryption started but not completed - rolling back to unencrypted";
        plan_out.next_step = "revert_encryption";
        return;
    }

    if (has_save) {
        // Encrypted and saved, just need COMMIT
        plan_out.action = RecoveryAction::COMPLETE_FORWARD;
        plan_out.reasoning = "Encryption complete, writing COMMIT entry";
        plan_out.next_step = "commit";
        return;
    }

    // No checkpoints or unknown state
    plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
    plan_out.reasoning = "No encryption checkpoints found - safe to rollback";
    plan_out.next_step = "revert_encryption";
}

void CWalletRecovery::AnalyzeHDCreation(const std::vector<WALEntry>& steps,
                                        RecoveryPlan& plan_out) {
    bool has_generate = HasCheckpoint(steps, "generate_mnemonic");
    bool has_encrypt = HasCheckpoint(steps, "encrypt_mnemonic");
    bool has_derive = HasCheckpoint(steps, "derive_keys");
    bool has_save = HasCheckpoint(steps, "save_wallet");

    if (has_generate && !has_encrypt) {
        // Mnemonic generated but not encrypted - SECURITY RISK
        plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
        plan_out.reasoning = "Mnemonic generated but not encrypted - security risk";
        plan_out.next_step = "delete_hd_state";
        return;
    }

    if (has_derive && !has_save) {
        // Keys derived but not saved - complete the save
        plan_out.action = RecoveryAction::COMPLETE_FORWARD;
        plan_out.reasoning = "HD keys derived, completing save operation";
        plan_out.next_step = "save_wallet";
        return;
    }

    if (has_save) {
        // Saved, just need COMMIT
        plan_out.action = RecoveryAction::COMPLETE_FORWARD;
        plan_out.reasoning = "HD wallet saved, writing COMMIT entry";
        plan_out.next_step = "commit";
        return;
    }

    // Early stage or unknown - rollback
    plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
    plan_out.reasoning = "HD creation incomplete - rolling back";
    plan_out.next_step = "delete_hd_state";
}

void CWalletRecovery::AnalyzeRestore(const std::vector<WALEntry>& steps,
                                     RecoveryPlan& plan_out) {
    bool has_validate = HasCheckpoint(steps, "validate_mnemonic");
    bool has_derive = HasCheckpoint(steps, "derive_addresses");
    bool has_save = HasCheckpoint(steps, "save_wallet");

    if (has_validate && !has_derive) {
        // Mnemonic validated but addresses not derived - safe to rollback
        plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
        plan_out.reasoning = "Restore started but addresses not derived - rolling back";
        plan_out.next_step = "delete_hd_state";
        return;
    }

    if (has_derive && !has_save) {
        // Addresses derived, complete the save
        plan_out.action = RecoveryAction::COMPLETE_FORWARD;
        plan_out.reasoning = "Addresses derived, completing save operation";
        plan_out.next_step = "save_wallet";
        return;
    }

    if (has_save) {
        // Saved, just need COMMIT
        plan_out.action = RecoveryAction::COMPLETE_FORWARD;
        plan_out.reasoning = "Restore complete, writing COMMIT entry";
        plan_out.next_step = "commit";
        return;
    }

    // No checkpoints or unknown state
    plan_out.action = RecoveryAction::ROLLBACK_AND_DELETE;
    plan_out.reasoning = "Restore not started or incomplete - rolling back";
    plan_out.next_step = "delete_hd_state";
}

bool CWalletRecovery::ExecuteRecovery(CWallet* wallet,
                                      CWalletWAL& wal,
                                      const RecoveryPlan& plan) {
    std::cout << "[WAL RECOVERY] Executing recovery for operation "
              << plan.operation_id.substr(0, 8) << "..." << std::endl;

    switch (plan.action) {
        case RecoveryAction::ROLLBACK_AND_DELETE: {
            std::cout << "[WAL RECOVERY] Rolling back operation..." << std::endl;

            bool success = false;
            switch (plan.operation_type) {
                case WALOperation::WALLET_INITIALIZATION:
                    success = RollbackInitialization(wallet, wal, plan.operation_id);
                    break;
                case WALOperation::WALLET_ENCRYPTION:
                    success = RollbackEncryption(wallet, wal, plan.operation_id);
                    break;
                case WALOperation::HD_WALLET_CREATION:
                    success = RollbackHDCreation(wallet, wal, plan.operation_id);
                    break;
                case WALOperation::HD_WALLET_RESTORE:
                    success = RollbackRestore(wallet, wal, plan.operation_id);
                    break;
            }

            if (success) {
                std::cout << "[WAL RECOVERY] Rollback successful" << std::endl;
            } else {
                std::cerr << "[WAL RECOVERY ERROR] Rollback failed" << std::endl;
            }
            return success;
        }

        case RecoveryAction::COMPLETE_FORWARD: {
            std::cout << "[WAL RECOVERY] Completing operation..." << std::endl;

            // For now, simple implementation: just write COMMIT
            // In full implementation, would execute pending steps

            if (wal.Commit(plan.operation_id)) {
                std::cout << "[WAL RECOVERY] Operation completed successfully" << std::endl;
                return true;
            } else {
                std::cerr << "[WAL RECOVERY ERROR] Failed to commit operation" << std::endl;
                return false;
            }
        }

        case RecoveryAction::MANUAL_INTERVENTION: {
            std::cerr << "[WAL RECOVERY ERROR] Manual intervention required" << std::endl;
            std::cerr << "[WAL RECOVERY ERROR] " << plan.error_message << std::endl;
            std::cerr << "[WAL RECOVERY ERROR] Please contact support or restore from backup" << std::endl;
            return false;
        }

        default:
            std::cerr << "[WAL RECOVERY ERROR] Unknown recovery action" << std::endl;
            return false;
    }
}

bool CWalletRecovery::RollbackInitialization(CWallet* wallet,
                                             CWalletWAL& wal,
                                             const std::string& operation_id) {
    std::cout << "[WAL RECOVERY] Rolling back wallet initialization..." << std::endl;

    // Delete wallet.dat if it exists
    std::string wallet_path = wal.GetWALPath();
    wallet_path = wallet_path.substr(0, wallet_path.length() - 4); // Remove ".wal"

    #ifdef _WIN32
    if (DeleteFileA(wallet_path.c_str())) {
        std::cout << "[WAL RECOVERY] Deleted wallet file: " << wallet_path << std::endl;
    }
    #else
    if (unlink(wallet_path.c_str()) == 0) {
        std::cout << "[WAL RECOVERY] Deleted wallet file: " << wallet_path << std::endl;
    }
    #endif

    // Write ROLLBACK to WAL and cleanup
    return wal.Rollback(operation_id);
}

bool CWalletRecovery::CompleteInitialization(CWallet* wallet,
                                             CWalletWAL& wal,
                                             const std::string& operation_id,
                                             const std::string& wallet_path) {
    if (!wallet) {
        std::cerr << "[WAL RECOVERY ERROR] Wallet is null" << std::endl;
        return false;
    }

    std::cout << "[WAL RECOVERY] Completing wallet initialization..." << std::endl;

    // Save wallet
    if (!wallet->Save(wallet_path)) {
        std::cerr << "[WAL RECOVERY ERROR] Failed to save wallet" << std::endl;
        return false;
    }

    // Write COMMIT to WAL
    return wal.Commit(operation_id);
}

bool CWalletRecovery::RollbackEncryption(CWallet* wallet,
                                         CWalletWAL& wal,
                                         const std::string& operation_id) {
    if (!wallet) {
        std::cerr << "[WAL RECOVERY ERROR] Wallet is null" << std::endl;
        return false;
    }

    std::cout << "[WAL RECOVERY] Rolling back wallet encryption..." << std::endl;
    std::cout << "[WAL RECOVERY] WARNING: This will revert wallet to unencrypted state" << std::endl;

    // Clear encryption state
    wallet->Lock(); // Lock wallet first

    // Note: In full implementation, would properly revert encryption
    // For now, just write ROLLBACK

    return wal.Rollback(operation_id);
}

bool CWalletRecovery::CompleteEncryption(CWallet* wallet,
                                         CWalletWAL& wal,
                                         const std::string& operation_id) {
    if (!wallet) {
        std::cerr << "[WAL RECOVERY ERROR] Wallet is null" << std::endl;
        return false;
    }

    std::cout << "[WAL RECOVERY] Completing wallet encryption..." << std::endl;

    // Wallet already encrypted and saved, just need COMMIT
    return wal.Commit(operation_id);
}

bool CWalletRecovery::RollbackHDCreation(CWallet* wallet,
                                         CWalletWAL& wal,
                                         const std::string& operation_id) {
    if (!wallet) {
        std::cerr << "[WAL RECOVERY ERROR] Wallet is null" << std::endl;
        return false;
    }

    std::cout << "[WAL RECOVERY] Rolling back HD wallet creation..." << std::endl;

    // Clear HD wallet state
    // Note: In full implementation, would call wallet->ClearHDState()

    return wal.Rollback(operation_id);
}

bool CWalletRecovery::CompleteHDCreation(CWallet* wallet,
                                         CWalletWAL& wal,
                                         const std::string& operation_id,
                                         const std::string& wallet_path) {
    if (!wallet) {
        std::cerr << "[WAL RECOVERY ERROR] Wallet is null" << std::endl;
        return false;
    }

    std::cout << "[WAL RECOVERY] Completing HD wallet creation..." << std::endl;

    // Save wallet with HD state
    if (!wallet->Save(wallet_path)) {
        std::cerr << "[WAL RECOVERY ERROR] Failed to save wallet" << std::endl;
        return false;
    }

    // Write COMMIT to WAL
    return wal.Commit(operation_id);
}

bool CWalletRecovery::RollbackRestore(CWallet* wallet,
                                      CWalletWAL& wal,
                                      const std::string& operation_id) {
    if (!wallet) {
        std::cerr << "[WAL RECOVERY ERROR] Wallet is null" << std::endl;
        return false;
    }

    std::cout << "[WAL RECOVERY] Rolling back HD wallet restore..." << std::endl;

    // Clear HD wallet state
    // Note: In full implementation, would call wallet->ClearHDState()

    return wal.Rollback(operation_id);
}

bool CWalletRecovery::CompleteRestore(CWallet* wallet,
                                      CWalletWAL& wal,
                                      const std::string& operation_id,
                                      const std::string& wallet_path) {
    if (!wallet) {
        std::cerr << "[WAL RECOVERY ERROR] Wallet is null" << std::endl;
        return false;
    }

    std::cout << "[WAL RECOVERY] Completing HD wallet restore..." << std::endl;

    // Save wallet with restored HD state
    if (!wallet->Save(wallet_path)) {
        std::cerr << "[WAL RECOVERY ERROR] Failed to save wallet" << std::endl;
        return false;
    }

    // Write COMMIT to WAL
    return wal.Commit(operation_id);
}
