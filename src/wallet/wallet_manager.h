// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_WALLET_MANAGER_H
#define DILITHION_WALLET_WALLET_MANAGER_H

#include <wallet/wallet.h>
#include <string>
#include <vector>
#include <chrono>

/**
 * CWalletManager - User-friendly wallet management interface
 *
 * Provides high-level wallet operations with:
 * - Security warnings and best practices
 * - Auto-backup functionality
 * - Interactive prompts
 * - Input validation
 */
class CWalletManager {
private:
    CWallet* m_wallet;
    std::string m_backup_directory;
    bool m_auto_backup_enabled;
    std::chrono::minutes m_backup_interval;
    std::chrono::system_clock::time_point m_last_backup;

    /**
     * Print security warning about mnemonic storage
     */
    void PrintMnemonicSecurityWarning() const;

    /**
     * Print passphrase best practices
     */
    void PrintPassphraseBestPractices() const;

    /**
     * Validate passphrase strength
     */
    bool ValidatePassphraseStrength(const std::string& passphrase, std::string& feedback) const;

    /**
     * Create backup of wallet and mnemonic
     */
    bool CreateBackup(const std::string& backup_name, std::string& backup_path);

    /**
     * Prompt user for confirmation
     */
    bool PromptConfirmation(const std::string& message) const;

    /**
     * Print formatted message
     */
    void PrintMessage(const std::string& message, const std::string& type = "INFO") const;

    /**
     * Print success message
     */
    void PrintSuccess(const std::string& message) const;

    /**
     * Print error message
     */
    void PrintError(const std::string& message) const;

    /**
     * Print warning message
     */
    void PrintWarning(const std::string& message) const;

public:
    /**
     * Constructor
     */
    explicit CWalletManager(CWallet* wallet);

    /**
     * Enable auto-backup
     * @param backup_dir Directory for backups
     * @param interval_minutes Backup interval in minutes (default: 60)
     */
    void EnableAutoBackup(const std::string& backup_dir, int interval_minutes = 60);

    /**
     * Disable auto-backup
     */
    void DisableAutoBackup();

    /**
     * Check if auto-backup is due and perform if necessary
     */
    void CheckAndPerformAutoBackup();

    /**
     * Interactive HD wallet creation flow
     * Guides user through wallet creation with security warnings
     */
    bool InteractiveCreateHDWallet(std::string& mnemonic_out);

    /**
     * Interactive HD wallet restoration flow
     * Guides user through restoration with validation
     */
    bool InteractiveRestoreHDWallet();

    /**
     * Interactive mnemonic export
     * Warns user about security risks
     */
    bool InteractiveExportMnemonic(std::string& mnemonic_out);

    /**
     * Display wallet status with recommendations
     */
    void DisplayWalletStatus() const;

    /**
     * Create manual backup
     */
    bool CreateManualBackup(std::string& backup_path);

    /**
     * Verify wallet backup
     */
    bool VerifyBackup(const std::string& backup_path) const;

    /**
     * Display security checklist
     */
    void DisplaySecurityChecklist() const;

    /**
     * Run first-time setup wizard
     * Mandatory wizard for new users on first wallet launch
     * Returns true if setup completed successfully, false if cancelled
     */
    bool RunFirstTimeSetupWizard();

    /**
     * Display welcome screen for first-time users
     */
    void DisplayWelcomeScreen() const;

    /**
     * Calculate security score (0-100)
     * Based on encryption, backups, and best practices
     */
    int CalculateSecurityScore() const;

    /**
     * Display security score with recommendations
     */
    void DisplaySecurityScore() const;

    /**
     * Prompt for and encrypt wallet with strong passphrase
     * Returns true if encryption successful
     */
    bool PromptAndEncryptWallet();

    /**
     * Warn user before large transaction
     * @param amount Transaction amount
     * @param address Recipient address
     * Returns true if user confirms, false to cancel
     */
    bool WarnLargeTransaction(double amount, const std::string& address) const;

    /**
     * Check if this is first run (no wallet exists)
     */
    static bool IsFirstRun();

    /**
     * Get backup directory
     */
    std::string GetBackupDirectory() const { return m_backup_directory; }

    /**
     * Is auto-backup enabled
     */
    bool IsAutoBackupEnabled() const { return m_auto_backup_enabled; }
};

#endif // DILITHION_WALLET_WALLET_MANAGER_H
