// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet_manager.h>
#include <wallet/passphrase_validator.h>
#include <wallet/mnemonic.h>  // PERSIST-006 FIX: BIP39 validation
#include <util/strencodings.h>
#include <rpc/auth.h>  // FIX-001 (CRYPT-003): Constant-time passphrase comparison
#include <iostream>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <sys/stat.h>

#ifdef _WIN32
    #include <direct.h>
    #include <windows.h>  // CID 1675185: For GetLastError and ERROR_ALREADY_EXISTS
    #define mkdir(path, mode) _mkdir(path)
#else
    #include <unistd.h>
    #include <errno.h>  // CID 1675185: For errno and EEXIST
    #include <cstring>  // CID 1675185: For strerror
#endif

// ANSI color codes for terminal output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

// FIX-001 (CRYPT-003): Constant-time string comparison helper
// Prevents timing attacks on passphrase comparison
static bool SecureStringCompare(const std::string& a, const std::string& b) {
    // Length check must also be constant-time
    size_t len_a = a.length();
    size_t len_b = b.length();

    // Pad to max length for constant-time comparison
    const size_t MAX_LEN = 256;
    uint8_t buf_a[MAX_LEN] = {0};
    uint8_t buf_b[MAX_LEN] = {0};

    memcpy(buf_a, a.data(), std::min(len_a, MAX_LEN));
    memcpy(buf_b, b.data(), std::min(len_b, MAX_LEN));

    // Constant-time buffer comparison
    bool match = RPCAuth::SecureCompare(buf_a, buf_b, MAX_LEN);

    // Length must also match
    return match && (len_a == len_b);
}

CWalletManager::CWalletManager(CWallet* wallet)
    : m_wallet(wallet)
    , m_auto_backup_enabled(false)
    , m_backup_interval(std::chrono::minutes(60))
    , m_last_backup(std::chrono::system_clock::now())
{
}

void CWalletManager::EnableAutoBackup(const std::string& backup_dir, int interval_minutes) {
    m_backup_directory = backup_dir;
    m_backup_interval = std::chrono::minutes(interval_minutes);
    m_auto_backup_enabled = true;

    // Create backup directory if it doesn't exist
    // CID 1675185 FIX: Check return value of mkdir to ensure directory is created
    // mkdir returns 0 on success, -1 on error
    // EEXIST (directory already exists) is not an error
#ifdef _WIN32
    if (_mkdir(backup_dir.c_str()) != 0) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            PrintError("Failed to create backup directory: " + backup_dir);
            std::cerr << "  Error code: " << error << std::endl;
        }
    }
#else
    if (mkdir(backup_dir.c_str(), 0700) != 0) {
        if (errno != EEXIST) {
            PrintError("Failed to create backup directory: " + backup_dir);
            std::cerr << "  Error: " << strerror(errno) << std::endl;
        }
    }
#endif

    PrintSuccess("Auto-backup enabled");
    std::cout << "  Backup directory: " << backup_dir << std::endl;
    std::cout << "  Backup interval: " << interval_minutes << " minutes" << std::endl;
}

void CWalletManager::DisableAutoBackup() {
    m_auto_backup_enabled = false;
    PrintWarning("Auto-backup disabled");
}

void CWalletManager::CheckAndPerformAutoBackup() {
    if (!m_auto_backup_enabled) {
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - m_last_backup);

    if (elapsed >= m_backup_interval) {
        std::string backup_path;
        if (CreateBackup("auto", backup_path)) {
            m_last_backup = now;
            PrintSuccess("Auto-backup completed: " + backup_path);
        } else {
            PrintError("Auto-backup failed");
        }
    }
}

void CWalletManager::PrintMnemonicSecurityWarning() const {
    std::cout << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "║              CRITICAL SECURITY WARNING                       ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "Your recovery phrase (mnemonic) is the ONLY way to restore your wallet!" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_BOLD << "DO:" << COLOR_RESET << std::endl;
    std::cout << "  ✓ Write it down on paper (pen, not pencil)" << std::endl;
    std::cout << "  ✓ Store in a fireproof/waterproof safe" << std::endl;
    std::cout << "  ✓ Make multiple copies in different locations" << std::endl;
    std::cout << "  ✓ Test restoration BEFORE funding wallet" << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_BOLD << "DON'T:" << COLOR_RESET << std::endl;
    std::cout << "  ✗ Store in plain text file on computer" << std::endl;
    std::cout << "  ✗ Email to yourself or store in cloud" << std::endl;
    std::cout << "  ✗ Take a photo (can be hacked)" << std::endl;
    std::cout << "  ✗ Share with anyone (even support staff)" << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_RED << "If you lose this phrase, your funds are PERMANENTLY LOST!" << COLOR_RESET << std::endl;
    std::cout << std::endl;
}

void CWalletManager::PrintPassphraseBestPractices() const {
    std::cout << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "Passphrase Best Practices:" << COLOR_RESET << std::endl;
    std::cout << "  • Use 20+ characters" << std::endl;
    std::cout << "  • Mix uppercase, lowercase, numbers, symbols" << std::endl;
    std::cout << "  • Make it memorable but not guessable" << std::endl;
    std::cout << "  • Don't use personal info (birthday, name)" << std::endl;
    std::cout << "  • Don't reuse from other accounts" << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "WARNING: If you forget passphrase, funds are LOST!" << COLOR_RESET << std::endl;
    std::cout << std::endl;
}

bool CWalletManager::ValidatePassphraseStrength(const std::string& passphrase, std::string& feedback) const {
    if (passphrase.empty()) {
        return true;  // Empty passphrase is allowed (less secure)
    }

    PassphraseValidator validator;
    PassphraseValidationResult result = validator.Validate(passphrase);

    feedback = "Passphrase strength: " + PassphraseValidator::GetStrengthDescription(result.strength_score);
    feedback += " (" + std::to_string(result.strength_score) + "/100)";

    if (!result.is_valid) {
        feedback += "\n  Issues: " + result.error_message;
    }

    return result.is_valid;
}

bool CWalletManager::CreateBackup(const std::string& backup_name, std::string& backup_path) {
    // SECURITY: This function only backs up wallet STATE (address indices), NOT the mnemonic.
    // The mnemonic should ONLY exist on paper - never stored digitally.
    // This is intentional to prevent seed phrase theft from compromised systems.

    if (!m_wallet->IsHDWallet()) {
        PrintError("Not an HD wallet");
        return false;
    }

    // Generate timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_now;

#ifdef _WIN32
    localtime_s(&tm_now, &time_t_now);
#else
    localtime_r(&time_t_now, &tm_now);
#endif

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &tm_now);

    // Create backup filename
    std::string backup_filename = "wallet_state_" + backup_name + "_" + std::string(timestamp) + ".txt";
    backup_path = m_backup_directory + "/" + backup_filename;

    // Get wallet info (state only - NOT the mnemonic)
    uint32_t account, external_idx, internal_idx;
    if (!m_wallet->GetHDWalletInfo(account, external_idx, internal_idx)) {
        PrintError("Failed to get wallet info");
        return false;
    }

    // Create backup file with secure permissions
    #ifndef _WIN32
        mode_t old_umask = umask(0077);  // Remove all group/other permissions
    #endif

    std::ofstream backup_file(backup_path);

    #ifndef _WIN32
        umask(old_umask);  // Restore original umask
        if (backup_file.is_open()) {
            chmod(backup_path.c_str(), S_IRUSR | S_IWUSR);  // 0600: owner read/write only
        }
    #endif

    if (!backup_file.is_open()) {
        PrintError("Failed to create backup file");
        return false;
    }

    // Write backup - STATE ONLY, no mnemonic
    backup_file << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
    backup_file << "║          DILITHION WALLET STATE BACKUP                       ║" << std::endl;
    backup_file << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    backup_file << std::endl;
    backup_file << "NOTE: This file contains wallet STATE only (address indices)." << std::endl;
    backup_file << "Your recovery phrase is NOT stored here - it should be on paper." << std::endl;
    backup_file << std::endl;
    backup_file << "Backup Date: " << timestamp << std::endl;
    backup_file << "Wallet Type: HD (Hierarchical Deterministic)" << std::endl;
    backup_file << std::endl;
    backup_file << "════════════════════════════════════════════════════════════════" << std::endl;
    backup_file << "WALLET STATE" << std::endl;
    backup_file << "════════════════════════════════════════════════════════════════" << std::endl;
    backup_file << std::endl;
    backup_file << "Account: " << account << std::endl;
    backup_file << "Receive Address Index: " << external_idx << std::endl;
    backup_file << "Change Address Index: " << internal_idx << std::endl;
    backup_file << std::endl;
    backup_file << "════════════════════════════════════════════════════════════════" << std::endl;
    backup_file << "RESTORATION INSTRUCTIONS" << std::endl;
    backup_file << "════════════════════════════════════════════════════════════════" << std::endl;
    backup_file << std::endl;
    backup_file << "1. Get your 24-word recovery phrase from your paper backup" << std::endl;
    backup_file << "2. Install Dilithion wallet software" << std::endl;
    backup_file << "3. Run: dilithion-cli restorehdwallet '{\"mnemonic\":\"<24 words>\"}'" << std::endl;
    backup_file << "4. If you used a passphrase, add: \"passphrase\":\"<your passphrase>\"" << std::endl;
    backup_file << "5. Generate addresses up to the indices shown above" << std::endl;
    backup_file << std::endl;

    backup_file.close();

    // Set restrictive permissions (owner read/write only)
#ifndef _WIN32
    chmod(backup_path.c_str(), S_IRUSR | S_IWUSR);
#endif

    return true;
}

bool CWalletManager::PromptConfirmation(const std::string& message) const {
    std::cout << COLOR_YELLOW << message << " (y/n): " << COLOR_RESET;
    std::string response;
    std::getline(std::cin, response);
    return (response == "y" || response == "Y" || response == "yes" || response == "Yes");
}

void CWalletManager::PrintMessage(const std::string& message, const std::string& type) const {
    if (type == "SUCCESS") {
        std::cout << COLOR_GREEN << "✓ " << message << COLOR_RESET << std::endl;
    } else if (type == "ERROR") {
        std::cout << COLOR_RED << "✗ " << message << COLOR_RESET << std::endl;
    } else if (type == "WARNING") {
        std::cout << COLOR_YELLOW << "⚠ " << message << COLOR_RESET << std::endl;
    } else {
        std::cout << COLOR_CYAN << "ℹ " << message << COLOR_RESET << std::endl;
    }
}

void CWalletManager::PrintSuccess(const std::string& message) const {
    PrintMessage(message, "SUCCESS");
}

void CWalletManager::PrintError(const std::string& message) const {
    PrintMessage(message, "ERROR");
}

void CWalletManager::PrintWarning(const std::string& message) const {
    PrintMessage(message, "WARNING");
}

bool CWalletManager::InteractiveCreateHDWallet(std::string& mnemonic_out) {
    std::cout << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "║        CREATE HIERARCHICAL DETERMINISTIC (HD) WALLET        ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Check wallet state
    if (m_wallet->IsHDWallet()) {
        PrintError("Wallet is already an HD wallet");
        return false;
    }

    if (!m_wallet->IsEmpty()) {
        PrintError("Can only create HD wallet on an empty wallet");
        return false;
    }

    // Display security warning
    PrintMnemonicSecurityWarning();

    // Ask for confirmation to proceed
    if (!PromptConfirmation("Have you read and understood the security warning?")) {
        PrintWarning("Wallet creation cancelled");
        return false;
    }

    std::cout << std::endl;

    // Ask about passphrase
    std::cout << COLOR_BOLD << "Optional Passphrase (BIP39)" << COLOR_RESET << std::endl;
    std::cout << "Adding a passphrase provides extra security but:" << std::endl;
    std::cout << "  • You MUST remember both mnemonic AND passphrase" << std::endl;
    std::cout << "  • Forgetting passphrase = permanent loss of funds" << std::endl;
    std::cout << std::endl;

    std::string passphrase;
    if (PromptConfirmation("Do you want to add a passphrase?")) {
        PrintPassphraseBestPractices();

        std::cout << "Enter passphrase (or press Enter for none): ";
        std::getline(std::cin, passphrase);

        if (!passphrase.empty()) {
            std::string feedback;
            if (!ValidatePassphraseStrength(passphrase, feedback)) {
                PrintWarning(feedback);
                if (!PromptConfirmation("Passphrase is weak. Continue anyway?")) {
                    PrintWarning("Wallet creation cancelled");
                    return false;
                }
            } else {
                std::cout << COLOR_GREEN << feedback << COLOR_RESET << std::endl;
            }

            // Confirm passphrase
            std::cout << "Confirm passphrase: ";
            std::string passphrase_confirm;
            std::getline(std::cin, passphrase_confirm);

            // FIX-001 (CRYPT-003): Use constant-time comparison to prevent timing attacks
            if (!SecureStringCompare(passphrase, passphrase_confirm)) {
                PrintError("Passphrases don't match");
                return false;
            }
        }
    }

    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "Generating wallet..." << COLOR_RESET << std::endl;

    // Generate wallet
    if (!m_wallet->GenerateHDWallet(mnemonic_out, passphrase)) {
        PrintError("Failed to generate HD wallet");
        return false;
    }

    std::cout << std::endl;
    PrintSuccess("HD Wallet created successfully!");
    std::cout << std::endl;

    // Display mnemonic
    std::cout << COLOR_RED << COLOR_BOLD << "════════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "YOUR RECOVERY PHRASE (Write this down NOW!)" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "════════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_BOLD << mnemonic_out << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "════════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Get first address
    CDilithiumAddress first_address = m_wallet->GetNewHDAddress();
    std::cout << "First address: " << COLOR_GREEN << first_address.ToString() << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Prompt for verification
    std::cout << COLOR_YELLOW << "IMPORTANT: Verify you have written down your recovery phrase!" << COLOR_RESET << std::endl;
    std::cout << "Type the FIRST word of your recovery phrase to confirm: ";

    std::string first_word_confirm;
    std::getline(std::cin, first_word_confirm);

    // Extract first word from mnemonic
    size_t space_pos = mnemonic_out.find(' ');
    std::string first_word = mnemonic_out.substr(0, space_pos);

    if (first_word_confirm != first_word) {
        PrintWarning("Verification failed! Please double-check your backup.");
    } else {
        PrintSuccess("Verification successful!");
    }

    std::cout << std::endl;

    // Offer to create backup
    if (PromptConfirmation("Create encrypted backup file now?")) {
        std::string backup_path;
        if (CreateBackup("initial", backup_path)) {
            PrintSuccess("Backup created: " + backup_path);
            PrintWarning("Keep this file secure!");
        } else {
            PrintError("Backup creation failed");
        }
    }

    std::cout << std::endl;
    DisplaySecurityChecklist();

    return true;
}

/**
 * RPC-006 FIX: Two-step confirmation for wallet restore
 *
 * OLD CODE (UNSAFE):
 *   Single prompt → immediate restore
 *   Easy to accidentally overwrite wallet
 *
 * RISK SCENARIO:
 *   User types wrong command → starts restore flow
 *   User continues thinking it's informational → wallet overwritten!
 *   Original wallet keys lost → funds lost!
 *
 * NEW CODE (SAFE):
 *   1. Display current wallet info (balance, addresses)
 *   2. Show explicit WARNING about data loss
 *   3. Require typing "CONFIRM" (not just y/n)
 *   4. Second confirmation after entering mnemonic
 *   5. Final point-of-no-return warning
 *
 * Defense in depth: Multiple explicit warnings with cognitive friction
 * to prevent accidental wallet overwrites.
 */
bool CWalletManager::InteractiveRestoreHDWallet() {
    std::cout << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "║             RESTORE HD WALLET FROM MNEMONIC                  ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // RPC-006 FIX: STEP 1 - Display current wallet state
    std::cout << COLOR_RED << COLOR_BOLD << "⚠️  WARNING: WALLET RESTORE WILL OVERWRITE YOUR CURRENT WALLET ⚠️" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Show current wallet info
    std::cout << COLOR_BOLD << "Current wallet status:" << COLOR_RESET << std::endl;

    if (m_wallet->IsHDWallet()) {
        std::cout << "  • Type: HD wallet" << std::endl;

        uint32_t account, external_idx, internal_idx;
        if (m_wallet->GetHDWalletInfo(account, external_idx, internal_idx)) {
            std::cout << "  • Account: " << account << std::endl;
            std::cout << "  • Addresses generated: " << external_idx << std::endl;
        }
    } else if (!m_wallet->IsEmpty()) {
        std::cout << "  • Type: Non-HD wallet with keys" << std::endl;
    } else {
        std::cout << "  • Type: Empty wallet" << std::endl;
    }

    double balance = m_wallet->GetBalance();
    std::cout << "  • Balance: " << balance << " DIL";
    if (balance > 0) {
        std::cout << " " << COLOR_RED << "← YOU WILL LOSE ACCESS TO THESE FUNDS!" << COLOR_RESET;
    }
    std::cout << std::endl;
    std::cout << std::endl;

    // RPC-006 FIX: STEP 2 - Explicit data loss warning
    std::cout << COLOR_RED << COLOR_BOLD << "DATA LOSS WARNING:" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << "  • Your current wallet file will be PERMANENTLY OVERWRITTEN" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << "  • All private keys will be REPLACED" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << "  • Funds in current wallet will be INACCESSIBLE" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << "  • This action CANNOT be undone" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // RPC-006 FIX: STEP 3 - First confirmation (must type CONFIRM)
    std::cout << COLOR_BOLD << "Before proceeding:" << COLOR_RESET << std::endl;
    std::cout << "  1. Ensure you have backed up your CURRENT wallet" << std::endl;
    std::cout << "  2. Ensure you have your recovery phrase written down correctly" << std::endl;
    std::cout << "  3. Ensure you are restoring the CORRECT wallet" << std::endl;
    std::cout << std::endl;

    std::cout << COLOR_YELLOW << "Type '" << COLOR_BOLD << "CONFIRM" << COLOR_RESET << COLOR_YELLOW
              << "' (all caps) to proceed, or anything else to cancel: " << COLOR_RESET;

    std::string confirmation1;
    std::getline(std::cin, confirmation1);

    if (confirmation1 != "CONFIRM") {
        std::cout << std::endl;
        PrintWarning("Wallet restore cancelled");
        std::cout << std::endl;
        return false;
    }

    std::cout << std::endl;

    // Get mnemonic
    std::cout << "Enter your 24-word recovery phrase:" << std::endl;
    std::cout << "(separate words with spaces)" << std::endl;
    std::cout << COLOR_YELLOW << "> " << COLOR_RESET;

    std::string mnemonic;
    std::getline(std::cin, mnemonic);

    if (mnemonic.empty()) {
        PrintError("No mnemonic provided");
        return false;
    }

    // Validate mnemonic format
    int word_count = 1;
    for (char c : mnemonic) {
        if (c == ' ') word_count++;
    }

    if (word_count != 24 && word_count != 12) {
        PrintWarning("Expected 24 words (or 12 for lower security), got " + std::to_string(word_count));
    }

    std::cout << std::endl;

    // RPC-006 FIX: Validate mnemonic before second confirmation
    // This ensures we catch typos before point-of-no-return
    if (!CMnemonic::Validate(mnemonic)) {
        std::cout << std::endl;
        PrintError("Invalid BIP39 mnemonic phrase");
        PrintWarning("Possible issues:");
        std::cout << "  • Invalid word count (must be 12, 15, 18, 21, or 24 words)" << std::endl;
        std::cout << "  • Words not in BIP39 wordlist (typos/misspellings)" << std::endl;
        std::cout << "  • Checksum verification failed" << std::endl;
        std::cout << std::endl;
        return false;
    }

    std::cout << COLOR_GREEN << "✓ Mnemonic validation passed" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Get passphrase (if any)
    std::string passphrase;
    if (PromptConfirmation("Did you use a passphrase when creating this wallet?")) {
        std::cout << "Enter passphrase: ";
        std::getline(std::cin, passphrase);
    }

    std::cout << std::endl;

    // RPC-006 FIX: STEP 4 - Final point-of-no-return confirmation
    std::cout << COLOR_RED << COLOR_BOLD << "⚠️  FINAL WARNING ⚠️" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << "You are about to PERMANENTLY OVERWRITE your current wallet." << std::endl;
    std::cout << "After this point, there is NO UNDO." << std::endl;
    std::cout << std::endl;

    if (!PromptConfirmation("Are you ABSOLUTELY SURE you want to proceed?")) {
        std::cout << std::endl;
        PrintWarning("Wallet restore cancelled");
        std::cout << std::endl;
        return false;
    }

    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "Restoring wallet..." << COLOR_RESET << std::endl;

    // Restore wallet
    if (!m_wallet->InitializeHDWallet(mnemonic, passphrase)) {
        PrintError("Failed to restore wallet");
        PrintWarning("Possible reasons:");
        std::cout << "  • Invalid mnemonic (wrong words or order)" << std::endl;
        std::cout << "  • Incorrect passphrase" << std::endl;
        std::cout << "  • Wrong wordlist language" << std::endl;
        return false;
    }

    PrintSuccess("Wallet restored successfully!");
    std::cout << std::endl;

    // Get first address
    CDilithiumAddress first_address = m_wallet->GetNewHDAddress();
    std::cout << "First address: " << COLOR_GREEN << first_address.ToString() << COLOR_RESET << std::endl;
    std::cout << std::endl;

    PrintWarning("Verify this address matches your previous wallet!");
    std::cout << std::endl;

    // Get wallet info
    uint32_t account, external_idx, internal_idx;
    if (m_wallet->GetHDWalletInfo(account, external_idx, internal_idx)) {
        std::cout << "Wallet state after restoration:" << std::endl;
        std::cout << "  Account: " << account << std::endl;
        std::cout << "  Generated addresses: " << external_idx << std::endl;
        std::cout << std::endl;
    }

    PrintWarning("The wallet will automatically scan for used addresses");
    PrintWarning("Generate more addresses with 'getnewaddress' if needed");
    std::cout << std::endl;

    // Offer to create backup
    if (PromptConfirmation("Create backup file now?")) {
        std::string backup_path;
        if (CreateBackup("restored", backup_path)) {
            PrintSuccess("Backup created: " + backup_path);
        }
    }

    return true;
}

bool CWalletManager::InteractiveExportMnemonic(std::string& mnemonic_out) {
    std::cout << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "║                   EXPORT MNEMONIC                            ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    PrintWarning("This will display your recovery phrase on screen");
    PrintWarning("Ensure no one can see your screen and no cameras are recording");
    std::cout << std::endl;

    if (!PromptConfirmation("Are you in a secure, private location?")) {
        PrintWarning("Export cancelled");
        return false;
    }

    std::cout << std::endl;

    // Export mnemonic
    if (!m_wallet->ExportMnemonic(mnemonic_out)) {
        PrintError("Failed to export mnemonic");
        PrintWarning("Wallet may be locked. Unlock it first with 'walletpassphrase'");
        return false;
    }

    std::cout << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "════════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "YOUR RECOVERY PHRASE" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "════════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_BOLD << mnemonic_out << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "════════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    PrintWarning("Keep this phrase secure!");
    std::cout << std::endl;

    return true;
}

void CWalletManager::DisplayWalletStatus() const {
    std::cout << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "║                  WALLET STATUS                               ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Check wallet type
    if (!m_wallet->IsHDWallet()) {
        std::cout << "Wallet Type: " << COLOR_YELLOW << "Traditional (Non-HD)" << COLOR_RESET << std::endl;
        std::cout << std::endl;
        PrintWarning("Consider upgrading to HD wallet for better backup/recovery");
        std::cout << "  Run 'createhdwallet' to create a new HD wallet" << std::endl;
        std::cout << std::endl;
        return;
    }

    std::cout << "Wallet Type: " << COLOR_GREEN << "HD (Hierarchical Deterministic)" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Get wallet info
    uint32_t account, external_idx, internal_idx;
    if (m_wallet->GetHDWalletInfo(account, external_idx, internal_idx)) {
        std::cout << "Account: " << account << std::endl;
        std::cout << "Receive Addresses Generated: " << external_idx << std::endl;
        std::cout << "Change Addresses Generated: " << internal_idx << std::endl;
        std::cout << std::endl;
    }

    // Encryption status
    if (m_wallet->IsCrypted()) {
        if (m_wallet->IsLocked()) {
            std::cout << "Encryption: " << COLOR_YELLOW << "Encrypted (LOCKED)" << COLOR_RESET << std::endl;
        } else {
            std::cout << "Encryption: " << COLOR_GREEN << "Encrypted (UNLOCKED)" << COLOR_RESET << std::endl;
        }
    } else {
        std::cout << "Encryption: " << COLOR_RED << "Not Encrypted" << COLOR_RESET << std::endl;
        PrintWarning("Encrypt your wallet for security!");
    }
    std::cout << std::endl;

    // Auto-backup status
    if (m_auto_backup_enabled) {
        std::cout << "Auto-Backup: " << COLOR_GREEN << "Enabled" << COLOR_RESET << std::endl;
        std::cout << "  Directory: " << m_backup_directory << std::endl;
        std::cout << "  Interval: " << m_backup_interval.count() << " minutes" << std::endl;
    } else {
        std::cout << "Auto-Backup: " << COLOR_YELLOW << "Disabled" << COLOR_RESET << std::endl;
        PrintWarning("Enable auto-backup for safety!");
    }
    std::cout << std::endl;

    // Security recommendations
    std::cout << COLOR_BOLD << "Security Recommendations:" << COLOR_RESET << std::endl;

    bool has_recommendations = false;

    if (!m_wallet->IsCrypted()) {
        std::cout << "  • Encrypt wallet with strong passphrase" << std::endl;
        has_recommendations = true;
    }

    if (!m_auto_backup_enabled) {
        std::cout << "  • Enable auto-backup" << std::endl;
        has_recommendations = true;
    }

    if (!has_recommendations) {
        std::cout << "  " << COLOR_GREEN << "✓ Wallet is well-protected" << COLOR_RESET << std::endl;
    }

    std::cout << std::endl;
}

bool CWalletManager::CreateManualBackup(std::string& backup_path) {
    std::cout << std::endl;
    std::cout << COLOR_CYAN << "Creating manual backup..." << COLOR_RESET << std::endl;

    if (CreateBackup("manual", backup_path)) {
        PrintSuccess("Backup created successfully");
        std::cout << "  Location: " << backup_path << std::endl;
        std::cout << std::endl;
        PrintWarning("Keep this file secure!");
        PrintWarning("Anyone with access to this file can access your funds");
        std::cout << std::endl;
        return true;
    }

    return false;
}

/**
 * PERSIST-006 FIX: Proper BIP39 backup verification
 *
 * OLD CODE (WEAK):
 *   Only checked word count (12 or 24 words)
 *   Did NOT validate:
 *     - Words are from BIP39 wordlist
 *     - BIP39 checksum is correct
 *     - Mnemonic structure is valid
 *
 * ATTACK SCENARIO:
 *   User writes down 24 random words (not a valid mnemonic)
 *   VerifyBackup() says "valid" ← FALSE SECURITY!
 *   User loses paper backup
 *   Tries to restore wallet → Invalid mnemonic, funds lost!
 *
 * NEW CODE (SECURE):
 *   Uses CMnemonic::Validate() which checks:
 *     1. Valid word count (12, 15, 18, 21, or 24)
 *     2. All words in BIP39 wordlist
 *     3. BIP39 checksum verification
 *     4. Proper entropy extraction
 *
 * This ensures backup verification catches corrupted/invalid mnemonics
 * BEFORE user loses access to their wallet file.
 */
bool CWalletManager::VerifyBackup(const std::string& backup_path) const {
    std::ifstream backup_file(backup_path);
    if (!backup_file.is_open()) {
        PrintError("Cannot open backup file: " + backup_path);
        return false;
    }

    // Read backup file and look for mnemonic lines
    std::string line;
    std::vector<std::string> candidate_lines;

    while (std::getline(backup_file, line)) {
        // Skip empty lines and obvious non-mnemonic lines
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Look for lines with space-separated words
        if (line.find(' ') != std::string::npos) {
            candidate_lines.push_back(line);
        }
    }

    backup_file.close();

    // Try to validate each candidate line as a BIP39 mnemonic
    for (const std::string& candidate : candidate_lines) {
        // PERSIST-006 FIX: Use proper BIP39 validation with checksum verification
        if (CMnemonic::Validate(candidate)) {
            // Extract word count for informative message
            int word_count = 1;
            for (char c : candidate) {
                if (c == ' ') word_count++;
            }

            std::cout << std::endl;
            PrintSuccess("Backup file contains valid BIP39 mnemonic");
            std::cout << "  • Word count: " << word_count << std::endl;
            std::cout << "  • Checksum: VALID" << std::endl;
            std::cout << "  • All words verified in BIP39 wordlist" << std::endl;
            std::cout << std::endl;

            return true;
        }
    }

    // No valid mnemonic found
    if (candidate_lines.empty()) {
        std::cout << std::endl;
        PrintError("Backup file does not contain a mnemonic phrase");
        std::cout << "  Expected format: 12, 15, 18, 21, or 24 space-separated words" << std::endl;
        std::cout << std::endl;
        return false;
    } else {
        std::cout << std::endl;
        PrintError("Backup file contains mnemonic-like data but BIP39 validation failed");
        std::cout << "  Possible issues:" << std::endl;
        std::cout << "  • Invalid word count (must be 12, 15, 18, 21, or 24 words)" << std::endl;
        std::cout << "  • Words not in BIP39 wordlist (typos/misspellings)" << std::endl;
        std::cout << "  • Checksum verification failed (corrupted backup)" << std::endl;
        std::cout << std::endl;
        std::cout << "  Candidate lines found: " << candidate_lines.size() << std::endl;
        std::cout << std::endl;

        // Show first candidate for debugging
        if (!candidate_lines.empty()) {
            PrintWarning("First candidate line:");
            std::cout << "  \"" << candidate_lines[0].substr(0, 80);
            if (candidate_lines[0].length() > 80) {
                std::cout << "...";
            }
            std::cout << "\"" << std::endl;
            std::cout << std::endl;
        }

        return false;
    }
}

void CWalletManager::DisplaySecurityChecklist() const {
    std::cout << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "║              SECURITY CHECKLIST                              ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    std::cout << "Before funding your wallet, ensure:" << std::endl;
    std::cout << std::endl;
    std::cout << "  [ ] Recovery phrase written down on paper" << std::endl;
    std::cout << "  [ ] Recovery phrase stored in secure location (safe)" << std::endl;
    std::cout << "  [ ] Multiple backup copies in different locations" << std::endl;
    std::cout << "  [ ] Tested wallet restoration with recovery phrase" << std::endl;
    std::cout << "  [ ] Wallet encrypted with strong passphrase" << std::endl;
    std::cout << "  [ ] Auto-backup enabled (optional but recommended)" << std::endl;
    std::cout << "  [ ] Computer scanned for malware" << std::endl;
    std::cout << "  [ ] No one else has seen your recovery phrase" << std::endl;
    std::cout << std::endl;

    std::cout << COLOR_GREEN << "Once checklist is complete, your wallet is ready for use!" << COLOR_RESET << std::endl;
    std::cout << std::endl;
}
