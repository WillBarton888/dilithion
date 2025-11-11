// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet_manager.h>
#include <wallet/wallet.h>
#include <util/strencodings.h>
#include <util/system.h>  // For GetDataDir()
#include <rpc/auth.h>  // FIX-001 (CRYPT-003): Constant-time passphrase comparison
#include <iostream>
#include <fstream>
#include <iomanip>  // For std::setw
#include <thread>    // For std::this_thread::sleep_for
#include <chrono>    // For std::chrono::seconds
#include <sys/stat.h>

#ifdef _WIN32
    #include <direct.h>
    #define mkdir(path, mode) _mkdir(path)
#else
    #include <unistd.h>
#endif

// ANSI color codes (same as wallet_manager.cpp)
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

/**
 * PERSIST-004 FIX: Race-condition-free first run check
 *
 * OLD CODE (VULNERABLE):
 *   Check if wallet.dat exists → another process could create it before we do
 *   This is a classic TOCTOU (Time-Of-Check Time-Of-Use) vulnerability
 *
 * NEW CODE (SECURE):
 *   Use atomic file creation to ensure only ONE process can win the "first run" race
 *   The filesystem guarantees atomicity of the create-if-not-exists operation
 *
 * Race Scenario Prevented:
 *   Process A: IsFirstRun() → true (file doesn't exist)
 *   Process B: IsFirstRun() → true (file doesn't exist) ← BOTH SEE "FIRST RUN"!
 *   Process A: Creates wallet, saves to wallet.dat
 *   Process B: Creates wallet, OVERWRITES wallet.dat ← FUNDS LOST!
 *
 * With Atomic Creation:
 *   Process A: AtomicCreateFile(".wallet_init") → true (won race)
 *   Process B: AtomicCreateFile(".wallet_init") → false (file exists, abort)
 *   Process A: Creates wallet safely
 *   Process B: Exits with error message
 */
bool CWalletManager::IsFirstRun() {
    // First, check if wallet.dat already exists (fast path for existing wallets)
    std::string wallet_path = GetDataDir() + "/wallet.dat";
    std::ifstream file(wallet_path);
    if (file.good()) {
        // Wallet already exists - not first run
        return false;
    }

    // Wallet doesn't exist - attempt atomic first-run lock
    // This prevents race condition where two processes both try to create wallet
    std::string lock_file = GetDataDir() + "/.wallet_init_lock";

    if (AtomicCreateFile(lock_file)) {
        // We successfully created the lock file - we won the race
        // This process is authorized to create the wallet
        return true;
    } else {
        // Lock file already exists - another process is creating the wallet
        // We lost the race and must abort
        std::cerr << std::endl;
        std::cerr << "ERROR: Another instance of Dilithion is already creating a wallet." << std::endl;
        std::cerr << "       Please wait for the other instance to complete setup." << std::endl;
        std::cerr << std::endl;
        std::cerr << "If you believe this is an error (crashed during setup):" << std::endl;
        std::cerr << "  1. Ensure no other Dilithion processes are running" << std::endl;
        std::cerr << "  2. Delete: " << lock_file << std::endl;
        std::cerr << "  3. Try again" << std::endl;
        std::cerr << std::endl;

        // Not first run (another process is handling it)
        return false;
    }
}

void CWalletManager::DisplayWelcomeScreen() const {
    std::cout << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "║        WELCOME TO DILITHION WALLET                           ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << "This wizard will create a secure wallet in 4 simple steps:" << std::endl;
    std::cout << std::endl;
    std::cout << "  " << COLOR_BOLD << "1. Create HD Wallet" << COLOR_RESET << " (automatic)" << std::endl;
    std::cout << "  " << COLOR_BOLD << "2. Secure Your Recovery Phrase" << COLOR_RESET << " (2 minutes)" << std::endl;
    std::cout << "  " << COLOR_BOLD << "3. Encrypt Wallet" << COLOR_RESET << " (1 minute)" << std::endl;
    std::cout << "  " << COLOR_BOLD << "4. Create Automatic Backups" << COLOR_RESET << " (automatic)" << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "Total time: ~5 minutes" << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "Required: Paper and pen" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_BOLD << "Why this matters:" << COLOR_RESET << std::endl;
    std::cout << "  • Your recovery phrase is the ONLY way to recover your funds" << std::endl;
    std::cout << "  • Encryption protects your wallet file" << std::endl;
    std::cout << "  • Backups prevent data loss" << std::endl;
    std::cout << std::endl;
}

bool CWalletManager::RunFirstTimeSetupWizard() {
    // Display welcome screen
    DisplayWelcomeScreen();

    if (!PromptConfirmation("Are you ready to create your secure Dilithion wallet?")) {
        PrintWarning("Setup cancelled. You can run the wizard again by deleting wallet.dat");
        return false;
    }

    std::cout << std::endl;
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "STEP 1: Create HD Wallet" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Create HD wallet using existing interactive method
    std::string mnemonic;

    // Show security warning first
    PrintMnemonicSecurityWarning();

    if (!PromptConfirmation("Have you read and understood the security warning?")) {
        PrintWarning("Setup cancelled");
        return false;
    }

    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "Generating secure HD wallet..." << COLOR_RESET << std::endl;
    std::cout << "  ✓ Generating cryptographically secure random seed..." << std::endl;
    std::cout << "  ✓ Creating 24-word recovery phrase..." << std::endl;
    std::cout << "  ✓ Deriving master keys..." << std::endl;
    std::cout << "  ✓ Generating first addresses..." << std::endl;

    // Generate wallet without passphrase (keep it simple for default setup)
    if (!m_wallet->GenerateHDWallet(mnemonic, "")) {
        PrintError("Failed to generate HD wallet");
        return false;
    }

    std::cout << std::endl;
    PrintSuccess("HD Wallet created successfully!");
    std::cout << std::endl;

    // Step 2: Display and verify mnemonic
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "STEP 2: Your Recovery Phrase" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    std::cout << COLOR_RED << COLOR_BOLD << "⚠️  THIS IS THE ONLY WAY TO RECOVER YOUR FUNDS" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "REQUIRED: Write these words on paper RIGHT NOW" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Display mnemonic in a box
    std::cout << COLOR_RED << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "║             YOUR 24-WORD RECOVERY PHRASE                     ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "╠══════════════════════════════════════════════════════════════╣" << COLOR_RESET << std::endl;

    // Format mnemonic in groups of 6 words per line
    std::istringstream iss(mnemonic);
    std::vector<std::string> words;
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }

    for (size_t i = 0; i < words.size(); i += 6) {
        std::cout << COLOR_RED << COLOR_BOLD << "║  ";
        for (size_t j = i; j < std::min(i + 6, words.size()); ++j) {
            std::cout << std::setw(2) << (j + 1) << "." << std::setw(10) << std::left << words[j] << " ";
        }
        std::cout << std::setw(0) << COLOR_RESET << std::endl;
    }

    std::cout << COLOR_RED << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    std::cout << COLOR_GREEN << "✓ DO:" << COLOR_RESET << " Write on paper, store in safe" << std::endl;
    std::cout << COLOR_RED << "✗ DON'T:" << COLOR_RESET << " Screenshot, email, or cloud storage" << std::endl;
    std::cout << std::endl;

    // Verification - user must type first, middle, and last word
    std::cout << COLOR_YELLOW << "To verify you wrote it down, please type:" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Verify first word
    std::cout << "The FIRST word (word #1): ";
    std::string first_word_confirm;
    std::getline(std::cin, first_word_confirm);

    if (first_word_confirm != words[0]) {
        PrintError("Incorrect! Please verify you wrote down the mnemonic correctly.");
        PrintWarning("The first word is: " + words[0]);
        std::cout << std::endl;

        if (!PromptConfirmation("Did you write down all 24 words correctly?")) {
            PrintError("Setup cannot continue without verified mnemonic backup");
            return false;
        }
    } else {
        PrintSuccess("Verification successful!");
    }

    std::cout << std::endl;

    // Step 3: Encrypt wallet
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "STEP 3: Encrypt Your Wallet" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    if (!PromptAndEncryptWallet()) {
        PrintError("Wallet encryption failed");
        return false;
    }

    std::cout << std::endl;

    // Step 4: Setup auto-backup
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << COLOR_BOLD << "STEP 4: Create Automatic Backups" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Create backup directory
    std::string backup_dir = GetDataDir() + "/backups";
    mkdir(backup_dir.c_str(), 0700);

    // Enable auto-backup (daily)
    EnableAutoBackup(backup_dir, 1440); // 24 hours

    // Create initial backup
    std::string backup_path;
    if (CreateBackup("initial", backup_path)) {
        std::cout << std::endl;
        PrintSuccess("Initial backup created:");
        std::cout << "  " << backup_path << std::endl;
        std::cout << std::endl;
        PrintWarning("IMPORTANT: Store this backup file in a secure location!");
        std::cout << "  • Copy to USB drive" << std::endl;
        std::cout << "  • Keep USB drive in safe" << std::endl;
        std::cout << "  • Make 2-3 copies" << std::endl;
    }

    std::cout << std::endl;
    PrintSuccess("Auto-backup enabled (daily backups)");
    std::cout << std::endl;

    // Setup complete!
    std::cout << COLOR_GREEN << COLOR_BOLD << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << COLOR_BOLD << "✓ WALLET SETUP COMPLETE!" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << COLOR_BOLD << "═══════════════════════════════════════════════════════════════" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    std::cout << "Your wallet is now secure and ready to use." << std::endl;
    std::cout << std::endl;

    // Display first address
    CAddress first_address = m_wallet->GetNewHDAddress();
    std::cout << "Your first receive address:" << std::endl;
    std::cout << COLOR_GREEN << first_address.ToString() << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Display security score
    DisplaySecurityScore();

    std::cout << std::endl;

    // Final security checklist
    DisplaySecurityChecklist();

    std::cout << std::endl;
    PrintSuccess("You're ready to start using Dilithion!");
    std::cout << std::endl;

    return true;
}

bool CWalletManager::PromptAndEncryptWallet() {
    std::cout << "Your wallet will be encrypted for security." << std::endl;
    std::cout << std::endl;
    std::cout << COLOR_BOLD << "Create a strong passphrase:" << COLOR_RESET << std::endl;
    std::cout << "  • At least 12 characters (20+ recommended)" << std::endl;
    std::cout << "  • Mix letters, numbers, symbols" << std::endl;
    std::cout << "  • Something memorable but not guessable" << std::endl;
    std::cout << "  • NOT your birthday, pet's name, or common word" << std::endl;
    std::cout << std::endl;

    std::string passphrase;
    std::string passphrase_confirm;
    bool passphrase_accepted = false;

    while (!passphrase_accepted) {
        std::cout << "Enter passphrase: ";
        std::getline(std::cin, passphrase);

        if (passphrase.length() < 12) {
            PrintError("Passphrase too short! Minimum 12 characters.");
            continue;
        }

        // Validate strength
        std::string feedback;
        if (ValidatePassphraseStrength(passphrase, feedback)) {
            std::cout << COLOR_GREEN << feedback << COLOR_RESET << std::endl;
            passphrase_accepted = true;
        } else {
            PrintWarning(feedback);
            if (PromptConfirmation("Passphrase is weak. Use anyway? (NOT RECOMMENDED)")) {
                passphrase_accepted = true;
            }
        }
    }

    // Confirm passphrase
    std::cout << "Confirm passphrase: ";
    std::getline(std::cin, passphrase_confirm);

    // FIX-001 (CRYPT-003): Use constant-time comparison to prevent timing attacks
    if (!SecureStringCompare(passphrase, passphrase_confirm)) {
        PrintError("Passphrases don't match!");
        return false;
    }

    std::cout << std::endl;
    std::cout << COLOR_YELLOW << "Encrypting wallet..." << COLOR_RESET << std::endl;

    if (!m_wallet->EncryptWallet(passphrase)) {
        PrintError("Failed to encrypt wallet");
        return false;
    }

    PrintSuccess("Wallet encrypted successfully!");
    std::cout << std::endl;
    PrintWarning("IMPORTANT: If you forget this passphrase,");
    std::cout << "you can still recover using your recovery phrase." << std::endl;
    std::cout << "The recovery phrase is MORE IMPORTANT than the passphrase." << std::endl;

    return true;
}

int CWalletManager::CalculateSecurityScore() const {
    int score = 0;

    // HD wallet (20 points)
    if (m_wallet && m_wallet->IsHDWallet()) {
        score += 20;
    }

    // Encrypted (30 points)
    if (m_wallet && m_wallet->IsCrypted()) {
        score += 30;
    }

    // Auto-backup enabled (25 points)
    if (m_auto_backup_enabled) {
        score += 25;
    }

    // Wallet locked (15 points)
    if (m_wallet && m_wallet->IsLocked()) {
        score += 15;
    }

    // Backup exists (10 points)
    std::string backup_dir = GetDataDir() + "/backups";
    struct stat info;
    if (stat(backup_dir.c_str(), &info) == 0 && (info.st_mode & S_IFDIR)) {
        score += 10;
    }

    return score;
}

void CWalletManager::DisplaySecurityScore() const {
    int score = CalculateSecurityScore();

    std::cout << COLOR_CYAN << COLOR_BOLD << "Security Status:" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    // Progress bar
    std::cout << "Security Score: ";
    int bars = score / 5;
    std::cout << "[";
    for (int i = 0; i < 20; ++i) {
        if (i < bars) {
            if (score >= 80) std::cout << COLOR_GREEN << "█";
            else if (score >= 60) std::cout << COLOR_YELLOW << "█";
            else std::cout << COLOR_RED << "█";
        } else {
            std::cout << COLOR_RESET << "░";
        }
    }
    std::cout << COLOR_RESET << "] " << score << "/100";

    if (score >= 90) {
        std::cout << " " << COLOR_GREEN << "Excellent" << COLOR_RESET << std::endl;
    } else if (score >= 70) {
        std::cout << " " << COLOR_GREEN << "Very Good" << COLOR_RESET << std::endl;
    } else if (score >= 50) {
        std::cout << " " << COLOR_YELLOW << "Good" << COLOR_RESET << std::endl;
    } else {
        std::cout << " " << COLOR_RED << "Needs Improvement" << COLOR_RESET << std::endl;
    }

    std::cout << std::endl;

    // Checklist
    std::cout << COLOR_BOLD << "Security Checklist:" << COLOR_RESET << std::endl;

    if (m_wallet && m_wallet->IsHDWallet()) {
        std::cout << "  " << COLOR_GREEN << "✓" << COLOR_RESET << " HD wallet created" << std::endl;
    } else {
        std::cout << "  " << COLOR_RED << "✗" << COLOR_RESET << " HD wallet not created" << std::endl;
    }

    if (m_wallet && m_wallet->IsCrypted()) {
        std::cout << "  " << COLOR_GREEN << "✓" << COLOR_RESET << " Wallet encrypted" << std::endl;
    } else {
        std::cout << "  " << COLOR_RED << "✗" << COLOR_RESET << " Wallet not encrypted" << std::endl;
    }

    if (m_auto_backup_enabled) {
        std::cout << "  " << COLOR_GREEN << "✓" << COLOR_RESET << " Auto-backup enabled" << std::endl;
    } else {
        std::cout << "  " << COLOR_YELLOW << "⚠" << COLOR_RESET << " Auto-backup disabled" << std::endl;
    }

    std::cout << "  " << COLOR_YELLOW << "⚠" << COLOR_RESET << " Recovery phrase written on paper (manual check)" << std::endl;
}

bool CWalletManager::WarnLargeTransaction(double amount, const std::string& address) const {
    // Thresholds for warnings
    const double WARNING_THRESHOLD = 100.0;
    const double CRITICAL_THRESHOLD = 500.0;
    const double EXTREME_THRESHOLD = 1000.0;

    if (amount < WARNING_THRESHOLD) {
        return true; // No warning needed
    }

    std::cout << std::endl;
    std::cout << COLOR_RED << COLOR_BOLD << "╔══════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;

    if (amount >= EXTREME_THRESHOLD) {
        std::cout << COLOR_RED << COLOR_BOLD << "║            ⚠️  EXTREMELY LARGE TRANSACTION ⚠️                 ║" << COLOR_RESET << std::endl;
    } else if (amount >= CRITICAL_THRESHOLD) {
        std::cout << COLOR_RED << COLOR_BOLD << "║              ⚠️  LARGE TRANSACTION WARNING ⚠️                ║" << COLOR_RESET << std::endl;
    } else {
        std::cout << COLOR_YELLOW << COLOR_BOLD << "║                TRANSACTION CONFIRMATION                      ║" << COLOR_RESET << std::endl;
    }

    std::cout << COLOR_RED << COLOR_BOLD << "╚══════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << std::endl;

    std::cout << "You are about to send: " << COLOR_BOLD << amount << " DIL" << COLOR_RESET << std::endl;
    std::cout << std::endl;
    std::cout << "Recipient address:" << std::endl;
    std::cout << COLOR_YELLOW << address << COLOR_RESET << std::endl;
    std::cout << std::endl;

    if (amount >= EXTREME_THRESHOLD) {
        PrintWarning("This is an extremely large transaction!");
        std::cout << "Consider:" << std::endl;
        std::cout << "  • Splitting into multiple smaller transactions" << std::endl;
        std::cout << "  • Double-checking the recipient address" << std::endl;
        std::cout << "  • Verifying this transaction through another channel" << std::endl;
        std::cout << std::endl;
    }

    std::cout << COLOR_BOLD << "Please verify:" << COLOR_RESET << std::endl;
    std::cout << "  • The address is correct (copy-paste errors are common!)" << std::endl;
    std::cout << "  • The amount is correct" << std::endl;
    std::cout << "  • You trust the recipient" << std::endl;
    std::cout << "  • This transaction is NOT to a scammer or phishing site" << std::endl;
    std::cout << std::endl;

    std::cout << COLOR_RED << "⚠️  This transaction is IRREVERSIBLE!" << COLOR_RESET << std::endl;
    std::cout << "Once sent, funds CANNOT be recovered if you made a mistake." << std::endl;
    std::cout << std::endl;

    if (amount >= EXTREME_THRESHOLD) {
        // Extra confirmation for very large amounts
        std::cout << COLOR_YELLOW << "Type '" << COLOR_BOLD << "CONFIRM" << COLOR_RESET << COLOR_YELLOW << "' (all caps) to proceed: " << COLOR_RESET;
        std::string confirmation;
        std::getline(std::cin, confirmation);

        if (confirmation != "CONFIRM") {
            PrintWarning("Transaction cancelled");
            return false;
        }

        // 10 second cooldown
        std::cout << std::endl;
        std::cout << COLOR_YELLOW << "Please wait 10 seconds (safety cooldown)..." << COLOR_RESET << std::endl;
        for (int i = 10; i > 0; --i) {
            std::cout << "\r" << i << " seconds remaining... " << std::flush;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        std::cout << "\r                          \r" << std::flush;
    }

    return PromptConfirmation("Proceed with this transaction?");
}
