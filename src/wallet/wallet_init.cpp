// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet.h>
#include <wallet/wallet_manager.h>
#include <util/system.h>
#include <iostream>

/**
 * Initialize wallet with first-time setup wizard if needed
 * Returns true if wallet initialized successfully
 */
bool InitializeWallet(CWallet** wallet_out) {
    // Check if this is first run (no wallet.dat exists)
    if (CWalletManager::IsFirstRun()) {
        std::cout << std::endl;
        std::cout << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║  First time running Dilithion? Welcome!                      ║" << std::endl;
        std::cout << "║  We'll help you create a secure wallet in just 5 minutes.    ║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
        std::cout << std::endl;

        // Create new wallet
        CWallet* new_wallet = new CWallet();

        // Run first-time setup wizard
        CWalletManager manager(new_wallet);

        if (!manager.RunFirstTimeSetupWizard()) {
            // User cancelled setup
            std::cerr << "Wallet setup cancelled." << std::endl;
            std::cerr << "You must complete the setup wizard to use Dilithion." << std::endl;
            delete new_wallet;
            return false;
        }

        // Wizard completed successfully
        std::cout << std::endl;
        std::cout << "Wallet setup completed successfully!" << std::endl;
        std::cout << "Saving wallet..." << std::endl;

        // Save wallet
        std::string wallet_path = GetDataDir() + "/wallet.dat";
        if (!new_wallet->SaveWallet(wallet_path)) {
            std::cerr << "ERROR: Failed to save wallet!" << std::endl;
            delete new_wallet;
            return false;
        }

        *wallet_out = new_wallet;
        return true;
    }

    // Existing wallet - load it
    std::string wallet_path = GetDataDir() + "/wallet.dat";
    CWallet* existing_wallet = new CWallet();

    if (!existing_wallet->LoadWallet(wallet_path)) {
        std::cerr << "ERROR: Failed to load wallet from " << wallet_path << std::endl;
        std::cerr << "Wallet file may be corrupted." << std::endl;
        std::cerr << std::endl;
        std::cerr << "Recovery options:" << std::endl;
        std::cerr << "1. Restore from backup (check ~/.dilithion/backups/)" << std::endl;
        std::cerr << "2. Restore from recovery phrase (run: dilithion-cli restorehdwallet)" << std::endl;
        delete existing_wallet;
        return false;
    }

    // Verify wallet is encrypted
    if (!existing_wallet->IsCrypted()) {
        std::cout << std::endl;
        std::cout << "WARNING: Your wallet is not encrypted!" << std::endl;
        std::cout << "This is a security risk." << std::endl;
        std::cout << std::endl;
        std::cout << "Would you like to encrypt it now? (y/n): ";

        std::string response;
        std::getline(std::cin, response);

        if (response == "y" || response == "Y" || response == "yes") {
            CWalletManager manager(existing_wallet);
            if (manager.PromptAndEncryptWallet()) {
                std::cout << "Wallet encrypted successfully!" << std::endl;
                // Save encrypted wallet
                existing_wallet->SaveWallet(wallet_path);
            }
        } else {
            std::cout << "RECOMMENDATION: Encrypt your wallet as soon as possible" << std::endl;
            std::cout << "Run: dilithion-cli encryptwallet <passphrase>" << std::endl;
        }
    }

    // Check if auto-backup should be enabled
    CWalletManager manager(existing_wallet);
    if (!manager.IsAutoBackupEnabled()) {
        std::string backup_dir = GetDataDir() + "/backups";
        manager.EnableAutoBackup(backup_dir, 1440); // Daily backups
        std::cout << "Auto-backup enabled (daily backups)" << std::endl;
    }

    *wallet_out = existing_wallet;
    return true;
}

/**
 * Shutdown wallet gracefully
 */
void ShutdownWallet(CWallet* wallet) {
    if (!wallet) {
        return;
    }

    std::cout << "Shutting down wallet..." << std::endl;

    // Perform final auto-backup if enabled
    CWalletManager manager(wallet);
    if (manager.IsAutoBackupEnabled()) {
        manager.CheckAndPerformAutoBackup();
    }

    // Save wallet
    std::string wallet_path = GetDataDir() + "/wallet.dat";
    if (!wallet->SaveWallet(wallet_path)) {
        std::cerr << "WARNING: Failed to save wallet on shutdown!" << std::endl;
    }

    delete wallet;
    std::cout << "Wallet shutdown complete." << std::endl;
}
