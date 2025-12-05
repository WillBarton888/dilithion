// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Wallet Balance Checker Utility
 *
 * Simple command-line tool to check wallet balances across multiple datadirs
 * Usage: ./check-wallet-balance [datadir1] [datadir2] [datadir3] ...
 *
 * If no datadirs are specified, checks default testnet datadirs:
 * - .dilithion-testnet
 * - .dilithion-testnet-node2
 * - .dilithion-testnet-node3
 */

#include <wallet/wallet.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

void print_wallet_info(const std::string& datadir) {
    std::string wallet_file = datadir + "/wallet.dat";

    CWallet wallet;

    // Try to load wallet
    if (!wallet.Load(wallet_file)) {
        std::cout << "  Status: Wallet file not found or could not be loaded" << std::endl;
        return;
    }

    // Get wallet addresses
    auto addresses = wallet.GetAddresses();
    if (addresses.empty()) {
        std::cout << "  Status: Empty wallet (no addresses)" << std::endl;
        return;
    }

    // Get balance
    int64_t balance = wallet.GetBalance();
    double balanceInDIL = static_cast<double>(balance) / 100000000.0;

    std::cout << "  Addresses: " << addresses.size() << std::endl;
    std::cout << "  Balance: " << std::fixed << std::setprecision(8)
              << balanceInDIL << " DIL (" << balance << " ions)" << std::endl;

    // Show first address
    if (!addresses.empty()) {
        std::cout << "  Primary Address: " << addresses[0].ToString() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=========================================" << std::endl;
    std::cout << "Dilithion Wallet Balance Checker" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << std::endl;

    std::vector<std::string> datadirs;

    if (argc > 1) {
        // Use datadirs from command line
        for (int i = 1; i < argc; ++i) {
            datadirs.push_back(argv[i]);
        }
    } else {
        // Use default testnet datadirs
        datadirs.push_back(".dilithion-testnet");
        datadirs.push_back(".dilithion-testnet-node2");
        datadirs.push_back(".dilithion-testnet-node3");
    }

    // Check each wallet
    for (size_t i = 0; i < datadirs.size(); ++i) {
        std::cout << "Node " << (i + 1) << " (" << datadirs[i] << "):" << std::endl;
        print_wallet_info(datadirs[i]);
        std::cout << std::endl;
    }

    std::cout << "=========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}
