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
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #include <shlobj.h>
#endif

// Get the home/appdata directory
std::string GetHomeDir() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, path) == S_OK) {
        return std::string(path);
    }
    // Fallback to USERPROFILE
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        return std::string(userprofile);
    }
    return ".";
#else
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home);
    }
    return ".";
#endif
}

// Get full path to datadir
std::string GetFullDataDir(const std::string& name) {
    std::string home = GetHomeDir();
#ifdef _WIN32
    return home + "\\" + name;
#else
    return home + "/" + name;
#endif
}

// Coinbase maturity constant (must match consensus/params.h)
static const unsigned int COINBASE_MATURITY = 100;

void print_wallet_info(const std::string& datadir) {
#ifdef _WIN32
    std::string wallet_file = datadir + "\\wallet.dat";
#else
    std::string wallet_file = datadir + "/wallet.dat";
#endif

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

    // Get best block height from wallet (for maturity calculation)
    int32_t bestHeight = wallet.GetBestBlockHeight();

    // Get unspent transaction outputs and calculate mature/immature balance
    auto utxos = wallet.GetUnspentTxOuts();

    int64_t matureBalance = 0;
    int64_t immatureBalance = 0;
    int64_t totalBalance = 0;

    for (const auto& utxo : utxos) {
        totalBalance += utxo.nValue;

        // Calculate confirmations
        // If bestHeight is not initialized (-1), treat all as mature for display
        if (bestHeight >= 0 && utxo.nHeight > 0) {
            unsigned int confirmations = static_cast<unsigned int>(bestHeight - utxo.nHeight + 1);
            if (confirmations >= COINBASE_MATURITY) {
                matureBalance += utxo.nValue;
            } else {
                immatureBalance += utxo.nValue;
            }
        } else {
            // No height info available, treat as mature
            matureBalance += utxo.nValue;
        }
    }

    double totalDIL = static_cast<double>(totalBalance) / 100000000.0;
    double matureDIL = static_cast<double>(matureBalance) / 100000000.0;
    double immatureDIL = static_cast<double>(immatureBalance) / 100000000.0;

    std::cout << "  Addresses: " << addresses.size() << std::endl;
    std::cout << "  UTXOs: " << utxos.size() << std::endl;
    if (bestHeight >= 0) {
        std::cout << "  Synced Height: " << bestHeight << std::endl;
    }
    std::cout << std::endl;
    std::cout << "  Balance Breakdown:" << std::endl;
    std::cout << "    Total:    " << std::fixed << std::setprecision(8)
              << totalDIL << " DIL" << std::endl;
    std::cout << "    Mature:   " << std::fixed << std::setprecision(8)
              << matureDIL << " DIL (spendable)" << std::endl;
    std::cout << "    Immature: " << std::fixed << std::setprecision(8)
              << immatureDIL << " DIL (needs " << COINBASE_MATURITY << " confirmations)" << std::endl;

    // Show first address
    std::cout << std::endl;
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
        // Use default testnet datadirs (with proper paths for this platform)
        datadirs.push_back(GetFullDataDir(".dilithion-testnet"));
        datadirs.push_back(GetFullDataDir(".dilithion-testnet-node2"));
        datadirs.push_back(GetFullDataDir(".dilithion-testnet-node3"));
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
