// Simple wallet generator utility
// Generates an HD wallet and outputs mnemonic + first address

#include "../src/wallet/wallet.h"
#include "../src/wallet/bip39.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    std::cout << "=== Dilithion Wallet Generator ===" << std::endl;
    std::cout << std::endl;

    // Create wallet instance
    CWallet wallet;

    // Generate HD wallet
    std::string mnemonic;
    if (!wallet.GenerateHDWallet(mnemonic, "")) {
        std::cerr << "ERROR: Failed to generate HD wallet" << std::endl;
        return 1;
    }

    // Get the first address
    CDilithiumAddress firstAddr = wallet.GetDefaultAddress();
    if (!firstAddr.IsValid()) {
        std::cerr << "ERROR: Failed to get address" << std::endl;
        return 1;
    }

    // Output results
    std::cout << "=== SEED PHRASE (WRITE THIS DOWN!) ===" << std::endl;
    std::cout << std::endl;
    std::cout << mnemonic << std::endl;
    std::cout << std::endl;
    std::cout << "=======================================" << std::endl;
    std::cout << std::endl;
    std::cout << "First Address: " << firstAddr.ToString() << std::endl;
    std::cout << std::endl;

    // Clear sensitive data
    memset(&mnemonic[0], 0, mnemonic.size());

    return 0;
}
