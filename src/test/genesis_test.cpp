// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Genesis Block Test & Generator
 *
 * This program:
 * 1. Creates the genesis block (mainnet or testnet)
 * 2. Displays genesis block parameters
 * 3. Optionally mines the genesis block (finds valid nonce)
 * 4. Outputs the final genesis block hash
 *
 * Usage:
 *   ./genesis_gen              - Display mainnet genesis
 *   ./genesis_gen --mine       - Mine mainnet genesis
 *   ./genesis_gen --testnet    - Display testnet genesis
 *   ./genesis_gen --testnet --mine - Mine testnet genesis
 */

#include <node/genesis.h>
#include <primitives/block.h>
#include <consensus/pow.h>
#include <core/chainparams.h>
#include <crypto/randomx_hash.h>

#include <iostream>
#include <iomanip>
#include <ctime>
#include <cstring>

using namespace std;
using namespace Dilithion;

void PrintBlockInfo(const CBlock& block) {
    cout << "Genesis Block Information:" << endl;
    cout << "=========================" << endl;
    cout << "Version:       " << block.nVersion << endl;
    cout << "Previous Hash: " << block.hashPrevBlock.GetHex() << endl;
    cout << "Merkle Root:   " << block.hashMerkleRoot.GetHex() << endl;
    cout << "Timestamp:     " << block.nTime;

    // Convert timestamp to human-readable
    time_t timestamp = block.nTime;
    cout << " (" << ctime(&timestamp) << ")";

    cout << "Bits (nBits):  0x" << hex << block.nBits << dec << endl;
    cout << "Nonce:         " << block.nNonce << endl;
    cout << "Hash:          " << block.GetHash().GetHex() << endl;
    cout << endl;

    // Print coinbase message
    cout << "Coinbase Message:" << endl;
    cout << string(block.vtx.begin(), block.vtx.end()) << endl;
    cout << endl;
}

int main(int argc, char* argv[]) {
    cout << "======================================" << endl;
    cout << "Dilithion Genesis Block Generator" << endl;
    cout << "Post-Quantum Cryptocurrency" << endl;
    cout << "======================================" << endl;
    cout << endl;

    // Parse command-line arguments
    bool isTestnet = false;
    bool shouldMine = false;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--testnet") {
            isTestnet = true;
        } else if (arg == "--mine") {
            shouldMine = true;
        } else if (arg == "--help" || arg == "-h") {
            cout << "Usage: " << argv[0] << " [OPTIONS]" << endl;
            cout << endl;
            cout << "Options:" << endl;
            cout << "  --testnet    Use testnet parameters (easier difficulty)" << endl;
            cout << "  --mine       Mine the genesis block (find valid nonce)" << endl;
            cout << "  --help       Show this help message" << endl;
            cout << endl;
            return 0;
        }
    }

    // Initialize RandomX VM for proof-of-work hashing
    // For genesis mining: Use FULL mode (0) for ~50x faster mining
    // FULL mode requires ~2.5GB RAM but mines much faster (~100 H/s vs ~2 H/s)
    // NYC node upgraded to 4GB RAM specifically for this task
    const char* rx_key = "Dilithion-RandomX-v1";
    randomx_init_for_hashing(rx_key, strlen(rx_key), 0);  // full_mode=0 for fast genesis mining

    // Initialize chain parameters
    if (isTestnet) {
        g_chainParams = new ChainParams(ChainParams::Testnet());
        cout << "Network: TESTNET" << endl;
        cout << "Difficulty: 256x easier than mainnet" << endl;
    } else {
        g_chainParams = new ChainParams(ChainParams::Mainnet());
        cout << "Network: MAINNET" << endl;
    }
    cout << endl;

    // Create genesis block
    CBlock genesis = Genesis::CreateGenesisBlock();

    cout << "Genesis block created with default parameters." << endl;
    cout << endl;

    PrintBlockInfo(genesis);

    if (shouldMine) {
        cout << "======================================" << endl;
        cout << "Mining Genesis Block" << endl;
        cout << "======================================" << endl;
        cout << endl;

        // Calculate target from nBits (using consensus CompactToBig)
        uint256 target = CompactToBig(genesis.nBits);

        // Mine the genesis block
        if (Genesis::MineGenesisBlock(genesis, target)) {
            cout << endl;
            cout << "======================================" << endl;
            cout << "Genesis Block Mined Successfully!" << endl;
            cout << "======================================" << endl;
            cout << endl;

            PrintBlockInfo(genesis);

            cout << "IMPORTANT: Update src/core/chainparams.cpp with:" << endl;
            if (isTestnet) {
                cout << "In ChainParams::Testnet():" << endl;
                cout << "  params.genesisNonce = " << genesis.nNonce << ";" << endl;
                cout << "  params.genesisHash = \"" << genesis.GetHash().GetHex() << "\";" << endl;
            } else {
                cout << "In ChainParams::Mainnet():" << endl;
                cout << "  params.genesisNonce = " << genesis.nNonce << ";" << endl;
                cout << "  params.genesisHash = \"" << genesis.GetHash().GetHex() << "\";" << endl;
            }
            cout << endl;
        } else {
            cout << "Failed to mine genesis block" << endl;
            return 1;
        }
    } else {
        cout << "To mine the genesis block, run: " << argv[0] << " --mine" << endl;
        cout << "(Warning: This may take a long time depending on difficulty)" << endl;
        cout << endl;
    }

    // Verify genesis block
    if (Genesis::IsGenesisBlock(genesis)) {
        cout << "✓ Genesis block verification passed" << endl;
    } else {
        cout << "✗ Genesis block verification failed" << endl;
        return 1;
    }

    cout << endl;
    cout << "Final Genesis Hash: " << genesis.GetHash().GetHex() << endl;
    cout << endl;

    // Cleanup
    delete g_chainParams;
    g_chainParams = nullptr;

    return 0;
}
