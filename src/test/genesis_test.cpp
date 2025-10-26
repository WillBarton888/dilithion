// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Genesis Block Test & Generator
 *
 * This program:
 * 1. Creates the genesis block
 * 2. Displays genesis block parameters
 * 3. Optionally mines the genesis block (finds valid nonce)
 * 4. Outputs the final genesis block hash
 */

#include <node/genesis.h>
#include <primitives/block.h>
#include <consensus/pow.h>

#include <iostream>
#include <iomanip>
#include <ctime>

using namespace std;

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

    // Create genesis block
    CBlock genesis = Genesis::CreateGenesisBlock();

    cout << "Genesis block created with default parameters." << endl;
    cout << endl;

    PrintBlockInfo(genesis);

    // Check if we should mine the genesis block
    bool shouldMine = false;
    if (argc > 1 && string(argv[1]) == "--mine") {
        shouldMine = true;
    }

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

            cout << "IMPORTANT: Update src/node/genesis.h with:" << endl;
            cout << "const uint32_t NONCE = " << genesis.nNonce << ";" << endl;
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

    return 0;
}
