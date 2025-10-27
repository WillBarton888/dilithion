// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
// Database inspection tool for debugging

#include <node/blockchain_storage.h>
#include <primitives/block.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <database_path>" << std::endl;
        return 1;
    }

    std::string db_path = argv[1];

    std::cout << "======================================" << std::endl;
    std::cout << "Dilithion Database Inspector" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << "Database: " << db_path << std::endl << std::endl;

    CBlockchainDB db;
    if (!db.Open(db_path, false)) {
        std::cerr << "Failed to open database at: " << db_path << std::endl;
        return 1;
    }

    std::cout << "✓ Database opened successfully" << std::endl << std::endl;

    // Read best block
    uint256 bestBlockHash;
    if (db.ReadBestBlock(bestBlockHash)) {
        std::cout << "Best Block Hash: " << bestBlockHash.GetHex() << std::endl;

        // Try to read the block index
        CBlockIndex bestIndex;
        if (db.ReadBlockIndex(bestBlockHash, bestIndex)) {
            std::cout << "Best Block Index:" << std::endl;
            std::cout << "  Height: " << bestIndex.nHeight << std::endl;
            std::cout << "  Time: " << bestIndex.nTime << std::endl;
            std::cout << "  Bits: 0x" << std::hex << bestIndex.nBits << std::dec << std::endl;
            std::cout << "  Nonce: " << bestIndex.nNonce << std::endl;
            std::cout << "  Version: " << bestIndex.nVersion << std::endl;
            std::cout << "  Status: 0x" << std::hex << bestIndex.nStatus << std::dec << std::endl;
            std::cout << "  Tx Count: " << bestIndex.nTx << std::endl;
        } else {
            std::cout << "  [WARNING] Failed to read block index for best block" << std::endl;
        }
    } else {
        std::cout << "[WARNING] No best block found in database" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}
