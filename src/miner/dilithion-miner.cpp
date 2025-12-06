// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Dilithion CPU Miner - Simple command-line mining application
 *
 * Usage:
 *   dilithion-miner [threads]
 *
 * Example:
 *   dilithion-miner 4    # Mine with 4 threads
 *   dilithion-miner      # Auto-detect CPU cores
 */

#include <miner/controller.h>
#include <primitives/block.h>

#include <iostream>
#include <iomanip>
#include <signal.h>
#include <thread>
#include <chrono>
#include <cerrno>
#include <climits>
#include <cstdlib>

using namespace std;

// Global miner instance for signal handling
CMiningController* g_pMiner = nullptr;
bool g_shutdown = false;

void SignalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        cout << "\n\nShutting down miner..." << endl;
        g_shutdown = true;
        if (g_pMiner) {
            g_pMiner->StopMining();
        }
    }
}

void PrintBanner() {
    cout << "======================================" << endl;
    cout << "   Dilithion CPU Miner v1.0" << endl;
    cout << "   Post-Quantum Cryptocurrency" << endl;
    cout << "======================================" << endl;
    cout << endl;
}

void PrintStats(const CMiningStats& stats) {
    cout << "\r";
    cout << "Hash Rate: " << setw(6) << stats.GetHashRate() << " H/s  |  ";
    cout << "Hashes: " << setw(10) << stats.nHashesComputed.load() << "  |  ";
    cout << "Blocks: " << setw(3) << stats.nBlocksFound.load() << "  |  ";
    cout << "Uptime: " << setw(5) << stats.GetUptime() << "s";
    cout << flush;
}

CBlockTemplate CreateGenesisTemplate() {
    // Create genesis block template for testing
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = uint256(); // Null hash for genesis
    block.hashMerkleRoot = uint256();
    block.nTime = static_cast<uint32_t>(time(nullptr));
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    // Set difficulty target
    // For testing, use easier target. In production, use proper difficulty
    uint256 target;
    // Medium difficulty: some zeros at the start
    memset(target.begin(), 0x00, 4);      // 4 bytes of zeros
    memset(target.begin() + 4, 0xFF, 28); // Rest is 0xFF

    return CBlockTemplate(block, target, 0);
}

int main(int argc, char* argv[]) {
    PrintBanner();

    // Parse command line arguments
    // MAINNET FIX: Replace atoi() with strtol() for proper error handling
    uint32_t nThreads = 0; // 0 = auto-detect
    if (argc > 1) {
        char* endptr = nullptr;
        errno = 0;
        long val = strtol(argv[1], &endptr, 10);

        // Check for conversion errors
        if (endptr == argv[1] || *endptr != '\0') {
            cerr << "Invalid thread count: not a number. Using auto-detect." << endl;
        } else if (errno == ERANGE || val < 0 || val > UINT32_MAX) {
            cerr << "Thread count out of range. Using auto-detect." << endl;
        } else if (val == 0) {
            // 0 means auto-detect, which is valid
            nThreads = 0;
        } else {
            nThreads = static_cast<uint32_t>(val);
        }
    }

    // Create miner
    CMiningController miner(nThreads);
    g_pMiner = &miner;

    cout << "Initializing miner..." << endl;
    cout << "Threads: " << miner.GetThreadCount() << endl;
    cout << "Algorithm: RandomX (CPU)" << endl;
    cout << endl;

    // Set up signal handlers
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    // Set block found callback
    miner.SetBlockFoundCallback([](const CBlock& block) {
        cout << "\n\n";
        cout << "======================================" << endl;
        cout << "         BLOCK FOUND!" << endl;
        cout << "======================================" << endl;
        cout << "Hash:   " << block.GetHash().GetHex() << endl;
        cout << "Nonce:  " << block.nNonce << endl;
        cout << "Time:   " << block.nTime << endl;
        cout << "======================================" << endl;
        cout << endl;
    });

    // Create block template
    cout << "Creating block template..." << endl;
    CBlockTemplate tmpl = CreateGenesisTemplate();
    cout << "Target: " << tmpl.hashTarget.GetHex() << endl;
    cout << endl;

    // Start mining
    cout << "Starting mining... (Press Ctrl+C to stop)" << endl;
    cout << endl;

    if (!miner.StartMining(tmpl)) {
        cerr << "Failed to start mining!" << endl;
        return 1;
    }

    // Main loop - print stats every second
    while (!g_shutdown && miner.IsMining()) {
        CMiningStats stats = miner.GetStats();
        PrintStats(stats);

        this_thread::sleep_for(chrono::seconds(1));
    }

    // Stop mining
    cout << "\n\nStopping mining..." << endl;
    miner.StopMining();

    // Print final stats
    CMiningStats finalStats = miner.GetStats();
    cout << endl;
    cout << "======================================" << endl;
    cout << "         Final Statistics" << endl;
    cout << "======================================" << endl;
    cout << "Total Hashes:  " << finalStats.nHashesComputed.load() << endl;
    cout << "Blocks Found:  " << finalStats.nBlocksFound.load() << endl;
    cout << "Avg Hash Rate: " << finalStats.GetHashRate() << " H/s" << endl;
    cout << "Total Time:    " << finalStats.GetUptime() << " seconds" << endl;
    cout << "======================================" << endl;

    return 0;
}
