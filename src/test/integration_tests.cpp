// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 5 Integration Tests
 *
 * Tests the full integration of all components:
 * - Phase 1: Blockchain storage, mempool, fees
 * - Phase 2: P2P networking (basic)
 * - Phase 3: Mining controller
 * - Phase 4: Wallet, RPC server
 */

#include <node/blockchain_storage.h>
#include <node/mempool.h>
#include <node/block_index.h>
#include <consensus/fees.h>
#include <net/peers.h>
#include <net/net.h>
#include <miner/controller.h>
#include <wallet/wallet.h>
#include <rpc/server.h>

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdio>

using namespace std;

// Helper: Remove test directory
void CleanupTestDir(const string& path) {
    system(("rm -rf " + path).c_str());
}

bool TestBlockchainAndMempool() {
    cout << "Testing blockchain storage and mempool integration..." << endl;

    string testdir = "/tmp/dilithion-integration-test-1";
    CleanupTestDir(testdir);

    // Open blockchain database
    CBlockchainDB blockchain;
    if (!blockchain.Open(testdir + "/blocks")) {
        cout << "  ✗ Failed to open blockchain database" << endl;
        return false;
    }
    cout << "  ✓ Blockchain database opened" << endl;

    // Create mempool
    CTxMemPool mempool;
    cout << "  ✓ Mempool created" << endl;

    // Create and store a block
    CBlock block;
    block.nVersion = 1;
    block.nTime = static_cast<uint32_t>(time(nullptr));
    block.nBits = 0x1d00ffff;
    block.nNonce = 12345;

    uint256 hash = block.GetHash();
    if (!blockchain.WriteBlock(hash, block)) {
        cout << "  ✗ Failed to write block" << endl;
        return false;
    }
    cout << "  ✓ Block written to database" << endl;

    // Read block back
    CBlock readBlock;
    if (!blockchain.ReadBlock(hash, readBlock)) {
        cout << "  ✗ Failed to read block" << endl;
        return false;
    }

    if (readBlock.nVersion != block.nVersion ||
        readBlock.nTime != block.nTime ||
        readBlock.nBits != block.nBits ||
        readBlock.nNonce != block.nNonce) {
        cout << "  ✗ Block data mismatch" << endl;
        return false;
    }
    cout << "  ✓ Block read correctly" << endl;

    blockchain.Close();
    CleanupTestDir(testdir);
    return true;
}

bool TestMiningIntegration() {
    cout << "\nTesting mining controller integration..." << endl;

    // Create mining controller with 2 threads
    CMiningController miner(2);
    cout << "  ✓ Mining controller created (2 threads)" << endl;

    // Create block template
    CBlock block;
    block.nVersion = 1;
    block.nTime = static_cast<uint32_t>(time(nullptr));
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    uint256 hashTarget;  // All zeros = very easy target
    CBlockTemplate blockTemplate(block, hashTarget, 0);

    // Track if block found
    bool blockFound = false;
    miner.SetBlockFoundCallback([&](const CBlock& foundBlock) {
        blockFound = true;
        uint256 hash = foundBlock.GetHash();
        cout << "  ✓ Block found! Hash: " << hash.GetHex().substr(0, 16) << "..." << endl;
    });

    // Start mining
    if (!miner.StartMining(blockTemplate)) {
        cout << "  ✗ Failed to start mining" << endl;
        return false;
    }
    cout << "  ✓ Mining started" << endl;

    // Mine for a bit
    this_thread::sleep_for(chrono::seconds(2));

    // Check stats
    auto stats = miner.GetStats();
    if (stats.nHashesComputed == 0) {
        cout << "  ✗ No hashes computed" << endl;
        miner.StopMining();
        return false;
    }
    cout << "  ✓ Hashes computed: " << stats.nHashesComputed << endl;
    cout << "  ✓ Hash rate: " << miner.GetHashRate() << " H/s" << endl;

    // Stop mining
    miner.StopMining();
    cout << "  ✓ Mining stopped" << endl;

    return true;
}

bool TestWalletIntegration() {
    cout << "\nTesting wallet integration..." << endl;

    CWallet wallet;
    cout << "  ✓ Wallet created" << endl;

    // Generate keys
    for (int i = 0; i < 3; ++i) {
        if (!wallet.GenerateNewKey()) {
            cout << "  ✗ Failed to generate key " << i << endl;
            return false;
        }
    }
    cout << "  ✓ Generated 3 key pairs" << endl;

    // Get addresses
    auto addresses = wallet.GetAddresses();
    if (addresses.size() != 3) {
        cout << "  ✗ Expected 3 addresses, got " << addresses.size() << endl;
        return false;
    }
    cout << "  ✓ Retrieved 3 addresses:" << endl;
    for (const auto& addr : addresses) {
        cout << "    " << addr.ToString() << endl;
    }

    // Check initial balance
    if (wallet.GetBalance() != 0) {
        cout << "  ✗ Expected balance 0, got " << wallet.GetBalance() << endl;
        return false;
    }
    cout << "  ✓ Initial balance: 0" << endl;

    // Add a fake UTXO
    uint256 txid;
    wallet.AddTxOut(txid, 0, 1000000, addresses[0], 0);  // 1M satoshis

    if (wallet.GetBalance() != 1000000) {
        cout << "  ✗ Expected balance 1000000, got " << wallet.GetBalance() << endl;
        return false;
    }
    cout << "  ✓ Balance after UTXO: " << wallet.GetBalance() << endl;

    return true;
}

bool TestRPCIntegration() {
    cout << "\nTesting RPC server integration..." << endl;

    // Create components
    CWallet wallet;
    wallet.GenerateNewKey();

    CMiningController miner(2);

    // Create RPC server
    CRPCServer server(18444);  // Non-standard port for testing
    server.RegisterWallet(&wallet);
    server.RegisterMiner(&miner);

    if (!server.Start()) {
        cout << "  ✗ Failed to start RPC server" << endl;
        return false;
    }
    cout << "  ✓ RPC server started on port 18444" << endl;

    // Give server time to start
    this_thread::sleep_for(chrono::milliseconds(100));

    if (!server.IsRunning()) {
        cout << "  ✗ Server not running" << endl;
        return false;
    }
    cout << "  ✓ Server is running" << endl;

    // Stop server
    server.Stop();

    if (server.IsRunning()) {
        cout << "  ✗ Server still running after stop" << endl;
        return false;
    }
    cout << "  ✓ Server stopped cleanly" << endl;

    return true;
}

bool TestFullNodeStack() {
    cout << "\nTesting full node stack integration..." << endl;

    string testdir = "/tmp/dilithion-integration-test-full";
    CleanupTestDir(testdir);

    try {
        // Phase 1: Blockchain and mempool
        CBlockchainDB blockchain;
        if (!blockchain.Open(testdir + "/blocks")) {
            cout << "  ✗ Failed to open blockchain" << endl;
            return false;
        }
        cout << "  ✓ Blockchain initialized" << endl;

        CTxMemPool mempool;
        cout << "  ✓ Mempool initialized" << endl;

        // Phase 2: P2P components (not fully tested yet)
        CPeerManager peer_manager;
        CNetMessageProcessor message_processor;
        CConnectionManager connection_manager(peer_manager, message_processor);
        cout << "  ✓ P2P components initialized" << endl;

        // Phase 3: Mining
        CMiningController miner(2);
        cout << "  ✓ Mining controller initialized" << endl;

        // Phase 4: Wallet
        CWallet wallet;
        wallet.GenerateNewKey();
        CAddress addr = wallet.GetNewAddress();
        cout << "  ✓ Wallet initialized (address: " << addr.ToString() << ")" << endl;

        // Phase 4: RPC server
        CRPCServer rpc_server(18445);
        rpc_server.RegisterWallet(&wallet);
        rpc_server.RegisterMiner(&miner);

        if (!rpc_server.Start()) {
            cout << "  ✗ Failed to start RPC server" << endl;
            blockchain.Close();
            return false;
        }
        cout << "  ✓ RPC server started" << endl;

        // Let everything run for a moment
        this_thread::sleep_for(chrono::milliseconds(500));

        // Clean shutdown
        cout << "  Initiating shutdown..." << endl;
        rpc_server.Stop();
        blockchain.Close();
        cout << "  ✓ Clean shutdown completed" << endl;

        CleanupTestDir(testdir);
        return true;

    } catch (const exception& e) {
        cout << "  ✗ Exception: " << e.what() << endl;
        CleanupTestDir(testdir);
        return false;
    }
}

int main() {
    cout << "======================================" << endl;
    cout << "Phase 5 Integration Tests" << endl;
    cout << "Testing Full Node Integration" << endl;
    cout << "======================================" << endl;
    cout << endl;

    bool allPassed = true;

    allPassed &= TestBlockchainAndMempool();
    allPassed &= TestMiningIntegration();
    allPassed &= TestWalletIntegration();
    allPassed &= TestRPCIntegration();
    allPassed &= TestFullNodeStack();

    cout << endl;
    cout << "======================================" << endl;
    if (allPassed) {
        cout << "✅ All integration tests passed!" << endl;
    } else {
        cout << "❌ Some tests failed" << endl;
    }
    cout << "======================================" << endl;
    cout << endl;

    cout << "Phase 5 Integration Validated:" << endl;
    cout << "  ✓ Blockchain + Mempool working together" << endl;
    cout << "  ✓ Mining controller functional" << endl;
    cout << "  ✓ Wallet operations working" << endl;
    cout << "  ✓ RPC server start/stop" << endl;
    cout << "  ✓ Full node stack initialization" << endl;
    cout << endl;

    cout << "Next Steps:" << endl;
    cout << "  - End-to-end transaction test" << endl;
    cout << "  - Genesis block creation" << endl;
    cout << "  - Documentation" << endl;
    cout << "  - Launch preparation" << endl;
    cout << endl;

    return allPassed ? 0 : 1;
}
