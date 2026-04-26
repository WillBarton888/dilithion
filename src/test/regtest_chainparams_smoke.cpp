// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 Day 5: Regtest mode smoke test.
//
// Confirms ChainParams::Regtest() factory constructs cleanly with the
// expected isolated-network identification fields. The full V2 byte-
// equivalence integration test (mining N blocks, comparing LevelDB
// dirs across env-var=0 vs =1) is built on top of this scaffolding.

#include <core/chainparams.h>

#include <cassert>
#include <iostream>

void test_regtest_factory_constructs_with_isolated_identity()
{
    std::cout << "  test_regtest_factory_constructs_with_isolated_identity..."
              << std::flush;
    Dilithion::ChainParams p = Dilithion::ChainParams::Regtest();

    // Network type tagged correctly.
    assert(p.IsRegtest());
    assert(!p.IsMainnet());
    assert(!p.IsTestnet());
    assert(!p.IsDilV());

    // Network identification distinct from mainnet/testnet/dilv.
    assert(p.networkMagic == 0xDA8FB5BB);
    assert(p.chainID == 9999);
    assert(p.p2pPort == 19444);
    assert(p.rpcPort == 19332);

    // No checkpoints — regtest must allow deep reorgs.
    assert(p.checkpoints.empty());

    // Datadir suffix identifies regtest cleanly.
    assert(p.dataDir.find("regtest") != std::string::npos);

    // Faster VDF for quick test runs.
    assert(p.vdfIterations < 500000);

    // Network name string.
    assert(std::string(p.GetNetworkName()) == "regtest");

    std::cout << " OK\n";
}

int main()
{
    std::cout << "\n=== Phase 5 Day 5: Regtest ChainParams Smoke ===\n" << std::endl;
    try {
        test_regtest_factory_constructs_with_isolated_identity();
        std::cout << "\n=== Regtest scaffolding ready (1 test passed) ===\n";
        return 0;
    } catch (...) {
        std::cerr << "Test failed" << std::endl;
        return 1;
    }
}
