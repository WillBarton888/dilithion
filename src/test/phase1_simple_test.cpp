// Copyright (c) 2025 The Dilithion Core developers
// Simple Phase 1 Component Test

#include <consensus/fees.h>
#include <node/block_index.h>
#include <node/mempool.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <iostream>
#include <cassert>

void test_fee_calculation() {
    std::cout << "Testing fee calculations..." << std::endl;
    
    // Test standard transaction sizes
    size_t size_1in_1out = Consensus::EstimateDilithiumTxSize(1, 1, 0);
    CAmount fee_1in_1out = Consensus::CalculateMinFee(size_1in_1out);
    
    std::cout << "  1-in, 1-out: " << size_1in_1out << " bytes, fee: " << fee_1in_1out << " sats" << std::endl;
    
    // Verify fee formula: MIN_TX_FEE + (size * FEE_PER_BYTE)
    CAmount expected_fee = 10000 + (size_1in_1out * 10);
    assert(fee_1in_1out == expected_fee);
    
    // Test fee rate calculation
    double rate = Consensus::CalculateFeeRate(fee_1in_1out, size_1in_1out);
    std::cout << "  Fee rate: " << rate << " sat/byte" << std::endl;
    assert(rate > 10.0 && rate < 15.0);  // Should be ~10 + small overhead
    
    // Test 2-in, 1-out
    size_t size_2in_1out = Consensus::EstimateDilithiumTxSize(2, 1, 0);
    CAmount fee_2in_1out = Consensus::CalculateMinFee(size_2in_1out);
    std::cout << "  2-in, 1-out: " << size_2in_1out << " bytes, fee: " << fee_2in_1out << " sats" << std::endl;
    
    std::cout << "  ✓ Fee calculations correct" << std::endl;
}

void test_block_index() {
    std::cout << "Testing block index..." << std::endl;
    
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1735689600;
    header.nBits = 0x1d00ffff;
    header.nNonce = 12345;
    
    CBlockIndex index(header);
    index.nHeight = 0;
    index.nTx = 1;
    index.nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;
    
    assert(index.IsValid());
    assert(index.HaveData());
    assert(index.nHeight == 0);
    
    std::string str = index.ToString();
    std::cout << "  " << str << std::endl;
    assert(str.find("CBlockIndex") != std::string::npos);
    
    std::cout << "  ✓ Block index working" << std::endl;
}

void test_mempool_basic() {
    std::cout << "Testing mempool basic operations..." << std::endl;
    
    CTxMemPool mempool;
    assert(mempool.Size() == 0);
    std::cout << "  ✓ Mempool starts empty" << std::endl;
    
    size_t size, bytes;
    double min_rate, max_rate;
    mempool.GetStats(size, bytes, min_rate, max_rate);
    
    assert(size == 0);
    assert(bytes == 0);
    std::cout << "  ✓ Mempool stats work" << std::endl;
}

void test_uint256_operators() {
    std::cout << "Testing uint256 operators..." << std::endl;
    
    uint256 a, b, c;
    a.data[0] = 1;
    b.data[0] = 2;
    c.data[0] = 1;
    
    assert(a < b);
    assert(!(b < a));
    assert(a == a);
    assert(a == c);
    assert(!(a == b));
    
    std::cout << "  ✓ uint256 operators work" << std::endl;
}

void test_transaction_basics() {
    std::cout << "Testing transaction basics..." << std::endl;
    
    CTransaction tx;
    tx.nVersion = 1;
    
    uint256 hash1 = tx.GetHash();
    uint256 hash2 = tx.GetHash();
    
    assert(hash1 == hash2);  // Hash caching works
    assert(hash1.data[0] == 1);  // Hash based on version
    
    size_t size = tx.GetSerializedSize();
    std::cout << "  Empty tx size: " << size << " bytes" << std::endl;
    assert(size == 8);  // 8 bytes for empty tx
    
    std::cout << "  ✓ Transaction basics work" << std::endl;
}

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "Phase 1 Simple Component Tests" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;
    
    try {
        test_fee_calculation();
        std::cout << std::endl;
        
        test_uint256_operators();
        std::cout << std::endl;
        
        test_transaction_basics();
        std::cout << std::endl;
        
        test_block_index();
        std::cout << std::endl;
        
        test_mempool_basic();
        std::cout << std::endl;
        
        std::cout << "======================================" << std::endl;
        std::cout << "✅ All basic tests passed!" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << std::endl;
        std::cout << "Phase 1 Core Components Validated:" << std::endl;
        std::cout << "  ✓ Fee validation (Hybrid Model)" << std::endl;
        std::cout << "  ✓ uint256 operators" << std::endl;
        std::cout << "  ✓ Transaction basics" << std::endl;
        std::cout << "  ✓ Block index" << std::endl;
        std::cout << "  ✓ Mempool structure" << std::endl;
        std::cout << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed: " << e.what() << std::endl;
        return 1;
    }
}
