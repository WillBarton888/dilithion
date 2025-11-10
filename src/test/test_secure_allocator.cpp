// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// FIX-009 (CRYPT-004): Secure Memory Allocator Test Suite
//
// Tests SecureAllocator implementation with mlock()/VirtualLock()

#include <util/secure_allocator.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>

// Test helper: Print hex
void PrintHex(const char* label, const std::vector<uint8_t, SecureAllocator<uint8_t>>& data) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

// Test 1: Basic Allocation and Deallocation
bool Test_BasicAllocation() {
    std::cout << "\n[TEST 1] Basic Allocation and Deallocation" << std::endl;

    {
        // Allocate secure vector
        std::vector<uint8_t, SecureAllocator<uint8_t>> secure_data(32);

        // Write sensitive data
        for (size_t i = 0; i < 32; ++i) {
            secure_data[i] = static_cast<uint8_t>(i);
        }

        // Verify data
        for (size_t i = 0; i < 32; ++i) {
            if (secure_data[i] != static_cast<uint8_t>(i)) {
                std::cout << "FAIL: Data verification failed" << std::endl;
                return false;
            }
        }

        std::cout << "  Allocated 32 bytes with SecureAllocator" << std::endl;
        std::cout << "  Data written and verified successfully" << std::endl;

        // Vector will be destroyed here, triggering SecureAllocator::deallocate()
    }

    std::cout << "PASS: SecureAllocator basic allocation/deallocation works" << std::endl;
    return true;
}

// Test 2: Vector Operations
bool Test_VectorOperations() {
    std::cout << "\n[TEST 2] Vector Operations with SecureAllocator" << std::endl;

    std::vector<uint8_t, SecureAllocator<uint8_t>> secure_vec;

    // Test push_back
    secure_vec.push_back(0xDE);
    secure_vec.push_back(0xAD);
    secure_vec.push_back(0xBE);
    secure_vec.push_back(0xEF);

    if (secure_vec.size() != 4) {
        std::cout << "FAIL: push_back failed, size=" << secure_vec.size() << std::endl;
        return false;
    }

    PrintHex("  After push_back", secure_vec);

    // Test resize
    secure_vec.resize(8, 0xFF);

    if (secure_vec.size() != 8) {
        std::cout << "FAIL: resize failed, size=" << secure_vec.size() << std::endl;
        return false;
    }

    PrintHex("  After resize(8, 0xFF)", secure_vec);

    // Test clear
    secure_vec.clear();

    if (!secure_vec.empty()) {
        std::cout << "FAIL: clear() failed, size=" << secure_vec.size() << std::endl;
        return false;
    }

    std::cout << "  After clear(): size=" << secure_vec.size() << std::endl;

    std::cout << "PASS: Vector operations work correctly with SecureAllocator" << std::endl;
    return true;
}

// Test 3: Memory Locking (Best-Effort)
bool Test_MemoryLocking() {
    std::cout << "\n[TEST 3] Memory Locking (Best-Effort)" << std::endl;

    // Allocate 1KB of secure memory
    const size_t test_size = 1024;
    std::vector<uint8_t, SecureAllocator<uint8_t>> secure_data(test_size);

    // Fill with pattern
    for (size_t i = 0; i < test_size; ++i) {
        secure_data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    // Note: We cannot directly test if mlock()/VirtualLock() succeeded because:
    // 1. It may fail due to insufficient privileges (requires CAP_IPC_LOCK on Linux or SeLockMemoryPrivilege on Windows)
    // 2. It may fail due to resource limits (ulimit -l on Linux, working set quota on Windows)
    // 3. SecureAllocator uses graceful degradation (doesn't throw on lock failure)
    //
    // The best we can do in a unit test is verify the allocator works even if locking fails.

    std::cout << "  Allocated " << test_size << " bytes with SecureAllocator" << std::endl;
    std::cout << "  Memory locking attempted (may fail without privileges)" << std::endl;
    std::cout << "  Linux: Requires CAP_IPC_LOCK or ulimit -l unlimited" << std::endl;
    std::cout << "  Windows: Requires SeLockMemoryPrivilege" << std::endl;

    // Verify data is still accessible (proves allocator works)
    bool data_ok = true;
    for (size_t i = 0; i < test_size; ++i) {
        if (secure_data[i] != static_cast<uint8_t>(i & 0xFF)) {
            data_ok = false;
            break;
        }
    }

    if (!data_ok) {
        std::cout << "FAIL: Data verification failed after locking attempt" << std::endl;
        return false;
    }

    std::cout << "PASS: SecureAllocator works (with or without successful locking)" << std::endl;
    return true;
}

// Test 4: Multiple Allocations
bool Test_MultipleAllocations() {
    std::cout << "\n[TEST 4] Multiple Allocations" << std::endl;

    std::vector<std::vector<uint8_t, SecureAllocator<uint8_t>>> vectors;

    // Create 10 secure vectors
    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t, SecureAllocator<uint8_t>> vec(64);
        // Fill with pattern based on index
        for (size_t j = 0; j < 64; ++j) {
            vec[j] = static_cast<uint8_t>((i + j) & 0xFF);
        }
        vectors.push_back(std::move(vec));
    }

    std::cout << "  Created 10 secure vectors, 64 bytes each" << std::endl;

    // Verify all vectors
    for (size_t i = 0; i < vectors.size(); ++i) {
        for (size_t j = 0; j < vectors[i].size(); ++j) {
            if (vectors[i][j] != static_cast<uint8_t>((i + j) & 0xFF)) {
                std::cout << "FAIL: Verification failed for vector " << i << std::endl;
                return false;
            }
        }
    }

    std::cout << "  All vectors verified successfully" << std::endl;

    // Clear all vectors (triggers deallocation)
    vectors.clear();

    std::cout << "PASS: Multiple secure allocations work correctly" << std::endl;
    return true;
}

// Test 5: Move Semantics
bool Test_MoveSemantics() {
    std::cout << "\n[TEST 5] Move Semantics" << std::endl;

    std::vector<uint8_t, SecureAllocator<uint8_t>> vec1(32);
    for (size_t i = 0; i < 32; ++i) {
        vec1[i] = static_cast<uint8_t>(i);
    }

    PrintHex("  vec1 before move", vec1);

    // Move vec1 to vec2
    std::vector<uint8_t, SecureAllocator<uint8_t>> vec2 = std::move(vec1);

    if (vec2.size() != 32) {
        std::cout << "FAIL: Move failed, vec2 size=" << vec2.size() << std::endl;
        return false;
    }

    PrintHex("  vec2 after move", vec2);

    // Verify vec2 data
    for (size_t i = 0; i < 32; ++i) {
        if (vec2[i] != static_cast<uint8_t>(i)) {
            std::cout << "FAIL: Data corruption after move" << std::endl;
            return false;
        }
    }

    std::cout << "PASS: Move semantics work correctly" << std::endl;
    return true;
}

// Test 6: Large Allocation
bool Test_LargeAllocation() {
    std::cout << "\n[TEST 6] Large Allocation (1MB)" << std::endl;

    const size_t large_size = 1024 * 1024;  // 1MB

    try {
        std::vector<uint8_t, SecureAllocator<uint8_t>> large_vec(large_size);

        // Write pattern to first and last pages
        large_vec[0] = 0xAA;
        large_vec[large_size - 1] = 0xBB;

        if (large_vec[0] != 0xAA || large_vec[large_size - 1] != 0xBB) {
            std::cout << "FAIL: Large allocation data verification failed" << std::endl;
            return false;
        }

        std::cout << "  Allocated " << (large_size / 1024) << " KB with SecureAllocator" << std::endl;
        std::cout << "  Data verification passed" << std::endl;

    } catch (const std::bad_alloc& e) {
        std::cout << "FAIL: Large allocation failed: " << e.what() << std::endl;
        return false;
    }

    std::cout << "PASS: Large allocation works correctly" << std::endl;
    return true;
}

// Main test runner
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "FIX-009 (CRYPT-004): Secure Memory Allocator Test Suite" << std::endl;
    std::cout << "Testing SecureAllocator with mlock()/VirtualLock()" << std::endl;
    std::cout << "========================================" << std::endl;

    int passed = 0;
    int failed = 0;

    // Run all tests
    if (Test_BasicAllocation()) passed++; else failed++;
    if (Test_VectorOperations()) passed++; else failed++;
    if (Test_MemoryLocking()) passed++; else failed++;
    if (Test_MultipleAllocations()) passed++; else failed++;
    if (Test_MoveSemantics()) passed++; else failed++;
    if (Test_LargeAllocation()) passed++; else failed++;

    // Print summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "TEST SUMMARY" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total Tests: " << (passed + failed) << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;

    if (failed == 0) {
        std::cout << "\n✓ ALL TESTS PASSED - FIX-009 SecureAllocator Verified" << std::endl;
        std::cout << "\nNOTE: Memory locking is best-effort and may fail without sufficient privileges:" << std::endl;
        std::cout << "- Linux: Requires CAP_IPC_LOCK capability or 'ulimit -l unlimited'" << std::endl;
        std::cout << "- Windows: Requires SeLockMemoryPrivilege" << std::endl;
        std::cout << "- The allocator provides graceful degradation if locking fails" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ SOME TESTS FAILED - Review Implementation" << std::endl;
        return 1;
    }
}
