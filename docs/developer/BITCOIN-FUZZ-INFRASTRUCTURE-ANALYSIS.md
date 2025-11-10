# Bitcoin Core Fuzz Testing Infrastructure Analysis

## Executive Summary

Bitcoin Core employs a sophisticated, multi-framework fuzzing infrastructure to identify vulnerabilities and edge cases in critical protocol components. The project maintains 136+ fuzz harnesses covering transaction processing, block validation, script execution, network protocols, and cryptographic functions. Integration with Google OSS-Fuzz provides continuous fuzzing with public vulnerability tracking.

## Part 1: Fuzzing Infrastructure Overview

### Framework Support
- libFuzzer (primary) - CMake preset: --preset=libfuzzer
- afl++ - Advanced fuzzing with custom compiler
- Honggfuzz - Google fuzzing tool

### Build Configuration
libfuzzer Preset (With Sanitizers):
- Binary: build_fuzz
- Compiler: clang
- Sanitizers: undefined,address,fuzzer
- BUILD_FOR_FUZZING=ON

libfuzzer-nosan (Without Sanitizers):
- Binary: build_fuzz_nosan
- Sanitizers: fuzzer only
- Higher throughput

### Build Flags
BUILD_FOR_FUZZING=ON: Deterministic execution, disables standard binaries
BUILD_FUZZ_BINARY=ON: Optional flag for building alongside targets

## Part 2: Build System and Setup

### Quick Start
1. Clone: git clone https://github.com/bitcoin/bitcoin.git
2. Configure: cmake --preset=libfuzzer
3. Build: cd build_fuzz && make -j$(nproc)
4. Run: FUZZ=decode_tx ./bin/fuzz
5. With corpus: FUZZ=block ./bin/fuzz qa-assets/fuzz_corpora/block/

### Alternative Frameworks
afl++: cmake with afl-clang-lto compiler
Honggfuzz: cmake with hfuzz-clang compiler

## Part 3: Fuzz Harness Examples

### Transaction Deserialization (decode_tx.cpp)
- Four deserialization strategies
- Witness format variations
- Detects: integer overflow, off-by-one errors

### Block Deserialization (block.cpp)
- Four validation configurations
- Hierarchical validation checks
- Detects: POW errors, merkle root bypass

### Script Execution (script.cpp)
- Script compression round-trip testing
- Witness operation counting
- Multi-version evaluation
- Detects: opcode misinterpretation, stack overflow

### Network Messages (p2p_transport_serialization.cpp)
- Message header verification
- Bidirectional message exchange
- V1/V2 protocol testing
- Detects: buffer overflow, state confusion

### Cryptographic Functions (crypto.cpp)
- Hash function testing
- Variable-length operations
- State finalization verification
- Detects: state corruption, buffer overflow

## Part 4: Common Patterns

### Input Consumption Utilities
ConsumeRandomLengthByteVector, ConsumeTransaction, ConsumeScript, ConsumePrivateKey

### Logical Consistency Pattern
- If result_strict succeeds, result_flexible must succeed
- If full_validation passes, partial must pass
- Round-trip consistency: decompress(compress(data)) == data

### State Machine Verification
Track state, apply operation, verify invariants

## Part 5: OSS-Fuzz Integration

Continuous fuzzing with:
- High-powered infrastructure
- Free vulnerability tracking
- Public coverage reports
- Automated bug reporting

Corpus location: bitcoin-core/qa-assets/fuzz_corpora/

Reduction: ./bin/fuzz corpus/ -set_cover_merge=1 reduced_corpus/

Crash reproduction:
1. Update qa-assets
2. Build with sanitizers
3. FUZZ=<target> ./bin/fuzz corpus/crash_id

## Part 6: Template Fuzz Harness

#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

FUZZ_TARGET(harness_name)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    SelectParams(ChainType::REGTEST);
    
    std::vector<uint8_t> data = ConsumeRandomLengthByteVector(provider);
    YourTestObject obj;
    if (!obj.FromData(data)) return;
    
    bool result1 = obj.Operation1();
    if (result1) assert(obj.IsValid());
    
    auto serialized = obj.Serialize();
    YourTestObject obj2;
    assert(obj2.Deserialize(serialized) == OK);
}

## Part 7: Local Fuzzing Setup

Requirements: 4+ cores, 8GB RAM, 50GB disk
Tools: CMake 3.25+, Clang 12+, Git, Python 3.8+

Installation:
sudo apt-get install build-essential cmake clang git python3

Basic fuzzing:
mkdir fuzz_outputs
FUZZ=decode_tx ./build_fuzz/bin/fuzz -artifact_prefix=fuzz_outputs/

With corpus:
FUZZ=block ./build_fuzz/bin/fuzz qa-assets/fuzz_corpora/block/

Parallel:
for i in {1..4}; do FUZZ=script ./build_fuzz/bin/fuzz & done

Troubleshooting:
- Must set FUZZ env var
- Compilation: cmake --preset=libfuzzer -DCMAKE_C_COMPILER=clang
- Memory: ./build_fuzz/bin/fuzz -rss_limit_mb=1024

## Part 8: Fuzz Harness Catalog

Cryptography (15+): base_encode_decode, bech32, bip324, crypto, crypto_aes256, hex, key
Transactions (18+): block, block_header, decode_tx, merkleblock, transaction, tx_pool, psbt
Network (12+): addrman, banman, connman, net, netaddress, p2p_handshake, socks5
Script (15+): eval_script, script, script_flags, script_interpreter, script_ops
Data Structures (20+): bitdeque, bloom_filter, coins_view, prevector, span, vecdeque
Other (50+): addition_overflow, asmap, chain, deserialize, fees, merkle, minisketch, policy_estimator

## References

Bitcoin Fuzzing: github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
QA Assets: github.com/bitcoin-core/qa-assets
libFuzzer: llvm.org/docs/LibFuzzer/
afl++: github.com/AFLplusplus/AFLplusplus
OSS-Fuzz: github.com/google/oss-fuzz

Document: November 3, 2025 - 136+ harnesses analyzed
