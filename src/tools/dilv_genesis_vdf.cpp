/**
 * DilV Genesis VDF Computation Tool
 *
 * Computes the VDF proof for the DilV genesis block and prints
 * the hardcoded C++ values to paste into genesis.cpp and chainparams.cpp.
 *
 * Genesis challenge derivation:
 *   prevHash     = 32 zero bytes (no previous block)
 *   height       = 0 (le32)
 *   minerAddress = 20 zero bytes (unspendable)
 *   challenge    = SHA3-256(prevHash || height || minerAddress) (56-byte preimage)
 *
 * Build:
 *   make dilv-genesis-vdf
 *
 * Usage:
 *   ./dilv-genesis-vdf
 */

#include <vdf/vdf.h>
#include <crypto/sha3.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <iomanip>
#include <iostream>
#include <sstream>

static const uint64_t DILV_VDF_ITERATIONS = 500000;

// Compute the genesis challenge: SHA3-256(zeros_32 || height_0_le32 || zeros_20)
static std::array<uint8_t, 32> ComputeGenesisChallenge() {
    uint8_t preimage[56];
    std::memset(preimage, 0, sizeof(preimage));
    // prevHash = 32 zero bytes (already zero)
    // height = 0 as le32 (already zero at offset 32)
    // minerAddress = 20 zero bytes (already zero at offset 36)

    std::array<uint8_t, 32> challenge{};
    SHA3_256(preimage, sizeof(preimage), challenge.data());
    return challenge;
}

static std::string BytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

static std::string BytesToCppArray(const uint8_t* data, size_t len, const std::string& name) {
    std::ostringstream oss;
    oss << "static const uint8_t " << name << "[" << len << "] = {";
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) oss << "\n    ";
        oss << "0x" << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
        if (i < len - 1) oss << ", ";
    }
    oss << "\n};";
    return oss.str();
}

int main() {
    std::cout << "=== DilV Genesis VDF Computation Tool ===" << std::endl;
    std::cout << std::endl;

    // Initialize VDF library
    if (!vdf::init()) {
        std::cerr << "ERROR: Failed to initialize VDF library" << std::endl;
        return 1;
    }

    // Step 1: Compute challenge
    std::cout << "Step 1: Computing genesis challenge..." << std::endl;
    auto challenge = ComputeGenesisChallenge();
    std::cout << "  Challenge: " << BytesToHex(challenge.data(), 32) << std::endl;
    std::cout << std::endl;

    // Step 2: Run VDF computation
    std::cout << "Step 2: Computing VDF with " << DILV_VDF_ITERATIONS << " iterations..." << std::endl;
    std::cout << "  (This may take a few seconds)" << std::endl;

    vdf::VDFConfig config;
    config.target_iterations = DILV_VDF_ITERATIONS;
    config.progress_interval = 100000;

    auto progressCb = [](uint64_t current, uint64_t total) {
        if (current % 100000 == 0) {
            std::cout << "  Progress: " << current << "/" << total
                      << " (" << (current * 100 / total) << "%)" << std::endl;
        }
    };

    vdf::VDFResult result = vdf::compute(challenge, DILV_VDF_ITERATIONS, config, progressCb);

    std::cout << std::endl;
    std::cout << "  VDF computation complete!" << std::endl;
    std::cout << "  Duration: " << (result.duration_us / 1000) << " ms" << std::endl;
    std::cout << "  Output: " << BytesToHex(result.output.data(), 32) << std::endl;
    std::cout << "  Proof size: " << result.proof.size() << " bytes" << std::endl;
    std::cout << std::endl;

    // Step 3: Compute proof hash
    std::cout << "Step 3: Computing proof hash..." << std::endl;
    auto proofHash = result.proof_hash();
    std::cout << "  Proof hash: " << BytesToHex(proofHash.data(), 32) << std::endl;
    std::cout << std::endl;

    // Step 4: Verify the proof
    std::cout << "Step 4: Verifying VDF proof..." << std::endl;
    bool valid = vdf::verify(challenge, result, config);
    std::cout << "  Verification: " << (valid ? "PASSED" : "FAILED") << std::endl;
    if (!valid) {
        std::cerr << "ERROR: VDF proof verification failed!" << std::endl;
        vdf::shutdown();
        return 1;
    }
    std::cout << std::endl;

    // Step 5: Output C++ code for genesis.cpp
    std::cout << "=========================================" << std::endl;
    std::cout << "= C++ CODE FOR genesis.cpp             =" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << std::endl;

    // VDF output bytes
    std::cout << "// VDF output (32 bytes) — result of " << DILV_VDF_ITERATIONS << " squarings" << std::endl;
    std::cout << BytesToCppArray(result.output.data(), 32, "vdfOutputBytes") << std::endl;
    std::cout << std::endl;

    // VDF proof hash bytes
    std::cout << "// VDF proof hash (32 bytes) — SHA3-256(proof_bytes)" << std::endl;
    std::cout << BytesToCppArray(proofHash.data(), 32, "vdfProofHashBytes") << std::endl;
    std::cout << std::endl;

    // VDF proof bytes (for coinbase embedding)
    std::cout << "// VDF proof (" << result.proof.size() << " bytes) — Wesolowski proof for coinbase" << std::endl;
    std::cout << BytesToCppArray(result.proof.data(), result.proof.size(), "genesisVdfProofBytes") << std::endl;
    std::cout << std::endl;

    // Genesis hash (need to compute actual block hash)
    std::cout << "// Genesis timestamp (use current UTC time):" << std::endl;
    std::cout << "// Set params.genesisTime in chainparams.cpp to a chosen launch timestamp" << std::endl;
    std::cout << std::endl;

    std::cout << "=========================================" << std::endl;
    std::cout << "= INSTRUCTIONS                         =" << std::endl;
    std::cout << "=========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "1. Copy the arrays above into genesis.cpp CreateDilVGenesisBlock()" << std::endl;
    std::cout << "2. Replace the placeholder arrays and empty proof vector" << std::endl;
    std::cout << "3. Set params.genesisTime in chainparams.cpp" << std::endl;
    std::cout << "4. Build dilv-node and run it to compute + print the genesis hash" << std::endl;
    std::cout << "5. Set params.genesisHash in chainparams.cpp" << std::endl;
    std::cout << std::endl;

    vdf::shutdown();
    return 0;
}
