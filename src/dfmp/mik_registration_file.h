// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DFMP_MIK_REGISTRATION_FILE_H
#define DILITHION_DFMP_MIK_REGISTRATION_FILE_H

/**
 * MIK Registration PoW Persistence (mik_registration.dat)
 *
 * Persists the solved 28-bit registration PoW (SHA3-256(pubkey||dna_hash||nonce))
 * so miners do NOT have to re-solve it on every resync or restart.
 *
 * File lives at {datadir}/mik_registration.dat, alongside wallet.dat — NOT inside
 * blocks/ or chainstate/, so --reset-chain can wipe chain state without touching it.
 *
 * Security: leaking this file alone is harmless. Consensus re-validates the PoW on
 * every block ([src/consensus/pow.cpp]), and signing still requires the MIK private
 * key from wallet.dat.
 *
 * On-disk format (little-endian, fixed size 2040 bytes):
 *   [magic:   4 bytes]  'M','R','P','W'
 *   [version: 4 bytes]  uint32_t = 1
 *   [pubkey: 1952 bytes] Dilithium3 public key
 *   [dnaHash:  32 bytes] DNA hash bound to the PoW solution
 *   [nonce:     8 bytes] uint64_t registration nonce
 *   [timestamp: 8 bytes] int64_t unix seconds when solved
 *   [checksum: 32 bytes] SHA3-256 over all preceding bytes
 */

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace DFMP {

struct MIKRegistrationFile {
    std::vector<uint8_t> pubkey;          // 1952 bytes
    std::array<uint8_t, 32> dnaHash{};
    uint64_t nonce = 0;
    int64_t timestamp = 0;
};

enum class MIKRegFileLoadResult {
    OK,                 // File loaded and checksum valid
    Missing,            // File does not exist (normal on first run)
    Corrupt,            // File exists but is malformed or checksum invalid
    PubkeyMismatch      // File valid but pubkey does not match current wallet MIK
};

/**
 * Save registration PoW to {datadir}/mik_registration.dat atomically.
 * Writes to a .tmp file then renames. Returns false on I/O failure.
 */
bool SaveMIKRegistration(const std::string& datadir,
                         const std::vector<uint8_t>& pubkey,
                         const std::array<uint8_t, 32>& dnaHash,
                         uint64_t nonce,
                         int64_t timestamp);

/**
 * Load registration PoW from {datadir}/mik_registration.dat.
 *
 * If expectedPubkey is non-empty, the loaded pubkey is compared to it. Mismatch
 * causes the file to be renamed to mik_registration.dat.stale (forensic trail)
 * and PubkeyMismatch is returned.
 *
 * Corrupt files are renamed to mik_registration.dat.corrupt.
 */
MIKRegFileLoadResult LoadMIKRegistration(const std::string& datadir,
                                         const std::vector<uint8_t>& expectedPubkey,
                                         MIKRegistrationFile& out);

/** Standard filename (no directory). */
extern const char* const MIK_REGISTRATION_FILENAME;

} // namespace DFMP

#endif // DILITHION_DFMP_MIK_REGISTRATION_FILE_H
