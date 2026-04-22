// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DIGITAL_DNA_SAMPLE_ENVELOPE_H
#define DILITHION_DIGITAL_DNA_SAMPLE_ENVELOPE_H

/**
 * DNA sample envelope (Phase 1.5 signed propagation).
 *
 * Wraps a DNA broadcast with a Dilithium3 signature so any peer can verify
 * the sample authentically originated from the MIK holder. Lets unmapped
 * peers push full-replacement updates (not just dim-fill), which closes the
 * propagation gap left after Phase 1.1 for legitimate updates that arrive
 * via relay chains.
 *
 * Wire trailer format (appended to existing `dnaires` payload):
 *   magic(4)          = 'S','M','P','1'
 *   timestamp_sec(8)  uint64 LE — sender's wall clock at signing
 *   nonce(8)          uint64 LE — random, unique per sample (replay defense)
 *   sig_len(2)        uint16 LE
 *   signature(sig_len) Dilithium3 sig, MIK_SIGNATURE_SIZE when present
 *
 * Sign target — domain-separated so the sig cannot be reused in any other
 * MIK-keyed protocol (block signing, future envelopes):
 *   sig_msg = "DNASMP1" || mik(20) || ts_le(8) || nonce_le(8) || SHA3_256(dna_data)
 *
 * This module is pure crypto — no long-lived state, no threading concerns.
 * Lookup of the MIK's Dilithium3 pubkey is handled separately by
 * `MikPubkeyCache` (populated by block-connect callbacks, read-through to
 * `dfmp_identity/` LevelDB).
 */

#include <array>
#include <cstdint>
#include <vector>

namespace digital_dna {

struct SampleEnvelope {
    /// 4-byte magic identifying the signed trailer.
    static constexpr std::array<uint8_t, 4> MAGIC = {'S', 'M', 'P', '1'};

    /// 7-byte domain separator inside the signed bytes.
    /// Prevents cross-protocol reuse against MIK block signatures.
    static constexpr char DOMAIN[] = "DNASMP1";
    static constexpr size_t DOMAIN_LEN = 7;  // strlen("DNASMP1")

    uint64_t timestamp_sec = 0;
    uint64_t nonce = 0;
    std::vector<uint8_t> signature;  // empty = unsigned

    /// Build the exact byte string that gets signed/verified.
    /// sig_msg = DOMAIN || mik(20) || ts_le(8) || nonce_le(8) || SHA3_256(dna_data)
    static std::vector<uint8_t> BuildSignTarget(
        const std::array<uint8_t, 20>& mik,
        uint64_t timestamp,
        uint64_t nonce,
        const std::vector<uint8_t>& dna_data);

    /// Sign a DNA sample. `mik_privkey` must be a valid Dilithium3 secret key
    /// (`MIK_PRIVKEY_SIZE` bytes). `signature_out` is resized to the signature
    /// length on success (`MIK_SIGNATURE_SIZE`), cleared on failure.
    /// Returns true iff the signature was produced.
    static bool Sign(const std::vector<uint8_t>& mik_privkey,
                     const std::array<uint8_t, 20>& mik,
                     uint64_t timestamp,
                     uint64_t nonce,
                     const std::vector<uint8_t>& dna_data,
                     std::vector<uint8_t>& signature_out);

    /// Verify a signed DNA sample. `mik_pubkey` must be the MIK's registered
    /// Dilithium3 public key (`MIK_PUBKEY_SIZE` bytes). Constant-time at the
    /// Dilithium3 library level.
    /// Returns true iff the signature validates against the reconstructed
    /// sign-target bytes.
    static bool Verify(const std::vector<uint8_t>& mik_pubkey,
                       const std::array<uint8_t, 20>& mik,
                       uint64_t timestamp,
                       uint64_t nonce,
                       const std::vector<uint8_t>& dna_data,
                       const std::vector<uint8_t>& signature);
};

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_SAMPLE_ENVELOPE_H
