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
#include <optional>
#include <vector>

namespace digital_dna {

struct SampleEnvelope {
    /// 4-byte magic identifying the signed trailer.
    static constexpr std::array<uint8_t, 4> MAGIC = {'S', 'M', 'P', '1'};

    /// 7-byte domain separator inside the signed bytes.
    /// Prevents cross-protocol reuse against MIK block signatures.
    static constexpr char DOMAIN[] = "DNASMP1";
    static constexpr size_t DOMAIN_LEN = 7;  // strlen("DNASMP1")

    /// Result of TryParse — distinguishes unsigned/no-trailer from malformed.
    enum class ParseResult {
        /// No trailer bytes present (pre-Phase-1.5 sender).
        NONE,
        /// Valid SMP1 trailer parsed into the struct.
        SIGNED,
        /// Unknown magic at trailer offset — silent-ignore (forward-compat
        /// slot for hypothetical future trailer formats like SMP2). Not a
        /// misbehaviour.
        UNKNOWN_MAGIC,
        /// SMP1 magic matched but bytes malformed (truncated fields, bad
        /// sig_len, duplicate magic, trailing garbage). Peer should be
        /// penalised — misbehaviour 10 at the caller.
        MALFORMED,
    };

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
    /// (`MIK_PRIVKEY_SIZE` bytes). Takes raw pointer + length so callers can
    /// pass keys from secure-allocator containers (e.g. the wallet's
    /// SecureAllocator-backed privkey) without copying into an unprotected
    /// `std::vector<uint8_t>`. `signature_out` is resized to the signature
    /// length on success (`MIK_SIGNATURE_SIZE`), cleared on failure.
    /// Returns true iff the signature was produced.
    static bool Sign(const uint8_t* mik_privkey, size_t mik_privkey_len,
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

    /// Parse the optional trailer bytes that appear after `dna_data` in a
    /// `dnaires` payload. `trailer_bytes` is the tail of the payload starting
    /// at offset `header + data_len` (empty if no bytes remain after the DNA
    /// blob). The receiver MUST NOT pass bytes from inside `dna_data` here —
    /// the offset rule is part of Phase 1.5 security (no dual-parse).
    ///
    /// On `SIGNED`, the returned envelope is populated and the signature
    /// field is exactly MIK_SIGNATURE_SIZE bytes (3309). Caller still needs
    /// to run `Verify()` to check authenticity.
    static ParseResult TryParse(const std::vector<uint8_t>& trailer_bytes,
                                SampleEnvelope& out);

    /// Build the trailer byte string for an already-signed envelope. Used
    /// by the sender to append after `dna_data` when the peer supports
    /// Phase 1.5. Returns the raw bytes:
    ///   magic(4) | ts_le(8) | nonce_le(8) | sig_len_le(2) | signature
    std::vector<uint8_t> ToWireBytes() const;
};

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_SAMPLE_ENVELOPE_H
