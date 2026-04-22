// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <digital_dna/sample_envelope.h>

#include <crypto/sha3.h>
#include <dfmp/mik.h>  // For MIK_PUBKEY_SIZE / MIK_PRIVKEY_SIZE / MIK_SIGNATURE_SIZE

#include <cstring>

// Dilithium3 reference implementation — same primitive used by MIK block
// signatures in src/dfmp/mik.cpp. Re-declared here to avoid coupling the
// digital_dna subsystem to the dfmp internal headers beyond size constants.
extern "C" {
    int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *sk);
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace digital_dna {

// Serialize a uint64 as 8 little-endian bytes into `out`, which must have
// at least 8 bytes of capacity already reserved.
static inline void append_le64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFFu));
    }
}

std::vector<uint8_t> SampleEnvelope::BuildSignTarget(
    const std::array<uint8_t, 20>& mik,
    uint64_t timestamp,
    uint64_t nonce,
    const std::vector<uint8_t>& dna_data)
{
    // Total: 7 (domain) + 20 (mik) + 8 (ts) + 8 (nonce) + 32 (SHA3-256) = 75 bytes
    std::vector<uint8_t> msg;
    msg.reserve(DOMAIN_LEN + mik.size() + 8 + 8 + 32);

    // Domain separator (raw ASCII, no terminator)
    msg.insert(msg.end(),
               reinterpret_cast<const uint8_t*>(DOMAIN),
               reinterpret_cast<const uint8_t*>(DOMAIN) + DOMAIN_LEN);

    // MIK
    msg.insert(msg.end(), mik.begin(), mik.end());

    // Timestamp + nonce (little-endian)
    append_le64(msg, timestamp);
    append_le64(msg, nonce);

    // SHA3-256 of the exact dna_data wire bytes. Binding to the wire bytes
    // (not to a canonical structural hash) keeps verify independent of
    // serializer drift across versions.
    uint8_t digest[32];
    if (dna_data.empty()) {
        SHA3_256(nullptr, 0, digest);
    } else {
        SHA3_256(dna_data.data(), dna_data.size(), digest);
    }
    msg.insert(msg.end(), digest, digest + 32);

    return msg;
}

bool SampleEnvelope::Sign(
    const std::vector<uint8_t>& mik_privkey,
    const std::array<uint8_t, 20>& mik,
    uint64_t timestamp,
    uint64_t nonce,
    const std::vector<uint8_t>& dna_data,
    std::vector<uint8_t>& signature_out)
{
    signature_out.clear();
    if (mik_privkey.size() != DFMP::MIK_PRIVKEY_SIZE) {
        return false;
    }

    auto msg = BuildSignTarget(mik, timestamp, nonce, dna_data);

    signature_out.resize(DFMP::MIK_SIGNATURE_SIZE);
    size_t siglen = 0;

    // Empty context — matches MIK block signing in src/dfmp/mik.cpp:111.
    int result = pqcrystals_dilithium3_ref_signature(
        signature_out.data(), &siglen,
        msg.data(), msg.size(),
        nullptr, 0,
        mik_privkey.data()
    );

    if (result != 0 || siglen != DFMP::MIK_SIGNATURE_SIZE) {
        signature_out.clear();
        return false;
    }
    return true;
}

bool SampleEnvelope::Verify(
    const std::vector<uint8_t>& mik_pubkey,
    const std::array<uint8_t, 20>& mik,
    uint64_t timestamp,
    uint64_t nonce,
    const std::vector<uint8_t>& dna_data,
    const std::vector<uint8_t>& signature)
{
    if (mik_pubkey.size() != DFMP::MIK_PUBKEY_SIZE) {
        return false;
    }
    if (signature.size() != DFMP::MIK_SIGNATURE_SIZE) {
        return false;
    }

    auto msg = BuildSignTarget(mik, timestamp, nonce, dna_data);

    int result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),
        msg.data(), msg.size(),
        nullptr, 0,
        mik_pubkey.data()
    );
    return result == 0;
}

} // namespace digital_dna
