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
    const uint8_t* mik_privkey, size_t mik_privkey_len,
    const std::array<uint8_t, 20>& mik,
    uint64_t timestamp,
    uint64_t nonce,
    const std::vector<uint8_t>& dna_data,
    std::vector<uint8_t>& signature_out)
{
    signature_out.clear();
    if (mik_privkey == nullptr || mik_privkey_len != DFMP::MIK_PRIVKEY_SIZE) {
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
        mik_privkey
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

static inline uint64_t read_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    }
    return v;
}

static inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

SampleEnvelope::ParseResult SampleEnvelope::TryParse(
    const std::vector<uint8_t>& trailer_bytes,
    SampleEnvelope& out)
{
    out = SampleEnvelope{};  // reset

    // No bytes after dna_data — unsigned payload from a pre-1.5 sender.
    if (trailer_bytes.empty()) {
        return ParseResult::NONE;
    }

    // Fewer bytes than the minimum magic length → definitionally malformed
    // (can't even tell what the magic is). Penalize.
    if (trailer_bytes.size() < MAGIC.size()) {
        return ParseResult::MALFORMED;
    }

    // Magic match check. Unknown magic = forward-compat silent-ignore.
    if (!std::equal(MAGIC.begin(), MAGIC.end(), trailer_bytes.begin())) {
        return ParseResult::UNKNOWN_MAGIC;
    }

    // SMP1 layout: magic(4) | ts_le(8) | nonce_le(8) | sig_len_le(2) | sig
    constexpr size_t HEADER_SIZE = 4 + 8 + 8 + 2;  // 22 bytes before signature
    if (trailer_bytes.size() < HEADER_SIZE) {
        return ParseResult::MALFORMED;  // truncated timestamp/nonce/sig_len
    }

    size_t off = MAGIC.size();
    uint64_t ts = read_le64(trailer_bytes.data() + off); off += 8;
    uint64_t nonce = read_le64(trailer_bytes.data() + off); off += 8;
    uint16_t sig_len = read_le16(trailer_bytes.data() + off); off += 2;

    size_t remaining = trailer_bytes.size() - off;

    // sig_len = 0 with non-zero trailing bytes — malformed (strict).
    // sig_len = 0 with zero trailing bytes — malformed too; an unsigned SMP1
    // trailer is meaningless (spec always pairs SMP1 with a real signature).
    if (sig_len == 0) {
        return ParseResult::MALFORMED;
    }

    // sig_len must match Dilithium3 signature size exactly. Any other size
    // is a protocol violation — penalize.
    if (sig_len != DFMP::MIK_SIGNATURE_SIZE) {
        return ParseResult::MALFORMED;
    }

    // Signature must fit exactly — no trailing bytes after signature (strict).
    if (sig_len != remaining) {
        return ParseResult::MALFORMED;
    }

    // Scan for a second SMP1 magic inside the trailer region. Parser defense
    // against ambiguous dual-interpretation: if a second magic occurs inside
    // the signature bytes (by coincidence or attacker design), that's fine
    // cryptographically — signature verification will fail or succeed based
    // on the bytes — but flag it so we don't later interpret those bytes as
    // a second trailer. The sig is 3309 bytes and the magic is 4 bytes, so
    // coincidental matches are rare but not zero. Reject to be strict.
    for (size_t i = 1; i + MAGIC.size() <= trailer_bytes.size(); ++i) {
        if (std::equal(MAGIC.begin(), MAGIC.end(), trailer_bytes.begin() + i)) {
            return ParseResult::MALFORMED;
        }
    }

    // All structural checks passed — copy the signature and return SIGNED.
    out.timestamp_sec = ts;
    out.nonce = nonce;
    out.signature.assign(trailer_bytes.begin() + off,
                         trailer_bytes.begin() + off + sig_len);
    return ParseResult::SIGNED;
}

std::vector<uint8_t> SampleEnvelope::ToWireBytes() const {
    std::vector<uint8_t> out;
    if (signature.size() != DFMP::MIK_SIGNATURE_SIZE) {
        // Caller error — return empty so sender falls back to unsigned.
        return out;
    }
    out.reserve(MAGIC.size() + 8 + 8 + 2 + signature.size());
    out.insert(out.end(), MAGIC.begin(), MAGIC.end());
    append_le64(out, timestamp_sec);
    append_le64(out, nonce);
    uint16_t sig_len = static_cast<uint16_t>(signature.size());
    out.push_back(static_cast<uint8_t>(sig_len & 0xFF));
    out.push_back(static_cast<uint8_t>((sig_len >> 8) & 0xFF));
    out.insert(out.end(), signature.begin(), signature.end());
    return out;
}

} // namespace digital_dna
