// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <script/htlc.h>
#include <crypto/sha3.h>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// ============================================================================
// HTLC Script Creation
// ============================================================================

CScript CreateHTLCScript(const HTLCParameters& params) {
    // Validate parameters
    if (params.hash_lock.size() != 32) {
        throw std::runtime_error("HTLC hash_lock must be 32 bytes");
    }
    if (params.claim_pubkey_hash.size() != 20) {
        throw std::runtime_error("HTLC claim_pubkey_hash must be 20 bytes");
    }
    if (params.refund_pubkey_hash.size() != 20) {
        throw std::runtime_error("HTLC refund_pubkey_hash must be 20 bytes");
    }

    CScript script;

    // OP_IF branch: claim path (recipient reveals preimage)
    script << OP_IF;
    script << OP_SHA3_256;
    script << params.hash_lock;
    script << OP_EQUALVERIFY;
    script << OP_DUP;
    script << OP_HASH160;
    script << params.claim_pubkey_hash;
    script << OP_EQUALVERIFY;
    script << OP_CHECKSIG;

    // OP_ELSE branch: refund path (sender reclaims after timeout)
    script << OP_ELSE;
    // Push timeout height as script number
    CScriptNum timeout(static_cast<int64_t>(params.timeout_height));
    script << timeout.getvch();
    script << OP_CHECKLOCKTIMEVERIFY;
    script << OP_DROP;
    script << OP_DUP;
    script << OP_HASH160;
    script << params.refund_pubkey_hash;
    script << OP_EQUALVERIFY;
    script << OP_CHECKSIG;

    script << OP_ENDIF;

    return script;
}

CScript CreateHTLCClaimScript(const std::vector<uint8_t>& signature,
                               const std::vector<uint8_t>& pubkey,
                               const std::vector<uint8_t>& preimage) {
    if (signature.size() != DILITHIUM3_SIG_SIZE) {
        throw std::runtime_error("HTLC claim: signature must be 3309 bytes");
    }
    if (pubkey.size() != DILITHIUM3_PK_SIZE) {
        throw std::runtime_error("HTLC claim: pubkey must be 1952 bytes");
    }
    if (preimage.size() != 32) {
        throw std::runtime_error("HTLC claim: preimage must be 32 bytes");
    }

    CScript script;

    // Push: <signature> <pubkey> <preimage> OP_TRUE
    // OP_TRUE selects the IF branch
    script << signature;
    script << pubkey;
    script << preimage;
    script << OP_TRUE;

    return script;
}

CScript CreateHTLCRefundScript(const std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& pubkey) {
    if (signature.size() != DILITHIUM3_SIG_SIZE) {
        throw std::runtime_error("HTLC refund: signature must be 3309 bytes");
    }
    if (pubkey.size() != DILITHIUM3_PK_SIZE) {
        throw std::runtime_error("HTLC refund: pubkey must be 1952 bytes");
    }

    CScript script;

    // Push: <signature> <pubkey> OP_FALSE
    // OP_FALSE selects the ELSE branch
    script << signature;
    script << pubkey;
    script << OP_FALSE;

    return script;
}

// ============================================================================
// HTLC Script Decoding
// ============================================================================

bool DecodeHTLCScript(const CScript& script, HTLCParameters& params) {
    // HTLC script structure:
    //   OP_IF
    //     OP_SHA3_256 <32-byte hash_lock> OP_EQUALVERIFY
    //     OP_DUP OP_HASH160 <20-byte claim_hash> OP_EQUALVERIFY OP_CHECKSIG
    //   OP_ELSE
    //     <timeout_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
    //     OP_DUP OP_HASH160 <20-byte refund_hash> OP_EQUALVERIFY OP_CHECKSIG
    //   OP_ENDIF
    //
    // Minimum size: 1(IF) + 1(SHA3) + 1+32(hash) + 1(EQV) + 1(DUP) + 1(H160) +
    //   1+20(claim) + 1(EQV) + 1(CSIG) + 1(ELSE) + 1+N(timeout) + 1(CLTV) +
    //   1(DROP) + 1(DUP) + 1(H160) + 1+20(refund) + 1(EQV) + 1(CSIG) + 1(ENDIF)
    // = ~86+ bytes

    if (script.size() < 80) return false;

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();

    // Helper lambda to read opcode
    auto readOp = [&]() -> uint8_t {
        if (pc >= pend) throw std::runtime_error("unexpected end");
        return *pc++;
    };

    // Helper lambda to read data push
    auto readPush = [&](size_t expectedSize) -> std::vector<uint8_t> {
        if (pc >= pend) throw std::runtime_error("unexpected end");
        uint8_t opcode = *pc++;

        size_t nSize = 0;
        if (opcode > 0 && opcode < OP_PUSHDATA1) {
            nSize = opcode;
        } else if (opcode == OP_PUSHDATA1) {
            if (pc >= pend) throw std::runtime_error("unexpected end");
            nSize = *pc++;
        } else if (opcode == OP_PUSHDATA2) {
            if (pc + 2 > pend) throw std::runtime_error("unexpected end");
            nSize = pc[0] | (static_cast<size_t>(pc[1]) << 8);
            pc += 2;
        } else {
            throw std::runtime_error("expected data push");
        }

        if (expectedSize > 0 && nSize != expectedSize) {
            throw std::runtime_error("unexpected data size");
        }
        if (pc + nSize > pend) throw std::runtime_error("unexpected end");

        std::vector<uint8_t> data(pc, pc + nSize);
        pc += nSize;
        return data;
    };

    // Helper to read a variable-length number push (for timeout)
    auto readNumPush = [&]() -> std::pair<std::vector<uint8_t>, int64_t> {
        if (pc >= pend) throw std::runtime_error("unexpected end");
        uint8_t opcode = *pc++;

        size_t nSize = 0;
        if (opcode > 0 && opcode < OP_PUSHDATA1) {
            nSize = opcode;
        } else if (opcode == OP_PUSHDATA1) {
            if (pc >= pend) throw std::runtime_error("unexpected end");
            nSize = *pc++;
        } else {
            throw std::runtime_error("expected number push");
        }

        if (nSize > 5 || pc + nSize > pend) throw std::runtime_error("invalid number");

        std::vector<uint8_t> vch(pc, pc + nSize);
        pc += nSize;

        CScriptNum num(vch, 5);
        return {vch, num.getint()};
    };

    try {
        // OP_IF
        if (readOp() != OP_IF) return false;

        // OP_SHA3_256
        if (readOp() != OP_SHA3_256) return false;

        // <32-byte hash_lock>
        params.hash_lock = readPush(32);

        // OP_EQUALVERIFY
        if (readOp() != OP_EQUALVERIFY) return false;

        // OP_DUP
        if (readOp() != OP_DUP) return false;

        // OP_HASH160
        if (readOp() != OP_HASH160) return false;

        // <20-byte claim_pubkey_hash>
        params.claim_pubkey_hash = readPush(20);

        // OP_EQUALVERIFY
        if (readOp() != OP_EQUALVERIFY) return false;

        // OP_CHECKSIG
        if (readOp() != OP_CHECKSIG) return false;

        // OP_ELSE
        if (readOp() != OP_ELSE) return false;

        // <timeout_height>
        auto [vch, timeout] = readNumPush();
        if (timeout < 0) return false;
        params.timeout_height = static_cast<uint32_t>(timeout);

        // OP_CHECKLOCKTIMEVERIFY
        if (readOp() != OP_CHECKLOCKTIMEVERIFY) return false;

        // OP_DROP
        if (readOp() != OP_DROP) return false;

        // OP_DUP
        if (readOp() != OP_DUP) return false;

        // OP_HASH160
        if (readOp() != OP_HASH160) return false;

        // <20-byte refund_pubkey_hash>
        params.refund_pubkey_hash = readPush(20);

        // OP_EQUALVERIFY
        if (readOp() != OP_EQUALVERIFY) return false;

        // OP_CHECKSIG
        if (readOp() != OP_CHECKSIG) return false;

        // OP_ENDIF
        if (readOp() != OP_ENDIF) return false;

        // Should be at end of script
        if (pc != pend) return false;

    } catch (const std::exception&) {
        return false;
    }

    return true;
}

// ============================================================================
// Preimage Utilities
// ============================================================================

std::vector<uint8_t> GeneratePreimage() {
    std::vector<uint8_t> preimage(32);

#ifdef _WIN32
    // Windows: BCryptGenRandom (CSPRNG)
    NTSTATUS status = BCryptGenRandom(
        NULL,
        preimage.data(),
        static_cast<ULONG>(preimage.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (status != 0) {
        throw std::runtime_error("BCryptGenRandom failed for preimage generation");
    }
#else
    // Unix: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("Failed to open /dev/urandom for preimage generation");
    }
    ssize_t bytes_read = read(fd, preimage.data(), preimage.size());
    close(fd);
    if (bytes_read != 32) {
        throw std::runtime_error("Failed to read 32 bytes from /dev/urandom");
    }
#endif

    return preimage;
}

std::vector<uint8_t> HashPreimage(const std::vector<uint8_t>& preimage) {
    if (preimage.size() != 32) {
        throw std::runtime_error("Preimage must be exactly 32 bytes");
    }

    std::vector<uint8_t> hash(32);
    SHA3_256(preimage.data(), preimage.size(), hash.data());
    return hash;
}
