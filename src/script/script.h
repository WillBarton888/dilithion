// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_SCRIPT_SCRIPT_H
#define DILITHION_SCRIPT_SCRIPT_H

#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>

// ============================================================================
// Script System Constants
// ============================================================================

// Larger than Bitcoin's 10KB to accommodate Dilithium3 signatures (3309 bytes)
static const unsigned int MAX_SCRIPT_SIZE = 20000;

// Maximum stack depth
static const unsigned int MAX_STACK_SIZE = 1000;

// Accommodates Dilithium3 signature (3309) + pubkey (1952)
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 5300;

// Same as Bitcoin Core
static const unsigned int MAX_OPS_PER_SCRIPT = 201;

// Dilithium3 signature and key sizes
static const size_t DILITHIUM3_SIG_SIZE = 3309;
static const size_t DILITHIUM3_PK_SIZE = 1952;

// ============================================================================
// Opcode Definitions (Bitcoin-compatible numbering)
// ============================================================================

enum opcodetype : uint8_t {
    // Push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,

    // 0x01-0x4b: Push next N bytes onto stack (implicit data push)
    // e.g., 0x14 means "push next 20 bytes"

    OP_PUSHDATA1 = 0x4c,  // next 1 byte = length, then that many bytes
    OP_PUSHDATA2 = 0x4d,  // next 2 bytes (LE) = length, then that many bytes
    OP_PUSHDATA4 = 0x4e,  // next 4 bytes (LE) = length, then that many bytes

    OP_1NEGATE = 0x4f,

    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2  = 0x52,
    OP_3  = 0x53,
    OP_4  = 0x54,
    OP_5  = 0x55,
    OP_6  = 0x56,
    OP_7  = 0x57,
    OP_8  = 0x58,
    OP_9  = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Flow control
    OP_NOP    = 0x61,
    OP_IF     = 0x63,
    OP_NOTIF  = 0x64,
    OP_ELSE   = 0x67,
    OP_ENDIF  = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Stack operations
    OP_DUP  = 0x76,
    OP_DROP = 0x75,
    OP_SWAP = 0x7c,
    OP_SIZE = 0x82,

    // Bitwise / comparison
    OP_EQUAL       = 0x87,
    OP_EQUALVERIFY = 0x88,

    // Crypto
    OP_SHA3_256  = 0xa8,  // SHA3-256 (replaces Bitcoin's OP_SHA256 at same slot)
    OP_HASH160   = 0xa9,  // Double SHA3-256, first 20 bytes (matches WalletCrypto::HashPubKey)
    OP_CHECKSIG  = 0xac,
    OP_CHECKMULTISIG = 0xae,  // Future: multi-signature support

    // Locktime
    OP_CHECKLOCKTIMEVERIFY  = 0xb1,  // BIP-65: absolute locktime
    OP_CHECKSEQUENCEVERIFY  = 0xb2,  // BIP-112: relative locktime

    // Reserved NOPs for future soft forks
    OP_NOP1  = 0xb0,
    OP_NOP4  = 0xb3,
    OP_NOP5  = 0xb4,
    OP_NOP6  = 0xb5,
    OP_NOP7  = 0xb6,
    OP_NOP8  = 0xb7,
    OP_NOP9  = 0xb8,
    OP_NOP10 = 0xb9,

    // Sentinel for invalid opcode
    OP_INVALIDOPCODE = 0xff,
};

// ============================================================================
// Script Number (Bitcoin-compatible script integer encoding)
// ============================================================================

class CScriptNum {
public:
    // Bitcoin-style script number encoding:
    // - Little-endian with sign bit in the MSB of the last byte
    // - Default max size is 4 bytes (range: -2^31+1 to 2^31-1)
    // - OP_CHECKLOCKTIMEVERIFY/OP_CHECKSEQUENCEVERIFY use 5-byte numbers

    explicit CScriptNum(int64_t n) : m_value(n) {}

    explicit CScriptNum(const std::vector<uint8_t>& vch, size_t nMaxNumSize = 4) {
        if (vch.size() > nMaxNumSize) {
            throw std::runtime_error("script number overflow");
        }
        m_value = set_vch(vch);
    }

    int64_t getint() const { return m_value; }

    std::vector<uint8_t> getvch() const {
        return serialize(m_value);
    }

    static std::vector<uint8_t> serialize(int64_t value) {
        if (value == 0)
            return {};

        std::vector<uint8_t> result;
        bool neg = value < 0;
        uint64_t absvalue = neg ? -static_cast<uint64_t>(value) : static_cast<uint64_t>(value);

        while (absvalue) {
            result.push_back(static_cast<uint8_t>(absvalue & 0xff));
            absvalue >>= 8;
        }

        // If the MSB is set, we need an extra byte for the sign bit
        if (result.back() & 0x80) {
            result.push_back(neg ? 0x80 : 0x00);
        } else if (neg) {
            result.back() |= 0x80;
        }

        return result;
    }

private:
    static int64_t set_vch(const std::vector<uint8_t>& vch) {
        if (vch.empty())
            return 0;

        int64_t result = 0;
        for (size_t i = 0; i < vch.size(); ++i) {
            result |= static_cast<int64_t>(vch[i]) << (8 * i);
        }

        // If the MSB of the last byte is set, the number is negative
        if (vch.back() & 0x80)
            return -(result & ~(static_cast<int64_t>(0x80) << (8 * (vch.size() - 1))));

        return result;
    }

    int64_t m_value;
};

// ============================================================================
// CScript - Serialized script
// ============================================================================

class CScript : public std::vector<uint8_t> {
public:
    CScript() {}
    CScript(const_iterator pbegin, const_iterator pend) : std::vector<uint8_t>(pbegin, pend) {}
    CScript(const uint8_t* pbegin, const uint8_t* pend) : std::vector<uint8_t>(pbegin, pend) {}

    // Push an opcode
    CScript& operator<<(opcodetype opcode) {
        push_back(static_cast<uint8_t>(opcode));
        return *this;
    }

    // Push a small integer (OP_0 through OP_16)
    CScript& operator<<(int64_t n) {
        if (n == -1 || (n >= 1 && n <= 16)) {
            push_back(static_cast<uint8_t>(n + (OP_1 - 1)));
        } else if (n == 0) {
            push_back(OP_0);
        } else {
            *this << CScriptNum::serialize(n);
        }
        return *this;
    }

    // Push data with appropriate opcode
    CScript& operator<<(const std::vector<uint8_t>& data) {
        if (data.size() < 0x4c) {
            // Direct push: opcode IS the size
            push_back(static_cast<uint8_t>(data.size()));
        } else if (data.size() <= 0xff) {
            push_back(OP_PUSHDATA1);
            push_back(static_cast<uint8_t>(data.size()));
        } else if (data.size() <= 0xffff) {
            push_back(OP_PUSHDATA2);
            push_back(static_cast<uint8_t>(data.size() & 0xff));
            push_back(static_cast<uint8_t>((data.size() >> 8) & 0xff));
        } else {
            push_back(OP_PUSHDATA4);
            uint32_t len = static_cast<uint32_t>(data.size());
            push_back(static_cast<uint8_t>(len & 0xff));
            push_back(static_cast<uint8_t>((len >> 8) & 0xff));
            push_back(static_cast<uint8_t>((len >> 16) & 0xff));
            push_back(static_cast<uint8_t>((len >> 24) & 0xff));
        }
        insert(end(), data.begin(), data.end());
        return *this;
    }

    // ========================================================================
    // Script type detection
    // ========================================================================

    // Standard P2PKH: OP_DUP OP_HASH160 <20> <hash20> OP_EQUALVERIFY OP_CHECKSIG
    bool IsPayToPublicKeyHash() const {
        return (size() == 25 &&
                (*this)[0] == OP_DUP &&
                (*this)[1] == OP_HASH160 &&
                (*this)[2] == 0x14 &&  // Push 20 bytes
                (*this)[23] == OP_EQUALVERIFY &&
                (*this)[24] == OP_CHECKSIG);
    }

    // P2SH (future): OP_HASH160 <20> <hash20> OP_EQUAL
    bool IsPayToScriptHash() const {
        return (size() == 23 &&
                (*this)[0] == OP_HASH160 &&
                (*this)[1] == 0x14 &&
                (*this)[22] == OP_EQUAL);
    }

    // HTLC pattern detection (simplified — checks for OP_IF ... OP_SHA3_256 ... OP_CHECKLOCKTIMEVERIFY)
    bool IsHTLC() const {
        if (size() < 40) return false;
        // Must start with OP_IF and contain OP_SHA3_256 and OP_CHECKLOCKTIMEVERIFY
        bool hasIF = false, hasSHA3 = false, hasCLTV = false;
        for (size_t i = 0; i < size(); ++i) {
            if ((*this)[i] == OP_IF) hasIF = true;
            if ((*this)[i] == OP_SHA3_256) hasSHA3 = true;
            if ((*this)[i] == OP_CHECKLOCKTIMEVERIFY) hasCLTV = true;
        }
        return hasIF && hasSHA3 && hasCLTV;
    }

    // Provably unspendable: starts with OP_RETURN
    bool IsUnspendable() const {
        return (size() > 0 && (*this)[0] == OP_RETURN);
    }
};

// ============================================================================
// Helper to detect legacy (pre-script-interpreter) scriptSig format
// ============================================================================

// Legacy scriptSig uses 2-byte LE length prefixes instead of push opcodes.
// Format: [sig_size(2 LE)] [sig(3309)] [pk_size(2 LE)] [pk(1952)] = 5265 bytes
// New format uses OP_PUSHDATA2 (0x4d) prefix for sig and pubkey pushes.
inline bool IsLegacyScriptSig(const std::vector<uint8_t>& scriptSig) {
    const size_t LEGACY_SIZE = 2 + DILITHIUM3_SIG_SIZE + 2 + DILITHIUM3_PK_SIZE;  // 5265
    if (scriptSig.size() != LEGACY_SIZE) return false;
    // Legacy format starts with 2-byte LE size of 3309 = 0xED 0x0C
    uint16_t first_size = scriptSig[0] | (scriptSig[1] << 8);
    return first_size == DILITHIUM3_SIG_SIZE;
}

#endif // DILITHION_SCRIPT_SCRIPT_H
