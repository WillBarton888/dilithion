// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_PRIMITIVES_BLOCK_H
#define DILITHION_PRIMITIVES_BLOCK_H

#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <iosfwd>

/** 256-bit hash */
class uint256 {
public:
    uint8_t data[32];
    
    uint256() { memset(data, 0, 32); }
    
    bool IsNull() const {
        for (int i = 0; i < 32; i++)
            if (data[i] != 0) return false;
        return true;
    }
    
    // CRITICAL-6 FIX: Document operator< byte order to prevent PoW misuse
    // WARNING: This operator uses LITTLE-ENDIAN byte order (memcmp)
    // ONLY use for STL containers (std::map, std::set, etc.)
    // NEVER use for PoW validation - use HashLessThan() instead
    // PoW requires BIG-ENDIAN comparison (MSB first)
    bool operator<(const uint256& other) const {
        return memcmp(data, other.data, 32) < 0;
    }
    
    bool operator==(const uint256& other) const {
        return memcmp(data, other.data, 32) == 0;
    }

    bool operator!=(const uint256& other) const {
        return memcmp(data, other.data, 32) != 0;
    }

    uint8_t* begin() { return data; }
    const uint8_t* begin() const { return data; }
    uint8_t* end() { return data + 32; }
    const uint8_t* end() const { return data + 32; }
    
    std::string GetHex() const;
    void SetHex(const std::string& str);
};

// Stream output operator for Boost.Test (defined in block.cpp)
std::ostream& operator<<(std::ostream& os, const uint256& h);

/** Helper function to construct uint256 from hex string (like Bitcoin Core's uint256S) */
inline uint256 uint256S(const std::string& str) {
    uint256 result;
    result.SetHex(str);
    return result;
}

class CBlockHeader {
public:
    // --- Legacy fields (80 bytes, all versions) ---
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    // --- VDF fields (64 bytes, version >= 4 only) ---
    uint256 vdfOutput;       // 32 bytes - VDF computation result
    uint256 vdfProofHash;    // 32 bytes - SHA3-256(full VDF proof)

    // IBD OPTIMIZATION: Cache the hash to avoid recomputation
    // This is mutable because GetHash() is logically const but caches the result
    mutable uint256 cachedHash;
    mutable bool fHashCached{false};

    // VDF block version threshold.
    static constexpr int32_t VDF_VERSION = 4;

    CBlockHeader() { SetNull(); }

    void SetNull() {
        nVersion = 0;
        hashPrevBlock = uint256();
        hashMerkleRoot = uint256();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vdfOutput = uint256();
        vdfProofHash = uint256();
        fHashCached = false;
        cachedHash = uint256();
    }

    bool IsNull() const { return (nBits == 0); }

    /** True if this block uses VDF consensus (version >= 4). */
    bool IsVDFBlock() const { return nVersion >= VDF_VERSION; }

    /** Serialized header size: 80 bytes (legacy) or 144 bytes (VDF). */
    size_t GetHeaderSize() const { return IsVDFBlock() ? 144 : 80; }

    /** Serialize the header into a byte vector (version-aware). */
    std::vector<uint8_t> SerializeHeader() const;

    // GetHash() - RandomX for legacy, SHA3-256 for VDF blocks
    // OPTIMIZATION: Cached - first call is slow for legacy (50-100ms), subsequent instant
    uint256 GetHash() const;

    // GetFastHash() - SHA3-256 hash for header identification (FAST: <0.01ms)
    // Use for map lookups when you don't need the canonical RandomX hash
    uint256 GetFastHash() const;

    // InvalidateCache() - Call after modifying header fields
    void InvalidateCache() { fHashCached = false; }
};

class CBlock : public CBlockHeader {
public:
    std::vector<uint8_t> vtx;

    CBlock() { SetNull(); }
    CBlock(const CBlockHeader &header) {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    void SetNull() {
        CBlockHeader::SetNull();
        vtx.clear();
    }
};

#endif
