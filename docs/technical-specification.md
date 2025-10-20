# Dilithion Technical Specification

**Version:** 0.1.0-draft
**Date:** October 2025
**Status:** Foundation Phase
**Authors:** Dilithion Core Team

---

## Abstract

Dilithion is a quantum-resistant cryptocurrency that replaces Bitcoin's ECDSA (secp256k1) signature scheme with CRYSTALS-Dilithium, a lattice-based post-quantum cryptographic signature scheme standardized by NIST as FIPS 204. This document specifies the technical details of the Dilithion protocol, including cryptographic primitives, consensus rules, network protocol, and implementation details.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Address Format](#3-address-format)
4. [Transaction Format](#4-transaction-format)
5. [Block Format](#5-block-format)
6. [Consensus Rules](#6-consensus-rules)
7. [Network Protocol](#7-network-protocol)
8. [Wallet Implementation](#8-wallet-implementation)
9. [Security Considerations](#9-security-considerations)
10. [Implementation Notes](#10-implementation-notes)

---

## 1. Introduction

### 1.1 Motivation

Quantum computers pose an existential threat to current cryptocurrencies that rely on ECDSA for transaction signing. Shor's algorithm can break ECDSA in polynomial time on a sufficiently large quantum computer. Dilithion addresses this threat by implementing post-quantum cryptography while maintaining Bitcoin's proven consensus mechanism.

### 1.2 Design Goals

1. **Quantum Resistance:** Secure against quantum computer attacks
2. **Proven Consensus:** Reuse Bitcoin's battle-tested Nakamoto consensus
3. **Minimal Changes:** Only modify what's necessary for quantum resistance
4. **Fair Launch:** No premine, no ICO, complete decentralization
5. **ASIC Compatibility:** Maintain SHA-256 mining for existing hardware

### 1.3 Scope

This specification covers:
- Cryptographic scheme selection and implementation
- Changes to Bitcoin Core required for quantum resistance
- Consensus rule modifications
- Network protocol updates
- Wallet and address format

This specification does NOT cover:
- Mining pool protocols (reuse Bitcoin's)
- Exchange integration
- Future protocol upgrades
- Economic policy (identical to Bitcoin)

---

## 2. Cryptographic Primitives

### 2.1 Digital Signature Scheme

**Algorithm:** CRYSTALS-Dilithium
**Parameter Set:** Dilithium-2
**Security Level:** NIST Security Level 2 (equivalent to 128-bit security)
**Standard:** NIST FIPS 204

#### 2.1.1 Parameter Specifications

```
DILITHIUM_MODE = 2

// Key sizes
PUBLIC_KEY_SIZE = 1312 bytes
SECRET_KEY_SIZE = 2560 bytes
SIGNATURE_SIZE = 2420 bytes

// Dilithium-2 parameters
q = 8380417 (prime modulus)
d = 13 (dropped bits)
τ = 39 (number of +1/-1 in c)
γ1 = 2^17 (coefficient range)
γ2 = (q-1)/88
k = 4 (dimensions)
l = 4 (dimensions)
η = 2 (secret key range)
β = τ * η = 78
ω = 80 (max number of 1s in hint h)
```

#### 2.1.2 Key Generation

```
Input: Random seed ζ (256 bits from cryptographically secure RNG)
Output: (pk, sk) where pk is public key, sk is secret key

Algorithm:
1. Generate matrix A from seed ρ (derived from ζ)
2. Sample secret vectors s1, s2 from uniform distribution
3. Compute t = As1 + s2
4. Pack pk = (ρ, t1) where t1 = HighBits(t)
5. Pack sk = (ρ, K, tr, s1, s2, t0)
6. Return (pk, sk)

Implementation: pqcrystals_dilithium2_ref_keypair()
```

#### 2.1.3 Signature Generation

```
Input: Message m, secret key sk
Output: Signature σ

Algorithm:
1. Compute message hash μ = H(tr || m)
2. Sample random nonce κ
3. Generate masking vector y
4. Compute w = Ay
5. Compute challenge c = H(μ || w1)
6. Compute response z = y + cs1
7. Compute hint h = MakeHint(-ct0, w - cs2 + ct0)
8. If ||z|| too large or ||w - cs2|| too large, restart
9. Return σ = (z, h, c)

Implementation: pqcrystals_dilithium2_ref_signature()
```

#### 2.1.4 Signature Verification

```
Input: Message m, signature σ = (z, h, c), public key pk
Output: true if valid, false otherwise

Algorithm:
1. Parse pk = (ρ, t1)
2. Compute message hash μ = H(tr || m)
3. Regenerate challenge c' = H(μ || UseHint(h, w' - ct))
4. Check c = c'
5. Check ||z|| < γ1 - β
6. Check number of 1s in h ≤ ω
7. Return true if all checks pass

Implementation: pqcrystals_dilithium2_ref_verify()
```

### 2.2 Hash Functions

#### 2.2.1 SHA-256 (Unchanged from Bitcoin)

**Usage:** Block hashing, Merkle tree, Proof of Work
**Rationale:** SHA-256 is quantum-resistant (Grover's algorithm only provides quadratic speedup)

#### 2.2.2 BLAKE3

**Usage:** Address generation (hash of public key)
**Output Size:** 256 bits (32 bytes)
**Rationale:** Modern, fast, secure hash function with 256-bit output (needed for larger public keys)

```cpp
// Address generation
address_hash = BLAKE3(public_key)
```

### 2.3 Random Number Generation

**Source:** Operating system entropy (`/dev/urandom`, `CryptGenRandom`, etc.)
**Implementation:** Bitcoin Core's `GetStrongRandBytes()`
**Usage:** Private key generation, signature nonces

**Critical:** Must use cryptographically secure RNG. Weak RNG = key compromise.

---

## 3. Address Format

### 3.1 Address Hash

Bitcoin uses `RIPEMD160(SHA256(pubkey))` = 20 bytes.

Dilithion uses `BLAKE3(pubkey)` = 32 bytes.

**Rationale:** Dilithium public keys are 1,312 bytes. Birthday attack resistance requires hash output ≥ 2×security_level. For 128-bit security, need 256-bit hash.

### 3.2 Address Encoding

**Encoding:** Bech32m (BIP 350)
**Human-Readable Part (HRP):** `qb` (quantum-bitcoin)
**Witness Version:** 0

#### 3.2.1 Format

```
qb1q<32-byte-address-hash-in-bech32m>
```

**Example:**
```
qb1qxyz...abc (52 characters total)
```

#### 3.2.2 Legacy Format (Optional, for tooling compatibility)

**Encoding:** Base58Check
**Version Byte:**
- Mainnet P2PKH: `0x3F` (addresses start with 'Q')
- Mainnet P2SH: `0x41` (addresses start with 'R')
- Testnet P2PKH: `0x6F` (addresses start with 'q')
- Testnet P2SH: `0xC4` (addresses start with '2')

**Format:**
```
Q<base58-encoded-address> (35 characters)
```

### 3.3 Address Generation Algorithm

```cpp
// From public key to address
void GenerateAddress(const CPubKey& pubkey, std::string& address) {
    // 1. Hash public key with BLAKE3
    uint256 pubkey_hash = BLAKE3(pubkey.data(), pubkey.size());

    // 2. Encode with Bech32m
    std::vector<uint8_t> data(pubkey_hash.begin(), pubkey_hash.end());
    address = bech32::Encode(bech32::Encoding::BECH32M, "qb", data);
}
```

---

## 4. Transaction Format

### 4.1 Transaction Structure

Transaction structure is IDENTICAL to Bitcoin, but signatures are larger.

```cpp
class CTransaction {
    int32_t nVersion;           // Transaction version (same as Bitcoin)
    std::vector<CTxIn> vin;     // Transaction inputs
    std::vector<CTxOut> vout;   // Transaction outputs
    uint32_t nLockTime;         // Lock time (same as Bitcoin)
};
```

### 4.2 Transaction Input

```cpp
class CTxIn {
    COutPoint prevout;          // Previous transaction output
    CScript scriptSig;          // Signature script (LARGER)
    uint32_t nSequence;         // Sequence number
};
```

**Key Difference:** `scriptSig` now contains Dilithium signatures (2,420 bytes) instead of ECDSA signatures (~72 bytes).

### 4.3 Script Templates

#### 4.3.1 Pay-to-PubKey-Hash (P2PKH)

**ScriptPubKey:**
```
OP_DUP OP_HASH256 <32-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
```

**ScriptSig:**
```
<dilithium-signature> <dilithium-public-key>
```

**Sizes:**
- Signature: 2,420 bytes
- Public key: 1,312 bytes
- Total scriptSig: ~3,732 bytes (vs Bitcoin's ~107 bytes)

#### 4.3.2 Pay-to-Script-Hash (P2SH)

**ScriptPubKey:**
```
OP_HASH256 <32-byte-script-hash> OP_EQUAL
```

**ScriptSig:**
```
<data> ... <data> <serialized-script>
```

### 4.4 Transaction Size Implications

**Bitcoin Average Transaction:**
- 1 input, 2 outputs
- ~250 bytes

**Dilithion Average Transaction:**
- 1 input, 2 outputs
- ~3,850 bytes (≈15× larger)

**Worst Case (10 inputs, 2 outputs):**
- Bitcoin: ~1,500 bytes
- Dilithion: ~38,000 bytes (≈25× larger)

### 4.5 Transaction Weight

Transaction weight calculation (similar to SegWit):

```
tx_weight = base_size × 3 + total_size
```

Where:
- `base_size` = transaction size without signatures
- `total_size` = complete transaction size including signatures

**Maximum Transaction Size:** 100,000 bytes (same as Bitcoin's policy rule)

---

## 5. Block Format

### 5.1 Block Structure

Block structure is IDENTICAL to Bitcoin:

```cpp
class CBlock {
    CBlockHeader header;
    std::vector<CTransaction> vtx;
};
```

### 5.2 Block Header

**UNCHANGED from Bitcoin:**

```cpp
class CBlockHeader {
    int32_t nVersion;           // Block version
    uint256 hashPrevBlock;      // Previous block hash
    uint256 hashMerkleRoot;     // Merkle root of transactions
    uint32_t nTime;             // Timestamp
    uint32_t nBits;             // Difficulty target
    uint32_t nNonce;            // Proof-of-work nonce
};
```

**Size:** 80 bytes (identical to Bitcoin)

### 5.3 Block Size Limits

**Maximum Block Size:** 4,000,000 bytes (4 MB)

**Rationale:**
- Bitcoin: ~2,000 transactions per 1 MB = 2,000 tx/block
- Dilithion: ~250 transactions per 4 MB ≈ 250 tx/block (maintain similar throughput)
- Average transaction is 15× larger → need 15× larger blocks

**Maximum Block Weight:** 16,000,000 (4× the size limit, same ratio as Bitcoin's SegWit)

### 5.4 Merkle Tree

**Hash Function:** SHA-256 (unchanged)
**Construction:** Identical to Bitcoin

**Rationale:** SHA-256 is quantum-resistant against Grover's algorithm. No changes needed.

---

## 6. Consensus Rules

### 6.1 Block Validation

#### 6.1.1 Block Size

```cpp
if (block.GetSerializeSize() > MAX_BLOCK_SIZE) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length");
}

const unsigned int MAX_BLOCK_SIZE = 4000000;  // 4 MB
```

#### 6.1.2 Transaction Validation

Identical to Bitcoin, except signature verification uses Dilithium:

```cpp
bool CheckSig(const vector<unsigned char>& vchSig,
              const vector<unsigned char>& vchPubKey,
              const CScript& scriptCode,
              const CTransaction& txTo, unsigned int nIn) {

    // Verify sizes
    if (vchPubKey.size() != 1312) return false;
    if (vchSig.size() != 2420) return false;

    // Compute signature hash (same as Bitcoin)
    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);

    // Verify with Dilithium
    return dilithium::Verify(vchSig.data(), vchSig.size(),
                             sighash.begin(), 32,
                             vchPubKey.data());
}
```

### 6.2 Proof of Work

**UNCHANGED from Bitcoin:**

**Algorithm:** SHA-256d (double SHA-256)
**Target Adjustment:** Every 2,016 blocks
**Target Block Time:** 10 minutes
**Target Timespan:** 2 weeks

```cpp
uint256 CalculateNextWorkRequired(const CBlockIndex* pindexLast,
                                  int64_t nFirstBlockTime,
                                  const Consensus::Params& params) {
    // IDENTICAL to Bitcoin
    // No changes needed - SHA-256 is quantum-resistant
}
```

**Rationale:** SHA-256 only gets square-root speedup from Grover's algorithm, which is acceptable. Reusing Bitcoin's PoW allows ASIC compatibility.

### 6.3 Block Reward and Supply

**IDENTICAL to Bitcoin:**

- **Initial Reward:** 50 DILI
- **Halving Interval:** 210,000 blocks (~4 years)
- **Total Supply:** 21,000,000 DILI
- **Smallest Unit:** 0.00000001 DILI (1 satoshi)

```cpp
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams) {
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    if (halvings >= 64) return 0;

    CAmount nSubsidy = 50 * COIN;
    nSubsidy >>= halvings;
    return nSubsidy;
}
```

### 6.4 Difficulty Adjustment

**IDENTICAL to Bitcoin:**

```cpp
// Retarget every 2,016 blocks
const int64_t nTargetTimespan = 14 * 24 * 60 * 60;  // 2 weeks
const int64_t nTargetSpacing = 10 * 60;             // 10 minutes
const int64_t nInterval = nTargetTimespan / nTargetSpacing;  // 2,016 blocks
```

### 6.5 Genesis Block

**Timestamp:** To be determined (launch date)
**Difficulty:** 0x1d00ffff (same as Bitcoin's genesis)
**Reward:** 50 DILI
**Message:** (To be determined - current event headline)

```cpp
const char* pszTimestamp = "NY Times 01/Jan/2027 Quantum Computer Threatens Bitcoin";
```

---

## 7. Network Protocol

### 7.1 P2P Protocol Version

**Protocol Version:** 70016 (or next available)
**Minimum Supported:** 70016

### 7.2 Message Format

**UNCHANGED from Bitcoin:**

All P2P messages use Bitcoin's existing format:
- Magic bytes (network identifier)
- Command name
- Payload length
- Checksum
- Payload

### 7.3 Network Identifier

**Mainnet Magic Bytes:** `0xF9BEE8D9` → Change to `0xD9E8BEF9` (reversed)
**Testnet Magic Bytes:** `0x0B110907` → Change to `0x0709110B` (reversed)

**Rationale:** Different magic bytes prevent accidental connection to Bitcoin network.

### 7.4 Default Ports

**Mainnet:** 8433 (not 8333)
**Testnet:** 18433 (not 18333)
**RPC:** 8432 (not 8332)

### 7.5 Message Size Limits

Updated to accommodate larger transactions:

```cpp
// Maximum size of a protocol message
static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 8 * 1000 * 1000;  // 8 MB

// Maximum size for a single transaction
static const unsigned int MAX_TX_SIZE = 100 * 1000;  // 100 KB
```

### 7.6 Compact Blocks

Compact blocks (BIP 152) work with larger transactions. Short transaction IDs remain 6 bytes.

**Modification:** Increase block reconstruction buffer to handle 4 MB blocks.

---

## 8. Wallet Implementation

### 8.1 Key Storage

#### 8.1.1 Wallet Format

**Format:** Berkeley DB (same as Bitcoin) or SQLite
**Encryption:** AES-256-CBC (same as Bitcoin)

**Key Storage:**
```cpp
struct CKey {
    unsigned char vchPrivKey[2560];  // Dilithium secret key
    bool fCompressed = false;        // Not used (no compression for Dilithium)
};
```

**Wallet Size Impact:**
- Bitcoin: 32 bytes per private key
- Dilithion: 2,560 bytes per private key (80× larger)
- 1,000 keys: Bitcoin = 32 KB, Dilithion = 2.5 MB

#### 8.1.2 HD Wallet Derivation

**Problem:** BIP32 HD wallets don't work with Dilithium (relies on ECDSA properties).

**Solution (Phase 1):** No HD derivation. Store keys individually.

**Future Solution:** Define quantum-resistant HD scheme (research needed).

### 8.2 Address Book

Address book stores 32-byte hashes instead of 20-byte hashes.

```cpp
// Bitcoin
std::map<uint160, CAddressBookData> mapAddressBook;

// Dilithion
std::map<uint256, CAddressBookData> mapAddressBook;
```

### 8.3 Backup Format

**Wallet Backup:** Same as Bitcoin (encrypted Berkeley DB file)
**Paper Wallet:** Base58-encoded private key (longer than Bitcoin)

**Private Key Length:**
- Bitcoin: 51 characters (WIF format)
- Dilithion: ~3,500 characters (impractical for paper)

**Recommendation:** Use QR codes for private key backup.

---

## 9. Security Considerations

### 9.1 Quantum Security

#### 9.1.1 Signature Scheme

**Dilithium Security:** Based on hardness of Module-LWE (Learning With Errors over module lattices).

**Known Attacks:**
- Best classical attack: 2^128 operations (for Dilithium-2)
- Best quantum attack: 2^128 operations (Grover's algorithm doesn't help significantly)

**Conclusion:** Dilithium-2 provides adequate post-quantum security.

#### 9.1.2 Hash Functions

**SHA-256:** Quantum attack via Grover's algorithm reduces security from 256 bits to 128 bits (2^128 operations).

**Verdict:** Still acceptable for mining and Merkle trees. No change needed.

**BLAKE3:** Same analysis applies. 256-bit output provides 128-bit quantum security.

### 9.2 Side-Channel Resistance

**Critical:** Dilithium implementation MUST be constant-time.

**Requirements:**
1. No branching on secret data
2. No secret-dependent memory access
3. Constant-time comparison functions
4. Memory cleared after use

**Implementation:** Use reference implementation from pq-crystals or liboqs (both implement constant-time operations).

### 9.3 Randomness Requirements

**Private Key Generation:** Requires 256 bits of cryptographically secure randomness.

**Signature Nonces:** Requires fresh randomness for each signature (nonce reuse = key compromise).

**Source:** Operating system CSPRNG (`/dev/urandom`, `BCryptGenRandom`, etc.)

### 9.4 Network Security

**Same threats as Bitcoin:**
- Sybil attacks
- Eclipse attacks
- 51% attacks
- DoS attacks

**Additional consideration:** Larger transaction size increases bandwidth requirements, potentially making DoS easier.

**Mitigation:** Connection limits, rate limiting, fee requirements.

---

## 10. Implementation Notes

### 10.1 Build Dependencies

**Required Libraries:**
- libboost (same as Bitcoin)
- libdb (Berkeley DB)
- libevent
- libsecp256k1 (remove - no longer needed)
- **pq-crystals/dilithium** OR **liboqs**

### 10.2 Performance Considerations

#### 10.2.1 Signature Verification

**Dilithium-2 Performance:**
- Key generation: ~0.3 ms
- Signing: ~1.0 ms
- Verification: ~0.4 ms

**Bitcoin (ECDSA) Performance:**
- Key generation: ~0.05 ms
- Signing: ~0.05 ms
- Verification: ~0.2 ms

**Impact:** Signature verification is 2× slower, but still <1ms. Acceptable for consensus validation.

#### 10.2.2 Block Propagation

**4 MB blocks take longer to propagate.**

**Estimated propagation time:**
- 100 Mbps connection: ~0.3 seconds
- 10 Mbps connection: ~3 seconds
- 1 Mbps connection: ~30 seconds

**Mitigation:** Compact blocks, FIBRE network (like Bitcoin).

#### 10.2.3 Initial Block Download

**Blockchain Size Growth:**
- Bitcoin: ~500 GB after 14 years
- Dilithion: Estimated ~7,500 GB after 14 years (15× larger)

**Mitigation:** Pruning mode, assumevalid, lighter nodes.

### 10.3 Testing Requirements

1. **Unit Tests:** All cryptographic operations
2. **Functional Tests:** All Bitcoin functional tests (modified for larger signatures)
3. **Integration Tests:** Multi-node testnet
4. **Stress Tests:** Maximum-size blocks and transactions
5. **Fuzz Testing:** All parsing and cryptographic code
6. **Side-Channel Testing:** Timing analysis of signature operations

### 10.4 Compatibility

**NOT compatible with:**
- Bitcoin addresses
- Bitcoin wallets
- Bitcoin block explorers
- Bitcoin mining pools (without modification)

**Compatible with:**
- Bitcoin ASIC miners (SHA-256)
- Bitcoin difficulty adjustment
- Bitcoin's economic model

---

## 11. References

### 11.1 Standards

- [NIST FIPS 204: CRYSTALS-Dilithium](https://csrc.nist.gov/publications/detail/fips/204/final)
- [Bitcoin Core 25.0 Documentation](https://github.com/bitcoin/bitcoin/tree/v25.0/doc)
- [BIP 32: HD Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP 350: Bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)

### 11.2 Implementations

- [CRYSTALS-Dilithium Reference](https://github.com/pq-crystals/dilithium)
- [liboqs: Open Quantum Safe](https://github.com/open-quantum-safe/liboqs)
- [Bitcoin Core](https://github.com/bitcoin/bitcoin)

### 11.3 Research Papers

- Dilithium: CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation
- Post-Quantum Cryptography: NIST PQC Standardization Process

---

## Appendix A: Comparison Table

| Feature | Bitcoin | Dilithion |
|---------|---------|-----------|
| **Signature Scheme** | ECDSA (secp256k1) | CRYSTALS-Dilithium-2 |
| **Public Key Size** | 33 bytes | 1,312 bytes |
| **Signature Size** | ~72 bytes | 2,420 bytes |
| **Address Hash Size** | 20 bytes | 32 bytes |
| **Average TX Size** | ~250 bytes | ~3,850 bytes |
| **Block Size Limit** | 1 MB | 4 MB |
| **Block Time** | 10 minutes | 10 minutes |
| **Difficulty Adjustment** | 2,016 blocks | 2,016 blocks |
| **Total Supply** | 21M BTC | 21M DILI |
| **Mining Algorithm** | SHA-256 | SHA-256 |
| **Quantum Resistant** | ❌ No | ✅ Yes |

---

## Appendix B: Test Vectors

### B.1 Dilithium Test Vector

```
// From NIST test vectors
seed: 0x00...00 (32 bytes of zeros)

public_key: 0x8e7625... (1312 bytes)
secret_key: 0x000000... (2560 bytes)

message: "test message"
signature: 0xc948ef... (2420 bytes)

verification: PASS
```

### B.2 Address Test Vector

```
// Example address generation
public_key (hex): 8e7625...  (1312 bytes)
blake3_hash: a3b2c1d4e5f6...  (32 bytes)
bech32m_address: qb1q5we9c85xfwqp...

// Legacy format
base58check_address: Q1A2B3C4D5E6F7G8H9...
```

---

## Appendix C: Change Log

### Version 0.1.0-draft (October 2025)
- Initial draft specification
- Core cryptographic parameters defined
- Consensus rules specified
- Network protocol outlined

---

**Status:** DRAFT - Subject to change during development
**Next Review:** After proof-of-concept implementation

---

**End of Technical Specification**
