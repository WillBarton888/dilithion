# DFMP v2.0 Specification

**Status:** DRAFT - Pending Implementation
**Version:** 2.0
**Date:** January 2026

---

## 1. Overview

DFMP v2.0 introduces the **Mining Identity Key (MIK)** - a persistent cryptographic identity separate from payout addresses. This solves the address rotation loophole present in v1.4.

### 1.1 Problem Statement

In DFMP v1.4, miner identity is derived from the coinbase payout address:
```
Identity = SHA3-256(coinbase.vout[0].scriptPubKey)[:20 bytes]
```

This creates a loophole: miners can rotate payout addresses to always appear as "new" identities, perpetually receiving first-block grace (1.0x difficulty) and bypassing DFMP entirely.

### 1.2 Solution

Introduce a mandatory **Mining Identity Key (MIK)** that:
- Is separate from payout addresses
- Must be included in every block (signed commitment)
- Persists across address rotations
- Starts with a maturity penalty (no first-block grace)

---

## 2. Mining Identity Key (MIK)

### 2.1 Definition

A MIK is a dedicated Dilithium3 keypair used solely for mining identity:

```
MIK = {
    privateKey: Dilithium3 private key (4,032 bytes)
    publicKey:  Dilithium3 public key (1,952 bytes)
    identity:   SHA3-256(publicKey)[:20 bytes]
}
```

### 2.2 Key Properties

| Property | Value |
|----------|-------|
| Algorithm | CRYSTALS-Dilithium3 (NIST FIPS 204) |
| Private key size | 4,032 bytes |
| Public key size | 1,952 bytes |
| Identity hash size | 20 bytes |
| Signature size | 3,309 bytes |

### 2.3 Identity Derivation

```cpp
// Identity is first 20 bytes of SHA3-256 hash of public key
Identity DeriveIdentity(const std::vector<uint8_t>& publicKey) {
    std::vector<uint8_t> hash = SHA3_256(publicKey);
    Identity id;
    std::copy(hash.begin(), hash.begin() + 20, id.data);
    return id;
}
```

---

## 3. Block Structure

### 3.1 Coinbase Transaction Format

```
vout[0]: Block reward payment (any address, can rotate freely)
vout[1]: OP_RETURN <MIK data>
```

### 3.2 MIK Data Format

**First block from a new MIK (registration):**
```
OP_RETURN [1952 bytes: MIK public key] [3309 bytes: signature]
Total: 5,261 bytes
```

**Subsequent blocks from known MIK:**
```
OP_RETURN [20 bytes: MIK identity hash] [3309 bytes: signature]
Total: 3,329 bytes
```

### 3.3 Signature Content

The MIK signs a commitment to the block:

```cpp
// Message to sign
std::vector<uint8_t> BuildSignatureMessage(
    const uint256& blockHeaderHash,
    const uint256& coinbaseTxid,
    const Identity& mikIdentity
) {
    std::vector<uint8_t> message;
    message.insert(message.end(), blockHeaderHash.begin(), blockHeaderHash.end());
    message.insert(message.end(), coinbaseTxid.begin(), coinbaseTxid.end());
    message.insert(message.end(), mikIdentity.data, mikIdentity.data + 20);
    return SHA3_256(message);
}
```

### 3.4 OP_RETURN Detection

```cpp
bool IsMIKRegistration(const std::vector<uint8_t>& opReturnData) {
    return opReturnData.size() == 5261;  // pubkey(1952) + sig(3309)
}

bool IsMIKReference(const std::vector<uint8_t>& opReturnData) {
    return opReturnData.size() == 3329;  // identity(20) + sig(3309)
}
```

---

## 4. Validation Rules

### 4.1 Block Validation

Every valid block MUST:

1. Have at least 2 coinbase outputs
2. Have vout[1] as OP_RETURN with valid MIK data
3. Contain a valid Dilithium3 signature
4. Meet DFMP-adjusted difficulty target

### 4.2 MIK Signature Validation

```cpp
bool ValidateMIKSignature(const CBlock& block, int height) {
    // 1. Extract OP_RETURN data from coinbase vout[1]
    auto opReturnData = ExtractOPReturn(block.vtx[0], 1);
    if (opReturnData.empty()) {
        return false;  // Missing MIK data
    }

    // 2. Determine if registration or reference
    std::vector<uint8_t> publicKey;
    Identity identity;
    std::vector<uint8_t> signature;

    if (IsMIKRegistration(opReturnData)) {
        // New MIK - extract pubkey and derive identity
        publicKey.assign(opReturnData.begin(), opReturnData.begin() + 1952);
        signature.assign(opReturnData.begin() + 1952, opReturnData.end());
        identity = DeriveIdentity(publicKey);

        // Store pubkey for future reference
        if (!g_mikDb->Exists(identity)) {
            g_mikDb->StorePubkey(identity, publicKey, height);
        }
    } else if (IsMIKReference(opReturnData)) {
        // Known MIK - lookup pubkey
        std::copy(opReturnData.begin(), opReturnData.begin() + 20, identity.data);
        signature.assign(opReturnData.begin() + 20, opReturnData.end());

        if (!g_mikDb->Exists(identity)) {
            return false;  // Unknown MIK, should have registered
        }
        publicKey = g_mikDb->GetPubkey(identity);
    } else {
        return false;  // Invalid OP_RETURN size
    }

    // 3. Build message and verify signature
    auto message = BuildSignatureMessage(
        block.GetHash(),
        block.vtx[0].GetHash(),
        identity
    );

    return Dilithium3_Verify(publicKey, message, signature);
}
```

### 4.3 DFMP Difficulty Validation

```cpp
bool ValidateDFMPDifficulty(const CBlock& block, int height) {
    // 1. Extract MIK identity
    Identity identity = ExtractMIKIdentity(block);

    // 2. Get MIK record (or create placeholder for new MIK)
    MIKRecord record = g_mikDb->GetOrCreateRecord(identity, height);

    // 3. Calculate maturity penalty
    double maturityPenalty = CalculateMaturityPenalty(height, record.firstSeenHeight);

    // 4. Calculate heat penalty
    int heat = g_heatTracker->GetHeat(identity);
    double heatPenalty = CalculateHeatPenalty(heat);

    // 5. Calculate total multiplier
    double totalMultiplier = maturityPenalty * heatPenalty;

    // 6. Calculate effective target
    uint256 baseTarget = GetBaseTarget(block.nBits);
    uint256 effectiveTarget = baseTarget / totalMultiplier;

    // 7. Verify block meets target
    return block.GetHash() <= effectiveTarget;
}
```

---

## 5. Maturity Penalty

### 5.1 Penalty Schedule (No First-Block Grace)

New MIKs start at 3.0x penalty with step-wise decay:

| MIK Age (blocks) | Maturity Penalty |
|------------------|------------------|
| 0-99 | 3.0x |
| 100-199 | 2.5x |
| 200-299 | 2.0x |
| 300-399 | 1.5x |
| 400+ | 1.0x |

### 5.2 Implementation

```cpp
double CalculateMaturityPenalty(int currentHeight, int firstSeenHeight) {
    // New MIK (not yet in database)
    if (firstSeenHeight < 0) {
        return 3.0;
    }

    int mikAge = currentHeight - firstSeenHeight;

    if (mikAge < 100) return 3.0;
    if (mikAge < 200) return 2.5;
    if (mikAge < 300) return 2.0;
    if (mikAge < 400) return 1.5;
    return 1.0;
}
```

### 5.3 Fixed-Point Implementation

For consensus-critical determinism:

```cpp
// Scale factor for fixed-point arithmetic
constexpr int64_t FP_SCALE = 1000000;

int64_t CalculateMaturityPenaltyFP(int currentHeight, int firstSeenHeight) {
    if (firstSeenHeight < 0) {
        return 3000000;  // 3.0 × FP_SCALE
    }

    int mikAge = currentHeight - firstSeenHeight;

    if (mikAge < 100) return 3000000;  // 3.0x
    if (mikAge < 200) return 2500000;  // 2.5x
    if (mikAge < 300) return 2000000;  // 2.0x
    if (mikAge < 400) return 1500000;  // 1.5x
    return 1000000;                     // 1.0x
}
```

---

## 6. Heat Penalty (Unchanged from v1.4)

### 6.1 Parameters

```cpp
constexpr int OBSERVATION_WINDOW = 100;
constexpr int FREE_TIER_THRESHOLD = 14;
constexpr double HEAT_COEFFICIENT = 0.046;
```

### 6.2 Formula

```
effective_heat = max(0, blocks_in_window - FREE_TIER_THRESHOLD)
heat_penalty = 1.0 + HEAT_COEFFICIENT × effective_heat²
```

### 6.3 Heat Penalty Table

| Blocks in Last 100 | Effective Heat | Heat Penalty |
|--------------------|----------------|--------------|
| 0-14 | 0 | 1.0x |
| 15 | 1 | 1.05x |
| 20 | 6 | 2.66x |
| 25 | 11 | 6.57x |
| 30 | 16 | 12.78x |
| 40 | 26 | 32.10x |
| 50 | 36 | 60.62x |

---

## 7. MIK Database

### 7.1 Record Structure

```cpp
struct MIKRecord {
    Identity identity;              // 20 bytes - primary key
    std::vector<uint8_t> publicKey; // 1,952 bytes - for signature verification
    int firstSeenHeight;            // Block height when MIK first appeared
    int lastMinedHeight;            // Most recent block mined
    int totalBlocksMined;           // Lifetime block count (for future reputation)
};
```

### 7.2 Database Operations

```cpp
class CMIKDatabase {
public:
    // Check if MIK exists
    bool Exists(const Identity& id) const;

    // Get full record
    std::optional<MIKRecord> GetRecord(const Identity& id) const;

    // Get just the public key (for signature verification)
    std::vector<uint8_t> GetPubkey(const Identity& id) const;

    // Store new MIK (on first block)
    bool StorePubkey(const Identity& id, const std::vector<uint8_t>& pubkey, int height);

    // Update on block mined
    void UpdateOnBlockMined(const Identity& id, int height);

    // Handle reorg - decrement block count, update lastMined
    void OnBlockDisconnected(const Identity& id, int height);
};
```

### 7.3 Storage Backend

LevelDB with key-value pairs:
- Key: `mik_` + identity (20 bytes)
- Value: Serialized MIKRecord

---

## 8. Wallet Integration

### 8.1 MIK Generation

```cpp
// Generate new MIK during wallet creation
MIK GenerateMIK() {
    // Generate Dilithium3 keypair
    auto [privateKey, publicKey] = Dilithium3_KeyGen();

    // Derive identity
    Identity identity = DeriveIdentity(publicKey);

    return MIK{privateKey, publicKey, identity};
}
```

### 8.2 Wallet Storage

MIK stored in wallet file, separate from payment keys:

```
wallet.dat structure:
  - version: wallet format version
  - encrypted_master_key: for address keys
  - addresses: [{pubkey, privkey_encrypted}, ...]
  - mik: {
      identity: 20 bytes
      publicKey: 1,952 bytes
      privateKey_encrypted: 4,032 bytes (encrypted with wallet passphrase)
    }
```

### 8.3 Mining Integration

```cpp
// When creating coinbase transaction for mining
CTransaction CreateCoinbaseTx(int height, const CScript& payoutScript) {
    CTransaction tx;

    // vout[0]: Block reward to payout address
    tx.vout.push_back(CTxOut(GetBlockSubsidy(height), payoutScript));

    // vout[1]: MIK commitment
    auto mikData = BuildMIKCommitment(height);
    tx.vout.push_back(CTxOut(0, CScript() << OP_RETURN << mikData));

    return tx;
}

std::vector<uint8_t> BuildMIKCommitment(int height) {
    MIK& mik = g_wallet->GetMIK();

    // Check if this MIK is known to the network
    bool isNewMIK = !g_mikDb->Exists(mik.identity);

    std::vector<uint8_t> data;

    if (isNewMIK) {
        // Include full public key for registration
        data.insert(data.end(), mik.publicKey.begin(), mik.publicKey.end());
    } else {
        // Just include identity hash
        data.insert(data.end(), mik.identity.data, mik.identity.data + 20);
    }

    // Sign commitment
    auto message = BuildSignatureMessage(/* ... */);
    auto signature = Dilithium3_Sign(mik.privateKey, message);
    data.insert(data.end(), signature.begin(), signature.end());

    return data;
}
```

---

## 9. Constants Summary

```cpp
namespace DFMP_V2 {
    // MIK sizes
    constexpr size_t MIK_IDENTITY_SIZE = 20;
    constexpr size_t MIK_PUBKEY_SIZE = 1952;
    constexpr size_t MIK_SIGNATURE_SIZE = 3309;
    constexpr size_t MIK_REGISTRATION_SIZE = 5261;  // pubkey + sig
    constexpr size_t MIK_REFERENCE_SIZE = 3329;     // identity + sig

    // Maturity penalty
    constexpr int MATURITY_STEP_BLOCKS = 100;
    constexpr int MATURITY_TOTAL_BLOCKS = 400;
    constexpr double MATURITY_PENALTY_START = 3.0;
    constexpr double MATURITY_PENALTY_END = 1.0;

    // Fixed-point versions
    constexpr int64_t FP_SCALE = 1000000;
    constexpr int64_t FP_MATURITY_30 = 3000000;  // 3.0x
    constexpr int64_t FP_MATURITY_25 = 2500000;  // 2.5x
    constexpr int64_t FP_MATURITY_20 = 2000000;  // 2.0x
    constexpr int64_t FP_MATURITY_15 = 1500000;  // 1.5x
    constexpr int64_t FP_MATURITY_10 = 1000000;  // 1.0x

    // Heat penalty (unchanged from v1.4)
    constexpr int OBSERVATION_WINDOW = 100;
    constexpr int FREE_TIER_THRESHOLD = 14;
    constexpr int64_t FP_HEAT_COEFF = 46000;  // 0.046 × FP_SCALE
}
```

---

## 10. Migration Notes

### 10.1 Activation

DFMP v2.0 activates from genesis (block 0). There is no migration from v1.4 required since this is for a fresh mainnet launch.

### 10.2 Backward Compatibility

Not applicable - v2.0 is for new chain launch, not upgrade of existing chain.

---

## 11. Security Considerations

### 11.1 MIK Key Security

- MIK private key must be protected like wallet private keys
- Compromise of MIK allows attacker to mine under that identity
- MIK does NOT give access to funds (payout address is separate)

### 11.2 Pre-generation Attack

**Attack:** Generate many MIKs, wait for them to mature, then mine.

**Mitigation:** Maturity is based on network-observed first-seen height, not pre-generation time. MIK only starts maturing when it appears in a valid block.

### 11.3 Identity Collision

**Risk:** Two different public keys producing same 20-byte identity hash.

**Mitigation:** SHA3-256 truncated to 160 bits provides ~2^80 collision resistance, sufficient for this application.

---

## 12. Testing Requirements

Before deployment, the following must be tested:

1. [ ] MIK generation and wallet storage
2. [ ] First block with MIK registration (5,261 byte OP_RETURN)
3. [ ] Subsequent blocks with MIK reference (3,329 byte OP_RETURN)
4. [ ] Signature verification for both registration and reference
5. [ ] Maturity penalty calculation at each step boundary
6. [ ] Heat penalty calculation (unchanged, but verify integration)
7. [ ] Block rejection for missing MIK
8. [ ] Block rejection for invalid MIK signature
9. [ ] Block rejection for unknown MIK without registration
10. [ ] MIK database persistence across node restart
11. [ ] Reorg handling (block disconnection)
12. [ ] Multi-node sync with MIK validation

---

## Appendix A: Changes from v1.4

| Aspect | v1.4 | v2.0 |
|--------|------|------|
| Identity source | Payout address | Mining Identity Key |
| Identity in block | Implicit | Explicit (OP_RETURN) |
| First-block grace | Yes (1.0x) | No (starts at 3.0x) |
| Maturity start | 5.0x | 3.0x |
| Maturity duration | 500 blocks (linear) | 400 blocks (step-wise) |
| Address rotation | Bypasses DFMP | Does not affect DFMP |
| Block size overhead | 0 bytes | 3,329-5,261 bytes |

---

## Appendix B: Revision History

| Version | Date | Changes |
|---------|------|---------|
| 2.0-draft | Jan 2026 | Initial specification |
