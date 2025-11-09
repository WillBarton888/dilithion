# Dilithion HD Wallet Technical Specification

**Version:** 2.0
**Date:** November 10, 2025
**Authors:** Dilithion Core Development Team
**Status:** Implementation Ready

---

## Executive Summary

This specification defines Hierarchical Deterministic (HD) wallet functionality for Dilithion cryptocurrency, adapting BIP32/BIP39/BIP44 standards for post-quantum CRYSTALS-Dilithium signatures. Unlike ECDSA-based HD wallets that use elliptic curve mathematics for key derivation, this implementation uses a KDF-based approach suitable for lattice-based cryptography.

**Key Innovation:** Deterministic Dilithium key generation from derived seeds using HMAC-SHA3-512 for quantum-resistant key derivation.

---

## 1. Cryptographic Primitives

### 1.1 Hash Functions

All hash functions use SHA-3 (Keccak) family for quantum resistance:

- **SHA3-256**: Address generation, checksums, fingerprints
- **SHA3-512**: Not used directly (HMAC-SHA3-512 used instead)
- **SHAKE-256**: Dilithium internal key expansion

### 1.2 Key Derivation Functions

- **PBKDF2-SHA3-512**: Mnemonic → seed conversion (BIP39)
  - Iterations: 2048 (BIP39 standard)
  - Output: 64 bytes

- **HMAC-SHA3-512**: HD key derivation (replaces BIP32 HMAC-SHA512)
  - Input: parent chain code (key), derivation data (message)
  - Output: 64 bytes (32-byte child seed + 32-byte child chain code)

### 1.3 Symmetric Encryption

- **AES-256-CBC**: Wallet encryption (existing implementation)
- **PBKDF2-SHA3-512**: Passphrase → encryption key derivation
  - Iterations: 300,000 (for wallet encryption)
  - Salt: 16 bytes (random)

---

## 2. BIP39 Mnemonic Phrase

### 2.1 Mnemonic Generation

**Algorithm:**

```
GenerateMnemonic(entropy_bits):
    1. Generate random entropy: E = random(entropy_bits / 8) bytes
    2. Calculate checksum: CS = SHA3-256(E)[0:(entropy_bits/32) bits]
    3. Concatenate: ENT = E || CS
    4. Split into 11-bit groups: G = split(ENT, 11)
    5. Map to words: for each g in G: words.append(WORDLIST[g])
    6. Return words
```

**Supported Entropy Levels:**

| Entropy (bits) | Checksum (bits) | Total (bits) | Mnemonic Length |
|----------------|-----------------|--------------|-----------------|
| 128            | 4               | 132          | 12 words        |
| 160            | 5               | 165          | 15 words        |
| 192            | 6               | 198          | 18 words        |
| 224            | 7               | 231          | 21 words        |
| 256            | 8               | 264          | 24 words        |

**Default:** 24 words (256-bit entropy)

### 2.2 Mnemonic Validation

```
ValidateMnemonic(words):
    1. Check word count: len(words) ∈ {12, 15, 18, 21, 24}
    2. Convert words to bits: bits = []
       for word in words:
           index = WORDLIST.index(word)
           if index < 0: return false  // Invalid word
           bits.append(11-bit representation of index)
    3. Split entropy and checksum:
       entropy_bits = (len(words) * 11) * 32/33
       entropy = bits[0:entropy_bits]
       checksum_expected = bits[entropy_bits:]
    4. Calculate actual checksum:
       checksum_actual = SHA3-256(entropy)[0:len(checksum_expected)]
    5. Return checksum_actual == checksum_expected
```

### 2.3 Mnemonic to Seed Conversion

**Algorithm:**

```
MnemonicToSeed(mnemonic_words, passphrase):
    1. Normalize mnemonic: mnemonic_str = join(mnemonic_words, ' ')
    2. Normalize passphrase: passphrase_utf8 = UTF8-NFKD(passphrase)
    3. Create salt: salt = "dilithion-mnemonic" + passphrase_utf8
    4. Derive seed: seed = PBKDF2-SHA3-512(
           password = mnemonic_str,
           salt = salt,
           iterations = 2048,
           dkLen = 64
       )
    5. Return seed (64 bytes)
```

**Dilithion-specific Salt:**
- Prefix: `"dilithion-mnemonic"` (instead of BIP39's `"mnemonic"`)
- Rationale: Prevents accidental cross-chain usage of same mnemonic
- Ensures Dilithion seeds are incompatible with Bitcoin/Ethereum mnemonics

### 2.4 BIP39 Wordlist

- **Language:** English (2048 words)
- **Source:** BIP39 standard wordlist (unmodified)
- **Properties:**
  - Each word uniquely identified by first 4 letters
  - No similar-looking words (e.g., "build" vs "built")
  - Levenshtein distance > 1 for error detection

---

## 3. HD Key Derivation

### 3.1 Extended Key Structure

An **extended key** contains all information needed to derive child keys:

```cpp
struct CHDExtendedKey {
    uint8_t seed[32];           // Seed for Dilithium key generation
    uint8_t chaincode[32];      // Entropy for child derivation
    uint32_t fingerprint;       // First 4 bytes of SHA3-256(parent_pubkey)[0:20]
    uint32_t depth;             // Derivation depth (0 = master)
    uint32_t child_index;       // Index of this key in parent
    CHDKeyPath path;            // Full derivation path
};
```

**Security Properties:**
- `seed`: Cannot be recovered from public key (lattice hardness)
- `chaincode`: Provides additional entropy for child derivation
- `fingerprint`: Allows quick parent verification without exposing keys

### 3.2 Master Key Derivation

**Input:** 64-byte seed from BIP39 mnemonic
**Output:** Master extended key

**Algorithm:**

```
DeriveMaster(seed_64bytes):
    1. Compute HMAC: I = HMAC-SHA3-512(key="Dilithion seed", data=seed_64bytes)
    2. Split result:
       IL = I[0:32]   // Left 32 bytes = master seed
       IR = I[32:64]  // Right 32 bytes = master chain code
    3. Generate master keypair: (pk, sk) = Dilithium3_Keypair_From_Seed(IL)
    4. Calculate fingerprint: fingerprint = SHA3-256(pk)[0:4]
    5. Return CHDExtendedKey{
           seed = IL,
           chaincode = IR,
           fingerprint = fingerprint,
           depth = 0,
           child_index = 0,
           path = "m"
       }
```

**Note:** HMAC key is `"Dilithion seed"` (with capital D), not `"Bitcoin seed"`.

### 3.3 Child Key Derivation (CKD)

**Notation:**
- `CKD(parent, i)` = derive child at index `i` from `parent`
- `i < 2³¹`: Normal (non-hardened) derivation
- `i ≥ 2³¹`: Hardened derivation

**Algorithm:**

```
DeriveChild(parent_extended_key, child_index):
    1. Determine derivation type:
       hardened = (child_index >= 0x80000000)

    2. Prepare HMAC data:
       if hardened:
           // Hardened: Use parent seed (private)
           data = 0x00 || parent.seed || BE32(child_index)
       else:
           // Normal: Use parent pubkey hash (public)
           parent_pk = Dilithium3_Keypair_From_Seed(parent.seed).pubkey
           pk_hash = SHA3-256(parent_pk)[0:20]
           data = pk_hash || BE32(child_index)

    3. Compute HMAC:
       I = HMAC-SHA3-512(key=parent.chaincode, data=data)

    4. Split result:
       IL = I[0:32]   // Child seed
       IR = I[32:64]  // Child chain code

    5. Generate child keypair:
       (child_pk, child_sk) = Dilithium3_Keypair_From_Seed(IL)

    6. Calculate child fingerprint:
       child_fingerprint = SHA3-256(child_pk)[0:4]

    7. Update path:
       if hardened:
           child_path = parent.path + "/" + (child_index - 0x80000000) + "'"
       else:
           child_path = parent.path + "/" + child_index

    8. Return CHDExtendedKey{
           seed = IL,
           chaincode = IR,
           fingerprint = child_fingerprint,
           depth = parent.depth + 1,
           child_index = child_index,
           path = child_path
       }
```

**Where:**
- `BE32(x)` = Big-endian 32-bit integer encoding
- `||` = Byte concatenation
- `0x00` = Single zero byte (private key marker)

### 3.4 Path Derivation

**BIP44 Path Format:**

```
m / purpose' / coin_type' / account' / change / address_index

Example: m/44'/573'/0'/0/0
```

**Components:**

| Level | Name          | Hardened | Range              | Description                  |
|-------|---------------|----------|--------------------|------------------------------|
| 1     | purpose       | Yes (')  | 44'                | BIP44 purpose                |
| 2     | coin_type     | Yes (')  | 573'               | Dilithion (registered)       |
| 3     | account       | Yes (')  | 0' to 2³¹-1'       | Account index                |
| 4     | change        | No       | 0 or 1             | 0=external, 1=internal       |
| 5     | address_index | No       | 0 to 2³¹-1         | Address index in chain       |

**Standard Paths:**
- Receiving addresses: `m/44'/573'/0'/0/i` (i = 0, 1, 2, ...)
- Change addresses: `m/44'/573'/0'/1/i` (i = 0, 1, 2, ...)
- Account 1 addresses: `m/44'/573'/1'/0/i`

**Hardened vs Normal Derivation:**

| Type     | Notation | Advantages                           | Disadvantages                |
|----------|----------|--------------------------------------|------------------------------|
| Hardened | i'       | Parent key cannot be derived from child | Requires private key         |
| Normal   | i        | Can derive child pubkeys from parent pubkey | Less secure (theoretical)    |

**Dilithion Choice:**
- Levels 1-3: Always hardened (standard for BIP44)
- Levels 4-5: Normal (allows watch-only wallets in future)

---

## 4. Deterministic Dilithium Key Generation

### 4.1 Challenge

CRYSTALS-Dilithium key generation (`pqcrystals_dilithium3_ref_keypair()`) uses system randomness. For HD wallets, we need deterministic generation from a seed.

### 4.2 Solution: Seeded Key Generation

**Approach:** Modify Dilithium reference implementation to accept external seed.

**New Function Signature:**

```c
int pqcrystals_dilithium3_ref_keypair_from_seed(
    uint8_t *pk,        // Output: public key (1952 bytes)
    uint8_t *sk,        // Output: secret key (4032 bytes)
    const uint8_t *seed // Input: 32-byte seed
);
```

**Implementation Strategy:**

```c
keypair_from_seed(pk, sk, seed):
    1. Expand 32-byte seed to required internal seeds using SHAKE-256:
       seedbuf = SHAKE-256(seed, output_len=3*SEEDBYTES + 2*CRHBYTES)

    2. Extract internal seeds:
       rho       = seedbuf[0:32]               // Public seed
       rhoprime  = seedbuf[32:96]              // Private seed
       key       = seedbuf[96:128]             // Signing key seed

    3. Expand matrix from rho (deterministic)

    4. Sample s1, s2 from rhoprime (deterministic)

    5. Compute public key: t = A*s1 + s2

    6. Pack keys into pk and sk

    7. Return 0 (success)
```

**Key Properties:**
- Same seed → same keypair (deterministic)
- Different seeds → independent keypairs (pseudo-random)
- No change to Dilithium security (seeds have 256-bit entropy)
- Keypairs indistinguishable from randomly generated

### 4.3 Security Analysis

**Question:** Does deterministic generation weaken Dilithium security?

**Answer:** No, for the following reasons:

1. **Entropy Sufficient:** 32-byte seed provides 256 bits of entropy, matching or exceeding Dilithium3 security level (128-bit classical, 256-bit quantum).

2. **Standard Practice:** Dilithium NIST specification allows deterministic generation for reproducible testing.

3. **Isolation:** Each derived key uses independent seed from HMAC-SHA3-512, preventing correlation.

4. **No Key Reuse:** HD derivation ensures each address gets unique seed.

**Verification:** Reference Dilithium implementation already uses deterministic generation internally (seeded PRNG). We're just exposing the seed parameter.

---

## 5. Wallet File Format v2

### 5.1 File Structure

```
┌─────────────────────────────────────────────────────┐
│ Header (48 bytes)                                   │
├─────────────────────────────────────────────────────┤
│ HD Wallet Metadata (variable, if HD enabled)        │
├─────────────────────────────────────────────────────┤
│ Legacy Keys (variable, backward compatibility)      │
├─────────────────────────────────────────────────────┤
│ Transactions (variable)                             │
└─────────────────────────────────────────────────────┘
```

### 5.2 Header Format

```
Offset  Size  Field           Description
------  ----  -------------   ---------------------------
0       8     Magic           "DILWLT02" (version 2)
8       4     Version         0x00000002 (little-endian)
12      4     Flags           Bit 0: encrypted
                              Bit 1: HD wallet
                              Bit 2-31: reserved
16      32    Reserved        Future use (zero-filled)
```

### 5.3 HD Wallet Metadata (if flags.bit1 = 1)

```
Offset  Size      Field                    Description
------  --------  -----------------------  ---------------------------
0       4         EncryptedSeedLen         Length of encrypted seed
4       N         EncryptedMasterSeed      AES-256-CBC encrypted seed (64 bytes plaintext)
4+N     16        SeedIV                   AES IV for seed encryption
20+N    32        MasterChainCode          Chain code (unencrypted)
52+N    4         SeedFingerprint          Fingerprint for verification
56+N    4         BIP39ChecksumLen         Mnemonic checksum length
60+N    32        BIP39Checksum            SHA3-256(mnemonic_words)
92+N    4         AccountIndex             Current account index
96+N    4         ExternalChainIndex       Next external address index
100+N   4         InternalChainIndex       Next internal address index
104+N   4         NumDerivedKeys           Count of derived addresses

For each derived key (NumDerivedKeys times):
  Offset  Size  Field           Description
  ------  ----  -------------   ---------------------------
  0       1     PathLength      Number of levels in path (typically 5)
  1       4*L   Path            Derivation indices (PathLength * 4 bytes)
  1+4L    21    AddressData     Address (version + hash)
  22+4L   1952  PublicKey       Dilithium public key
```

**Encryption:**
- `EncryptedMasterSeed`: Encrypted with wallet master key (from passphrase)
- `MasterChainCode`: NOT encrypted (needed for watch-only wallets in future)
- `BIP39Checksum`: Allows mnemonic validation without decryption

**Storage Optimization:**
- Private keys NOT stored (derived on-demand from seed)
- Public keys cached for performance (address generation)
- Reduces wallet file size vs storing full keypairs

### 5.4 Backward Compatibility

**Loading Logic:**

```
LoadWallet(filename):
    1. Read magic bytes
    2. If magic == "DILWLT01":
          Load as legacy wallet (version 1)
          Return legacy wallet object
    3. If magic == "DILWLT02":
          Load as version 2 wallet
          Check flags.bit1:
            If set: Initialize HD wallet components
            If not set: Initialize as legacy wallet with v2 format
          Load legacy keys if present (mixed wallet)
    4. Else:
          Error: Unknown wallet format
```

**Version 1 → Version 2 Migration:**

Users can upgrade via `upgradetohdwallet` RPC command:
- Generates new HD seed
- Preserves existing legacy keys (if keep_legacy=true)
- Saves as version 2 format
- Returns mnemonic for backup

---

## 6. Address Gap Limit (BIP44)

### 6.1 Concept

**Problem:** How many addresses to scan when recovering wallet from seed?

**Solution:** Gap limit = maximum number of consecutive unused addresses before stopping scan.

### 6.2 Dilithion Implementation

**Gap Limit:** 20 addresses (BIP44 standard)

**Recovery Algorithm:**

```
ScanHDChain(utxo_set, chain_type, account_index):
    gap = 0
    index = 0
    found_addresses = []

    while gap < 20:
        // Derive address at path m/44'/573'/account_index'/chain_type/index
        path = BuildPath(44', 573', account_index', chain_type, index)
        address = DeriveAddress(path)

        // Check if address has any UTXOs
        has_utxos = utxo_set.HasUTXOsForAddress(address)

        if has_utxos:
            found_addresses.append(address)
            gap = 0  // Reset gap counter
        else:
            gap += 1  // Increment gap

        index += 1

    return found_addresses
```

**Implications:**
- Maximum 20 unused addresses between used addresses
- Wallet scans up to 20 addresses ahead of last used
- If user generates >20 addresses without using any, some may not be recovered

**User Guidance:**
- Use addresses in order (sequential)
- Don't skip ahead >20 addresses
- Wallet UI should enforce sequential generation

---

## 7. Security Considerations

### 7.1 Threat Model

**Assumptions:**
- Adversary has access to wallet file (encrypted)
- Adversary may have access to public keys and addresses
- Adversary does NOT have wallet passphrase or mnemonic

**Goals:**
- Protect mnemonic and private keys
- Prevent key derivation from public information
- Ensure forward secrecy (child keys don't reveal parent)

### 7.2 Key Security Properties

| Property                  | Mechanism                   | Protection Level      |
|---------------------------|-----------------------------|-----------------------|
| Mnemonic entropy          | 256-bit random              | 2²⁵⁶ brute force     |
| Mnemonic → seed KDF       | PBKDF2-SHA3 (2048 rounds)   | Slow dictionary       |
| Seed encryption           | AES-256-CBC                 | 2²⁵⁶ key space       |
| Wallet encryption         | PBKDF2 (300k rounds)        | Very slow brute force|
| HD derivation             | HMAC-SHA3-512               | Quantum-resistant     |
| Hardened derivation       | Uses private seed           | No pubkey→privkey    |
| Memory wiping             | Explicit cleanse            | No RAM dumps          |

### 7.3 Attack Resistance

**Attack: Derive parent from child key**
- Hardened derivation: ✅ Impossible (requires parent private seed)
- Normal derivation: ✅ Computationally infeasible (HMAC one-way)

**Attack: Derive sibling keys from one child**
- Protection: Each child uses independent HMAC output
- Result: ✅ Secure (no cross-child correlation)

**Attack: Brute-force mnemonic**
- 12 words: 2¹²⁸ entropy + checksum validation = infeasible
- 24 words: 2²⁵⁶ entropy = quantum-secure

**Attack: Weak passphrase**
- Mitigation: Passphrase strength validation enforced
- Requirement: Minimum 12 characters, complexity rules

**Attack: Quantum computer breaks Dilithium**
- Impact: Only affects signatures, not HD derivation
- Recovery: Upgrade to new post-quantum scheme, derive from same seed

### 7.4 Best Practices

**For Users:**
1. Write mnemonic on paper (never digital)
2. Store mnemonic in secure location (fire-proof safe)
3. Use strong wallet passphrase (different from mnemonic passphrase)
4. Test recovery on testnet before mainnet
5. Verify first address matches after recovery

**For Developers:**
1. Wipe all sensitive data from memory after use
2. Never log mnemonic or seeds
3. Encrypt HD seed with wallet master key
4. Validate all derivation inputs (bounds checking)
5. Use constant-time comparisons for checksums

---

## 8. Test Vectors

### 8.1 BIP39 Test Cases

**Test Vector 1: 12-word mnemonic**

```
Entropy (hex):
  00000000000000000000000000000000

Mnemonic:
  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

Seed (hex):
  (Computed with PBKDF2-SHA3-512, salt="dilithion-mnemonic", iterations=2048)
  [64 bytes - to be computed during implementation]

Master fingerprint:
  [4 bytes - to be computed]
```

**Test Vector 2: 24-word mnemonic**

```
Entropy (hex):
  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

Mnemonic:
  zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote

Seed (hex):
  [64 bytes - to be computed during implementation]

Master fingerprint:
  [4 bytes - to be computed]
```

### 8.2 HD Derivation Test Cases

**Test Vector 3: Master key derivation**

```
Input seed (from test vector 2):
  [64 bytes from mnemonic "zoo zoo...vote"]

Master extended key:
  seed: [32 bytes - IL from HMAC]
  chaincode: [32 bytes - IR from HMAC]
  fingerprint: [4 bytes]
  path: m

Master public key:
  [1952 bytes - Dilithium3 public key from seed]
```

**Test Vector 4: Child derivation**

```
Parent: Master key from test vector 3
Child index: 44' (0x8000002C - hardened)

Child extended key:
  seed: [32 bytes]
  chaincode: [32 bytes]
  fingerprint: [4 bytes]
  path: m/44'

Verification: Re-deriving with same parent and index must produce identical child
```

**Test Vector 5: Full BIP44 path**

```
Path: m/44'/573'/0'/0/0 (first receiving address)

Extended key at each level:
  m:               [master key]
  m/44':           [purpose]
  m/44'/573':      [coin type]
  m/44'/573'/0':   [account]
  m/44'/573'/0'/0: [external chain]
  m/44'/573'/0'/0/0: [first address]

Final address:
  Public key: [1952 bytes]
  Address: D1... (Base58Check encoded)

Verification: Same mnemonic + path → same address (determinism test)
```

### 8.3 Wallet File Test Cases

**Test Vector 6: Save and load HD wallet**

```
Setup:
  1. Create HD wallet from test vector 2 mnemonic
  2. Derive 10 addresses (m/44'/573'/0'/0/0 to m/44'/573'/0'/0/9)
  3. Generate 5 change addresses (m/44'/573'/0'/1/0 to m/44'/573'/0'/1/4)
  4. Encrypt wallet with passphrase "test-password-123"
  5. Save to file: test_hd_wallet.dat

Verification:
  1. Load from file: test_hd_wallet.dat
  2. Unlock with passphrase "test-password-123"
  3. Derive same 10 receiving addresses
  4. Verify public keys match exactly
  5. Verify fingerprint matches
```

---

## 9. Implementation Checklist

### 9.1 Phase 0: Design ✅
- [x] Cryptographic specification documented
- [x] File format designed
- [x] API interfaces specified
- [x] Test vectors defined

### 9.2 Phase 1: BIP39 Mnemonic
- [ ] Implement wordlist (2048 words)
- [ ] Implement mnemonic generation
- [ ] Implement mnemonic validation
- [ ] Implement mnemonic → seed conversion
- [ ] Unit tests (20+ cases)

### 9.3 Phase 2: HD Derivation
- [ ] Implement deterministic Dilithium keygen
- [ ] Implement master key derivation
- [ ] Implement child key derivation (hardened + normal)
- [ ] Implement path parsing and derivation
- [ ] Unit tests (30+ cases)

### 9.4 Phase 3: Wallet Integration
- [ ] Add HD members to CWallet class
- [ ] Implement HD wallet initialization
- [ ] Implement address generation (receiving + change)
- [ ] Implement gap limit scanning
- [ ] Implement wallet file v2 save/load
- [ ] Integration tests (40+ cases)

### 9.5 Phase 4: RPC Interface
- [ ] Implement createhdwallet
- [ ] Implement restorehdwallet
- [ ] Implement dumpmnemonic
- [ ] Implement gethdwalletinfo
- [ ] Implement derivehd
- [ ] RPC tests (20+ cases)

### 9.6 Phase 5: Testing & Documentation
- [ ] Comprehensive test suite (200+ tests)
- [ ] Security audit
- [ ] User guide documentation
- [ ] Migration guide
- [ ] Performance testing
- [ ] Fuzzing campaign (24 hours)

---

## 10. References

1. **BIP32**: Hierarchical Deterministic Wallets
   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

2. **BIP39**: Mnemonic code for generating deterministic keys
   https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

3. **BIP44**: Multi-Account Hierarchy for Deterministic Wallets
   https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

4. **CRYSTALS-Dilithium**: Post-Quantum Digital Signature Algorithm
   https://pq-crystals.org/dilithium/

5. **NIST PQC Standardization**
   https://csrc.nist.gov/projects/post-quantum-cryptography

6. **SHA-3 Standard (FIPS 202)**
   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

7. **SLIP-0044**: Registered coin types for BIP44
   https://github.com/satoshilabs/slips/blob/master/slip-0044.md

---

## Appendix A: Dilithion Coin Type Registration

**Coin Type:** 573 (0x0000023D)
**Symbol:** DLT
**Derivation Path:** m/44'/573'/account'/change/index

**Registration Status:** Pending registration with SLIP-0044
**Alternative:** Use 1' (testnet) until official registration

---

## Appendix B: Glossary

- **BIP**: Bitcoin Improvement Proposal
- **HD Wallet**: Hierarchical Deterministic Wallet
- **KDF**: Key Derivation Function
- **HMAC**: Hash-based Message Authentication Code
- **Extended Key**: Key + chain code for HD derivation
- **Chain Code**: Additional entropy for child key derivation
- **Hardened Derivation**: Child key derivation using parent private key
- **Gap Limit**: Maximum consecutive unused addresses before stopping scan
- **Mnemonic**: Human-readable backup phrase (12-24 words)

---

**End of Specification**

**Version:** 2.0
**Last Updated:** November 10, 2025
**Next Review:** Post-implementation security audit
