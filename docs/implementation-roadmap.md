# Dilithion Implementation Roadmap

Complete technical implementation guide for forking Bitcoin Core into a quantum-resistant cryptocurrency.

---

## Table of Contents

1. [Bitcoin Core Architecture Overview](#bitcoin-core-architecture-overview)
2. [Core Modification Map](#core-modification-map)
3. [File-by-File Modification Checklist](#file-by-file-modification-checklist)
4. [Build System Changes](#build-system-changes)
5. [Testing Strategy](#testing-strategy)
6. [Development Workflow](#development-workflow)

---

## Bitcoin Core Architecture Overview

### Directory Structure

```
bitcoin/
├── src/
│   ├── consensus/        # Consensus rules (TOUCH CAREFULLY)
│   ├── crypto/           # Cryptographic primitives (MAJOR CHANGES)
│   ├── key.cpp/h         # Private key operations (MAJOR CHANGES)
│   ├── pubkey.cpp/h      # Public key operations (MAJOR CHANGES)
│   ├── script/           # Script execution (MODERATE CHANGES)
│   ├── primitives/       # Block/tx structures (MINOR CHANGES)
│   ├── validation.cpp    # Block validation (TOUCH CAREFULLY)
│   ├── net*              # P2P networking (MINIMAL CHANGES)
│   └── wallet/           # Wallet functionality (MODERATE CHANGES)
```

---

## Core Modification Map

### 🔴 CRITICAL: Cryptographic Core (Months 4-6)

These files handle all signature operations. This is where your project lives or dies.

#### 1. `src/key.h` and `src/key.cpp` - Private Keys

**Current (ECDSA):**
```cpp
class CKey {
private:
    secp256k1_context* ctx;  // 32-byte private key
    unsigned char keydata[32];

public:
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig);
    bool SignCompact(const uint256& hash, std::vector<unsigned char>& vchSig);
    CPrivKey GetPrivKey();
};
```

**Your Changes (Dilithium):**
```cpp
class CKey {
private:
    // Dilithium-2 parameters
    unsigned char keydata[2560];  // Dilithium private key size

public:
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig);
    // Remove SignCompact (doesn't make sense for Dilithium)
    CPrivKey GetPrivKey();

    // New Dilithium-specific methods
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig);
};
```

**Modifications Needed:**
- Replace secp256k1 context with Dilithium context
- Change keydata size from 32 to 2,560 bytes
- Reimplement `Sign()` using `pqcrystals_dilithium2_ref_signature()`
- Update serialization/deserialization
- Update key generation from random bytes

**Critical Security Considerations:**
- Ensure constant-time operations (no timing attacks)
- Secure memory wiping on destruction
- Proper random number generation
- Side-channel resistance

#### 2. `src/pubkey.h` and `src/pubkey.cpp` - Public Keys

**Current (ECDSA):**
```cpp
class CPubKey {
private:
    unsigned char vch[65];  // 33 or 65 bytes compressed/uncompressed

public:
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig);
    bool RecoverCompact(const uint256& hash, const std::vector<unsigned char>& vchSig);
    CKeyID GetID() const;  // Returns 20-byte hash
};
```

**Your Changes (Dilithium):**
```cpp
class CPubKey {
private:
    unsigned char vch[1312];  // Dilithium-2 public key size

public:
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig);
    // Remove RecoverCompact (no key recovery in Dilithium)
    CKeyID GetID() const;  // Returns 32-byte hash (need larger)

    // Size is now fixed at 1312 bytes
    unsigned int size() const { return 1312; }
};
```

**Modifications Needed:**
- Change storage from 65 bytes to 1,312 bytes
- Reimplement `Verify()` using `pqcrystals_dilithium2_ref_verify()`
- Remove key recovery (doesn't exist in Dilithium)
- Update `GetID()` to use 32-byte hash instead of 20-byte

**Implications:**
- Addresses will be longer (32 bytes vs 20 bytes)
- Transactions will be larger
- Need new address format

#### 3. `src/crypto/` directory - Add Dilithium

**New Files to Create:**
```
src/crypto/dilithium/
├── dilithium.h          # Your wrapper around pqcrystals
├── dilithium.cpp        # Implementation
├── params.h             # Dilithium-2 parameters
└── test/                # Unit tests
```

**Integration Approach:**
```cpp
// src/crypto/dilithium/dilithium.h
#include "pqcrystals/dilithium2/api.h"

class DilithiumContext {
public:
    static const size_t PUBLIC_KEY_SIZE = 1312;
    static const size_t SECRET_KEY_SIZE = 2560;
    static const size_t SIGNATURE_SIZE = 2420;

    static bool GenerateKeyPair(unsigned char* pk, unsigned char* sk);
    static bool Sign(unsigned char* sig, size_t* siglen,
                     const unsigned char* msg, size_t msglen,
                     const unsigned char* sk);
    static bool Verify(const unsigned char* sig, size_t siglen,
                       const unsigned char* msg, size_t msglen,
                       const unsigned char* pk);
};
```

**What to Vendor In:**
- Official CRYSTALS-Dilithium reference implementation
- Or: Use liboqs (Open Quantum Safe) library
- Preference: Official reference (simpler, more auditable)

**Dependencies:**
```bash
# Add to depends/ directory
git submodule add https://github.com/pq-crystals/dilithium.git depends/dilithium

# Or use liboqs
git submodule add https://github.com/open-quantum-safe/liboqs.git depends/liboqs
```

---

### 🟡 IMPORTANT: Data Structures (Months 5-7)

#### 4. `src/primitives/transaction.h` - Transaction Structure

**Current:**
```cpp
class CTransaction {
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    // ...
};

class CTxIn {
    COutPoint prevout;
    CScript scriptSig;      // Contains ECDSA signature (72 bytes)
    uint32_t nSequence;
};
```

**Your Changes:**
```cpp
// Same structure, but scriptSig now contains:
// - Dilithium signature: 2,420 bytes (vs ECDSA's 72 bytes)
// - This is a 33x increase in size

class CTxIn {
    COutPoint prevout;
    CScript scriptSig;      // Now ~2,420 bytes per input
    uint32_t nSequence;
};
```

**Implications:**
- Average transaction size: ~400 bytes → ~10 KB (25x increase)
- Block with 2,000 txs: ~0.8 MB → ~20 MB
- Need to adjust block size limit

**Block Size Decision:**
```cpp
// src/consensus/consensus.h
// Current Bitcoin
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 1000000;  // 1 MB

// Your chain (to maintain similar tx throughput)
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;  // 4 MB
```

#### 5. `src/script/interpreter.cpp` - Script Validation

**Current Signature Validation:**
```cpp
bool CheckSig(const std::vector<unsigned char>& vchSig,
              const std::vector<unsigned char>& vchPubKey,
              const CScript& scriptCode,
              const CTransaction& txTo,
              unsigned int nIn, int nHashType, int flags) {

    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);

    if (!pubkey.Verify(sighash, vchSig))  // ECDSA verification
        return false;

    return true;
}
```

**Your Changes:**
```cpp
bool CheckSig(const std::vector<unsigned char>& vchSig,
              const std::vector<unsigned char>& vchPubKey,
              const CScript& scriptCode,
              const CTransaction& txTo,
              unsigned int nIn, int nHashType, int flags) {

    // Public key is now 1,312 bytes instead of 33
    if (vchPubKey.size() != 1312)
        return false;

    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    // Signature is now 2,420 bytes instead of ~72
    if (vchSig.size() != 2420)
        return false;

    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);

    if (!pubkey.Verify(sighash, vchSig))  // Dilithium verification
        return false;

    return true;
}
```

**Files to Modify:**
- `src/script/interpreter.cpp` - Main validation logic
- `src/script/sign.cpp` - Signature creation
- `src/script/standard.cpp` - Standard script templates

#### 6. Address Format - Multiple Files

**Current Bitcoin Addresses:**
```cpp
// 20-byte hash of public key
CKeyID = uint160 (RIPEMD160(SHA256(pubkey)))

// Base58Check encoding
// Example: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

**Your New Addresses:**
```cpp
// 32-byte hash of public key (need more space)
CKeyID = uint256 (BLAKE3(pubkey))

// Bech32m encoding (like Bitcoin's native SegWit)
// Example: qb1qxyz...abc (your prefix + 32 bytes)
```

**Files to Modify:**
- `src/base58.cpp` - Address encoding (or switch to Bech32m)
- `src/key_io.cpp` - Key/address parsing
- `src/outputtype.cpp` - Address type handling
- `src/chainparams.cpp` - Network prefixes

**New Address Prefix:**
```cpp
// src/chainparams.cpp
base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);  // 'Q' prefix
base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,65);  // 'R' prefix

// Or use Bech32m (recommended)
bech32_hrp = "qb";  // quantum-bitcoin
```

---

### 🟢 MODERATE: Consensus & Validation (Months 7-9)

#### 7. `src/consensus/` - Consensus Rules

**Files that Reference Signature Sizes:**
```cpp
// src/consensus/consensus.h
static const unsigned int MAX_PUBKEYS_PER_MULTISIG = 20;  // May need adjustment

// src/consensus/tx_verify.cpp
// Weight calculations need updates
```

**What Changes:**
- `MAX_BLOCK_WEIGHT` needs recalculation
- Transaction weight formula (signatures are heavier)
- Maximum transaction size limits

**What Stays the Same:**
- Block time (10 minutes)
- Difficulty adjustment (2,016 blocks)
- Halving schedule (210,000 blocks)
- Total supply (21 million)
- Mining algorithm (SHA-256)

#### 8. `src/validation.cpp` - Block Validation

**This is consensus-critical. Change CAREFULLY.**

**What You're Modifying:**
```cpp
bool CheckBlock(const CBlock& block, CValidationState& state,
                const Consensus::Params& consensusParams, bool fCheckPOW) {

    // Check block size
    if (block.vtx.empty() ||
        block.vtx.size() > MAX_BLOCK_SIZE ||  // Need to update this
        ::GetSerializeSize(block, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                            "bad-blk-length");

    // ... rest of validation
}
```

**Changes Needed:**
- Update `MAX_BLOCK_SIZE` from 1MB to 4MB
- Verify weight calculations account for larger signatures
- Ensure signature verification calls your Dilithium code

**What NOT to Change:**
- Proof of Work validation
- Difficulty adjustment
- Timestamp rules
- Coinbase rules
- Block reward schedule

---

### 🔵 MINIMAL: Network & Infrastructure (Months 8-10)

#### 9. `src/net_processing.cpp` - P2P Message Handling

**Mostly unchanged, but verify:**
- Message size limits accommodate 4MB blocks
- Compact block transmission handles larger transactions
- Mempool message sizes

**Files to Check:**
```cpp
// src/net_processing.cpp
static const unsigned int MAX_GETDATA_SZ = 1000;  // Probably fine

// src/protocol.h
static const unsigned int MAX_INV_SZ = 50000;  // Check if adequate
```

#### 10. `src/wallet/` - Wallet Functionality

**Files to Modify:**
```
src/wallet/
├── wallet.cpp        # Key storage, signing
├── rpcdump.cpp       # Import/export keys
├── rpcwallet.cpp     # RPC commands
└── scriptpubkeyman.cpp  # Key management
```

**Changes:**
- Key storage format (2,560 bytes instead of 32)
- Address generation
- Backup format (wallet files will be larger)
- HD wallet derivation (BIP32 won't work directly)

**HD Wallet Problem:**

Bitcoin uses BIP32 for hierarchical deterministic wallets. This won't work with Dilithium.

**Solutions:**
1. **Use seed-based derivation** - Generate Dilithium keys from master seed
2. **Store keys individually** - No HD derivation (simpler, less elegant)
3. **Create new standard** - Define quantum-resistant HD scheme

**Recommendation:** Start with option 2 (simplest), add option 3 later.

---

## File-by-File Modification Checklist

### Phase 1: Core Crypto (MUST DO FIRST)

**Priority 1 (Weeks 1-8):**
```
☐ src/crypto/dilithium/dilithium.h          [CREATE NEW]
☐ src/crypto/dilithium/dilithium.cpp        [CREATE NEW]
☐ src/key.h                                  [MAJOR REWRITE]
☐ src/key.cpp                                [MAJOR REWRITE]
☐ src/pubkey.h                               [MAJOR REWRITE]
☐ src/pubkey.cpp                             [MAJOR REWRITE]
☐ src/test/key_tests.cpp                     [UPDATE TESTS]
```

### Phase 2: Data Structures (WEEKS 9-16)

**Priority 2:**
```
☐ src/primitives/transaction.h              [MINOR UPDATES]
☐ src/script/interpreter.cpp                [SIGNATURE VALIDATION]
☐ src/script/sign.cpp                       [SIGNATURE CREATION]
☐ src/script/standard.cpp                   [SCRIPT TEMPLATES]
☐ src/consensus/consensus.h                 [BLOCK SIZE LIMITS]
☐ src/base58.cpp or src/bech32.cpp         [ADDRESS FORMAT]
☐ src/key_io.cpp                            [ADDRESS PARSING]
```

### Phase 3: Consensus (WEEKS 17-24)

**Priority 3:**
```
☐ src/validation.cpp                        [BLOCK VALIDATION]
☐ src/consensus/tx_verify.cpp               [TX VERIFICATION]
☐ src/chainparams.cpp                       [NETWORK PARAMETERS]
☐ src/pow.cpp                               [VERIFY NO CHANGES NEEDED]
```

### Phase 4: Wallet & RPC (WEEKS 25-32)

**Priority 4:**
```
☐ src/wallet/wallet.cpp                     [KEY STORAGE]
☐ src/wallet/scriptpubkeyman.cpp            [KEY MANAGEMENT]
☐ src/wallet/rpcdump.cpp                    [IMPORT/EXPORT]
☐ src/rpc/blockchain.cpp                    [RPC UPDATES]
☐ src/qt/                                    [GUI, IF NEEDED]
```

### Phase 5: Testing (WEEKS 33-40)

**Priority 5:**
```
☐ test/functional/*.py                      [FUNCTIONAL TESTS]
☐ src/test/*.cpp                            [UNIT TESTS]
☐ test/util/setup_common.cpp                [TEST FRAMEWORK]
```

---

## Build System Changes

### `configure.ac` and `Makefile.am`:

```bash
# Add Dilithium library dependency
AC_CHECK_HEADER([pqcrystals/dilithium2/api.h],
    [], [AC_MSG_ERROR([libdilithium headers not found])])

AC_CHECK_LIB([pqcrystals_dilithium2_ref],
    [pqcrystals_dilithium2_ref_keypair],
    [DILITHIUM_LIBS=-lpqcrystals_dilithium2_ref],
    [AC_MSG_ERROR([libdilithium library not found])])
```

### `CMakeLists.txt` (if using CMake):

```cmake
# Find Dilithium library
find_package(PQCrystals REQUIRED)

# Link against it
target_link_libraries(bitcoin_node
    PRIVATE
    pqcrystals::dilithium
)
```

---

## Genesis Block Modification

### `src/chainparams.cpp` - Genesis Block:

```cpp
// MainNet genesis block
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const CAmount& genesisReward) {
    // CHANGE THIS
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

    // Your timestamp
    const char* pszTimestamp = "NY Times 01/Jan/2027 Quantum Computer Threatens Bitcoin";

    // Rest stays mostly the same
}

// Update genesis hash (you'll mine this)
consensus.hashGenesisBlock = uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");  // WILL CHANGE
```

---

## Critical Constants to Change

### Network Parameters (`src/chainparams.cpp`):

```cpp
// Mainnet
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        // Block timing (KEEP SAME)
        consensus.nPowTargetSpacing = 10 * 60;  // 10 minutes
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;  // 2 weeks

        // Block size (CHANGE THIS)
        consensus.nMaxBlockSize = 4000000;  // 4 MB instead of 1 MB

        // P2P port (MUST BE DIFFERENT)
        nDefaultPort = 8433;  // Not 8333 (Bitcoin's port)

        // Address prefixes (MUST BE DIFFERENT)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);  // Q
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,65);  // R

        // Bech32 prefix
        bech32_hrp = "qb";  // quantum-bitcoin (not "bc" like Bitcoin)

        // Seeds (YOU'LL ADD THESE POST-LAUNCH)
        vSeeds.emplace_back("seed.dilithion.com");
    }
};
```

---

## Testing Strategy

### Unit Tests to Write:

```cpp
// src/test/dilithium_tests.cpp
BOOST_AUTO_TEST_SUITE(dilithium_tests)

BOOST_AUTO_TEST_CASE(dilithium_key_generation) {
    CKey key;
    key.MakeNewKey(true);
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(key.size() == 2560);
}

BOOST_AUTO_TEST_CASE(dilithium_signature_creation) {
    CKey key;
    key.MakeNewKey(true);

    uint256 hash = Hash("test message");
    std::vector<unsigned char> sig;

    BOOST_CHECK(key.Sign(hash, sig));
    BOOST_CHECK(sig.size() == 2420);
}

BOOST_AUTO_TEST_CASE(dilithium_signature_verification) {
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    uint256 hash = Hash("test message");
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);

    BOOST_CHECK(pubkey.Verify(hash, sig));
}

BOOST_AUTO_TEST_CASE(dilithium_invalid_signature_rejected) {
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    uint256 hash = Hash("test message");
    std::vector<unsigned char> sig(2420, 0x00);  // Invalid signature

    BOOST_CHECK(!pubkey.Verify(hash, sig));
}

BOOST_AUTO_TEST_SUITE_END()
```

---

## Development Workflow

### Step 1: Fork Bitcoin Core

```bash
# Clone Bitcoin Core
git clone https://github.com/bitcoin/bitcoin.git dilithion
cd dilithion

# Create your branch
git checkout -b quantum-resistant

# Rename remotes
git remote rename origin bitcoin-upstream
git remote add origin https://github.com/yourusername/dilithion.git
```

### Step 2: Add Dilithium Library

```bash
# Option A: Git submodule (recommended)
mkdir -p depends/dilithium
git submodule add https://github.com/pq-crystals/dilithium.git depends/dilithium

# Option B: Use liboqs
git submodule add https://github.com/open-quantum-safe/liboqs.git depends/liboqs
```

### Step 3: Build Bitcoin Core (baseline)

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 libssl-dev libevent-dev libboost-all-dev libdb-dev \
    libdb++-dev libminiupnpc-dev libzmq3-dev libqt5gui5 libqt5core5a \
    libqt5dbus5 qttools5-dev qttools5-dev-tools

# Build
./autogen.sh
./configure
make -j$(nproc)

# Verify it works
./src/bitcoind --version
```

### Step 4: Make Your First Modification

```bash
# Modify genesis block as a test
nano src/chainparams.cpp

# Change the timestamp
const char* pszTimestamp = "YOUR MESSAGE HERE";

# Rebuild
make -j$(nproc)

# If it compiles, you're ready to start real work
```

---

## Immediate Next Steps (Week 1)

### Day 1-2: Environment Setup
- [ ] Fork Bitcoin Core repository
- [ ] Get it compiling on your machine
- [ ] Run the test suite (should pass)
- [ ] Make trivial modification and verify rebuild works

### Day 3-4: Study CRYSTALS-Dilithium
- [ ] Read NIST FIPS 204 specification
- [ ] Download reference implementation
- [ ] Compile and run Dilithium examples
- [ ] Understand parameter sets (choose Dilithium-2)

### Day 5-7: Initial Design Doc
- [ ] Write 10-page technical specification
- [ ] Map out every file that needs changes
- [ ] Identify dependencies between modifications
- [ ] Create detailed timeline

### Week 2: Proof of Concept
- [ ] Create `src/crypto/dilithium/` directory
- [ ] Wrapper functions for key generation
- [ ] Simple sign/verify test program
- [ ] Verify correct operation outside Bitcoin

### Week 3: Key Infrastructure
- [ ] Modify `CKey` class for Dilithium private keys
- [ ] Update serialization/deserialization
- [ ] Write unit tests
- [ ] Ensure tests pass

### Week 4: Public Key & Addresses
- [ ] Modify `CPubKey` class
- [ ] Update address generation (32-byte hash)
- [ ] Implement Bech32m encoding
- [ ] Test address creation/parsing

---

## Danger Zones (Extra Careful)

### 🚨 Consensus-Critical Code:

```
src/validation.cpp           - Block acceptance rules
src/consensus/tx_verify.cpp  - Transaction verification
src/script/interpreter.cpp   - Script execution (signature checks)
src/pow.cpp                  - Mining difficulty (don't touch)
```

**Testing Requirement:**
- Every change needs comprehensive test
- Run functional tests after every modification
- Compare behavior with Bitcoin Core on test vectors

### 🚨 Cryptographic Code:

```
src/key.cpp                  - Private key operations
src/pubkey.cpp               - Signature verification
src/crypto/dilithium/*       - Dilithium implementation
```

**Testing Requirement:**
- Cryptographer review mandatory
- Test against official Dilithium test vectors
- Side-channel analysis
- Fuzz testing

---

## Documentation to Create

### For Yourself:
- [ ] Implementation journal (daily notes)
- [ ] Decision log (why you made each choice)
- [ ] Test results log
- [ ] Known issues tracker

### For Community:
- [ ] Technical whitepaper
- [ ] Build instructions
- [ ] API documentation
- [ ] Migration guide (from Bitcoin)
- [ ] Security assumptions

---

## Reality Check Milestones

### Month 3: Can you compile modified code?
- **If no:** Need more C++ help
- **If yes:** Proceed

### Month 6: Do unit tests pass for key operations?
- **If no:** Debug cryptographic implementation
- **If yes:** Proceed

### Month 9: Does testnet sync blocks?
- **If no:** Consensus bugs, fix immediately
- **If yes:** Proceed

### Month 12: Can you mine blocks?
- **If no:** Mining infrastructure issues
- **If yes:** Ready for external testing

### Month 18: Has anyone else successfully run it?
- **If no:** Reconsider launch
- **If yes:** Proceed to security audit

---

## When to Ask for Help

**Definitely seek expert help if:**
- Cryptographic implementation shows timing variations
- Consensus tests fail and you don't know why
- Memory leaks in key handling
- Network doesn't sync properly
- Any security-critical code uncertainty

**Where to Ask:**
- Bitcoin Stack Exchange (technical questions)
- Cryptography Stack Exchange (crypto questions)
- Bitcoin Core developer IRC/Slack
- Academic cryptographers (email directly)

---

## The Actual First Task

**Before anything else, do this:**

```bash
# 1. Clone Bitcoin Core
git clone https://github.com/bitcoin/bitcoin.git quantum-test
cd quantum-test

# 2. Build it
./autogen.sh
./configure --disable-wallet --without-gui  # Simpler initial build
make -j4

# 3. Run tests
make check

# 4. If all tests pass, report back
# 5. If anything fails, debug until it works
```

Once you've successfully built Bitcoin Core, you're ready to start real modifications.

---

**Next:** See `technical-specification.md` for detailed cryptographic specifications.
