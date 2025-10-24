# Next Session: Start Here

**Last Updated:** October 24, 2025 - End of Session 6
**Status:** ✅ READY TO IMPLEMENT Option 1 (Additive Integration)
**Next Step:** Create DilithiumKey and DilithiumPubKey classes

---

## Quick Context (30 seconds)

**What happened:** We discovered replacing ECDSA breaks Bitcoin Core v27.0 (50+ files affected). Made smart pivot to **Option 1: Additive Integration** - keep ECDSA, ADD Dilithium alongside it.

**Current state:** Bitcoin Core v27.0 ready, original ECDSA restored, crypto layer verified, architecture documented.

**Next step:** Implement DilithiumKey and DilithiumPubKey classes (2-3 hours of work).

---

## Where We Are

### Git Repositories

**Dilithion Repo** (`C:\Users\will\dilithion`):
- Branch: `phase-2-transaction-integration`
- Latest: Commit `823d8c5` - Session 6 complete with full documentation

**Bitcoin Core Repo** (`~/bitcoin-dilithium` in WSL):
- Branch: `dilithium-integration`
- Latest: Commit `638690f` - Pivot to Option 1, original ECDSA restored
- State: READY for implementation

### Key Files Created

1. **`docs/ARCHITECTURE-DECISION-ADDITIVE-INTEGRATION.md`** ⭐ READ THIS FIRST
   - 15KB comprehensive technical specification
   - Complete implementation plan
   - Code examples for everything
   - This is your blueprint

2. **`docs/SESSION-6-ARCHITECTURE-PIVOT.md`**
   - Full session report
   - Context on why we pivoted
   - Detailed decision rationale

3. **`docs/NEXT-SESSION-START-HERE.md`** (this file)
   - Quick start guide
   - What to do next

---

## Crypto Layer Interface (Verified)

**Location:** `~/bitcoin-dilithium/src/crypto/dilithium/`

**Available Functions:**
```cpp
namespace dilithium {
    // Generate keypair
    int keygen(unsigned char* pk,  // 1312 bytes
               unsigned char* sk); // 2528 bytes

    // Sign message
    int sign(unsigned char* sig,        // 2420 bytes output
             size_t* siglen,
             const unsigned char* msg,
             size_t msglen,
             const unsigned char* sk);

    // Verify signature
    int verify(const unsigned char* sig,  // 2420 bytes
               size_t siglen,
               const unsigned char* msg,
               size_t msglen,
               const unsigned char* pk);  // 1312 bytes
}

// Constants
#define DILITHIUM_PUBLICKEYBYTES 1312
#define DILITHIUM_SECRETKEYBYTES 2528
#define DILITHIUM_BYTES 2420
```

**Status:** ✅ Verified and working (Phase 1)

---

## Next Steps: Implementation (Step-by-Step)

### Step 1: Create DilithiumKey Class (45 min)

**File:** `~/bitcoin-dilithium/src/dilithium/dilithiumkey.h`

**Code Template:**
```cpp
// Copyright (c) 2025 The Dilithion Developers
// Distributed under the MIT software license

#ifndef BITCOIN_DILITHIUM_DILITHIUMKEY_H
#define BITCOIN_DILITHIUM_DILITHIUMKEY_H

#include <crypto/dilithium/dilithium.h>
#include <serialize.h>
#include <uint256.h>
#include <vector>

// Forward declaration
class DilithiumPubKey;

/**
 * Dilithium private key (post-quantum secure)
 *
 * This class wraps the CRYSTALS-Dilithium secret key and provides
 * Bitcoin-compatible signing operations. It works ALONGSIDE the
 * existing ECDSA CKey class (not as a replacement).
 */
class DilithiumKey
{
private:
    std::vector<unsigned char> keydata;  // 2528 bytes
    bool fValid{false};

public:
    static constexpr size_t DILITHIUM_SECRETKEYBYTES = 2528;
    static constexpr size_t DILITHIUM_PUBLICKEYBYTES = 1312;
    static constexpr size_t DILITHIUM_BYTES = 2420;

    DilithiumKey() = default;
    ~DilithiumKey();

    //! Generate new random Dilithium key
    bool MakeNewKey();

    //! Sign a hash (deterministic per Bitcoin conventions)
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    //! Get corresponding public key
    DilithiumPubKey GetPubKey() const;

    //! Check if key is valid
    bool IsValid() const { return fValid; }

    //! Get key data (const access only)
    const std::vector<unsigned char>& GetKeyData() const { return keydata; }

    //! Serialization
    SERIALIZE_METHODS(DilithiumKey, obj) {
        READWRITE(obj.keydata, obj.fValid);
    }
};

#endif // BITCOIN_DILITHIUM_DILITHIUMKEY_H
```

**File:** `~/bitcoin-dilithium/src/dilithium/dilithiumkey.cpp`

```cpp
// Copyright (c) 2025 The Dilithium Developers

#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumpubkey.h>
#include <crypto/dilithium/dilithium.h>
#include <random.h>
#include <support/cleanse.h>

DilithiumKey::~DilithiumKey() {
    // CRITICAL: Clear secret key from memory
    memory_cleanse(keydata.data(), keydata.size());
}

bool DilithiumKey::MakeNewKey() {
    keydata.resize(DILITHIUM_SECRETKEYBYTES);
    std::vector<unsigned char> pubkey(DILITHIUM_PUBLICKEYBYTES);

    // Generate keypair using crypto layer
    int result = dilithium::keygen(pubkey.data(), keydata.data());

    if (result != 0) {
        keydata.clear();
        fValid = false;
        return false;
    }

    fValid = true;
    return true;
}

bool DilithiumKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid) return false;

    vchSig.resize(DILITHIUM_BYTES);
    size_t siglen = DILITHIUM_BYTES;

    // Sign the 32-byte hash
    int result = dilithium::sign(
        vchSig.data(), &siglen,
        hash.begin(), 32,
        keydata.data()
    );

    if (result != 0 || siglen != DILITHIUM_BYTES) {
        vchSig.clear();
        return false;
    }

    return true;
}

DilithiumPubKey DilithiumKey::GetPubKey() const {
    // Implementation after DilithiumPubKey is created
    // For now, return empty
    return DilithiumPubKey();
}
```

---

### Step 2: Create DilithiumPubKey Class (45 min)

**File:** `~/bitcoin-dilithium/src/dilithium/dilithiumpubkey.h`

```cpp
#ifndef BITCOIN_DILITHIUM_DILITHIUMPUBKEY_H
#define BITCOIN_DILITHIUM_DILITHIUMPUBKEY_H

#include <crypto/dilithium/dilithium.h>
#include <serialize.h>
#include <uint256.h>
#include <vector>

class DilithiumKeyID;

/**
 * Dilithium public key (post-quantum secure)
 */
class DilithiumPubKey
{
private:
    std::vector<unsigned char> vch;  // 1312 bytes

public:
    static constexpr size_t DILITHIUM_PUBLICKEYBYTES = 1312;
    static constexpr size_t DILITHIUM_BYTES = 2420;

    DilithiumPubKey() = default;
    explicit DilithiumPubKey(const std::vector<unsigned char>& vchIn) : vch(vchIn) {}

    //! Verify signature
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;

    //! Get key identifier (BLAKE3-256 hash of public key)
    DilithiumKeyID GetID() const;

    //! Check if valid
    bool IsValid() const { return vch.size() == DILITHIUM_PUBLICKEYBYTES; }

    //! Get size
    size_t size() const { return vch.size(); }

    //! Get data
    const unsigned char* data() const { return vch.data(); }
    const std::vector<unsigned char>& GetVch() const { return vch; }

    //! Serialization
    SERIALIZE_METHODS(DilithiumPubKey, obj) {
        READWRITE(obj.vch);
    }

    //! Comparison operators
    friend bool operator==(const DilithiumPubKey& a, const DilithiumPubKey& b) {
        return a.vch == b.vch;
    }
    friend bool operator!=(const DilithiumPubKey& a, const DilithiumPubKey& b) {
        return !(a == b);
    }
    friend bool operator<(const DilithiumPubKey& a, const DilithiumPubKey& b) {
        return a.vch < b.vch;
    }
};

#endif // BITCOIN_DILITHIUM_DILITHIUMPUBKEY_H
```

**File:** `~/bitcoin-dilithium/src/dilithium/dilithiumpubkey.cpp`

```cpp
#include <dilithium/dilithiumpubkey.h>
#include <dilithium/dilithiumkeyid.h>
#include <crypto/dilithium/dilithium.h>

bool DilithiumPubKey::Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid()) return false;
    if (vchSig.size() != DILITHIUM_BYTES) return false;

    // Verify the signature
    int result = dilithium::verify(
        vchSig.data(), vchSig.size(),
        hash.begin(), 32,
        vch.data()
    );

    return (result == 0);
}

DilithiumKeyID DilithiumPubKey::GetID() const {
    return DilithiumKeyID(*this);
}
```

---

### Step 3: Create DilithiumKeyID Class (30 min)

**File:** `~/bitcoin-dilithium/src/dilithium/dilithiumkeyid.h`

```cpp
#ifndef BITCOIN_DILITHIUM_DILITHIUMKEYID_H
#define BITCOIN_DILITHIUM_DILITHIUMKEYID_H

#include <uint256.h>

// Forward declaration
class DilithiumPubKey;

/**
 * Dilithium key identifier (BLAKE3-256 hash of public key)
 *
 * Similar to CKeyID but for Dilithium keys.
 * Inherits from uint256 for consistency with Bitcoin Core patterns.
 */
class DilithiumKeyID : public uint256
{
public:
    DilithiumKeyID() : uint256() {}
    explicit DilithiumKeyID(const DilithiumPubKey& pubkey);
};

#endif // BITCOIN_DILITHIUM_DILITHIUMKEYID_H
```

**File:** `~/bitcoin-dilithium/src/dilithium/dilithiumkeyid.cpp`

```cpp
#include <dilithium/dilithiumkeyid.h>
#include <dilithium/dilithiumpubkey.h>
#include <crypto/blake3.h>

DilithiumKeyID::DilithiumKeyID(const DilithiumPubKey& pubkey) {
    // BLAKE3-256 hash of Dilithium public key
    CBLAKE3 hasher;
    hasher.Write(pubkey.data(), pubkey.size());
    hasher.Finalize((unsigned char*)this->begin());
}
```

---

### Step 4: Update Build System (15 min)

**Add to:** `~/bitcoin-dilithium/src/Makefile.am`

Find the section with Bitcoin Core source files and add:

```makefile
# Dilithium support (post-quantum)
BITCOIN_CORE_H += \
  dilithium/dilithiumkey.h \
  dilithium/dilithiumpubkey.h \
  dilithium/dilithiumkeyid.h

libbitcoin_util_a_SOURCES += \
  dilithium/dilithiumkey.cpp \
  dilithium/dilithiumpubkey.cpp \
  dilithium/dilithiumkeyid.cpp
```

---

### Step 5: Write Tests (30 min)

**File:** `~/bitcoin-dilithium/src/test/dilithium_key_tests.cpp`

```cpp
#include <boost/test/unit_test.hpp>
#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumpubkey.h>
#include <dilithium/dilithiumkeyid.h>
#include <random.h>

BOOST_AUTO_TEST_SUITE(dilithium_key_tests)

BOOST_AUTO_TEST_CASE(dilithium_key_generation)
{
    DilithiumKey key;
    BOOST_CHECK(!key.IsValid());

    BOOST_CHECK(key.MakeNewKey());
    BOOST_CHECK(key.IsValid());
}

BOOST_AUTO_TEST_CASE(dilithium_sign_verify)
{
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());

    DilithiumPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());
    BOOST_CHECK_EQUAL(pubkey.size(), 1312);

    // Sign a random hash
    uint256 hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    BOOST_CHECK_EQUAL(sig.size(), 2420);

    // Verify signature
    BOOST_CHECK(pubkey.Verify(hash, sig));

    // Verify fails with wrong hash
    uint256 wrongHash = GetRandHash();
    BOOST_CHECK(!pubkey.Verify(wrongHash, sig));
}

BOOST_AUTO_TEST_CASE(dilithium_keyid)
{
    DilithiumKey key;
    key.MakeNewKey();
    DilithiumPubKey pubkey = key.GetPubKey();

    DilithiumKeyID keyid = pubkey.GetID();
    BOOST_CHECK(keyid != uint256());

    // Same pubkey should give same keyid
    DilithiumKeyID keyid2 = pubkey.GetID();
    BOOST_CHECK(keyid == keyid2);
}

BOOST_AUTO_TEST_SUITE_END()
```

---

### Step 6: Build and Test (30 min)

```bash
cd ~/bitcoin-dilithium

# Clean previous build
make clean

# Rebuild
./autogen.sh
./configure --disable-wallet --disable-gui
make -j20

# Run Dilithium tests
./src/test/test_bitcoin --run_test=dilithium_key_tests --log_level=all
```

---

## Expected Timeline

| Task | Time | Status |
|------|------|--------|
| Create DilithiumKey class | 45 min | Pending |
| Create DilithiumPubKey class | 45 min | Pending |
| Create DilithiumKeyID class | 30 min | Pending |
| Update build system | 15 min | Pending |
| Write tests | 30 min | Pending |
| Build & validate | 30 min | Pending |
| **Total** | **3 hours** | **Week 1 Day 1** |

---

## Success Criteria

- [x] Architecture decided (Option 1)
- [x] Original ECDSA restored
- [x] Crypto layer verified
- [ ] DilithiumKey class compiles
- [ ] DilithiumPubKey class compiles
- [ ] DilithiumKeyID class compiles
- [ ] All tests pass
- [ ] Can generate Dilithium keys
- [ ] Can sign with Dilithium
- [ ] Can verify Dilithium signatures

---

## Important Notes

**What We're Building:**
- DilithiumKey/DilithiumPubKey **ALONGSIDE** CKey/CPubKey (not replacing)
- Both ECDSA and Dilithium work together
- This is additive integration

**What NOT to Do:**
- ❌ Don't modify CKey/CPubKey/CKeyID
- ❌ Don't remove ECDSA functionality
- ❌ Don't touch Taproot (XOnlyPubKey)
- ❌ Don't touch BIP324 (EllSwiftPubKey)

**Key Principle:**
> Add new Dilithium classes, keep all Bitcoin Core ECDSA intact.

---

## Files to Read Before Starting

1. **`docs/ARCHITECTURE-DECISION-ADDITIVE-INTEGRATION.md`** ⭐ MUST READ
   - Complete technical spec
   - All implementation details
   - Code examples

2. **`docs/SESSION-6-ARCHITECTURE-PIVOT.md`**
   - Why we pivoted
   - Decision rationale

3. **`src/crypto/dilithium/dilithium.h`** (in Bitcoin Core repo)
   - Crypto layer interface
   - Function signatures

---

## Questions?

**Q: Where's the Dilithium reference implementation?**
A: `/root/dilithion-windows/depends/dilithium/ref/` (already tested in Phase 0)

**Q: Do I need to understand the whole architecture doc?**
A: No - just follow the code templates above. The architecture doc is reference material.

**Q: What if the build fails?**
A: Check that original CKey/CPubKey are intact (should be at commit 638690f). If not, run:
```bash
cd ~/bitcoin-dilithium
git checkout 638690f
```

**Q: How do I know if I'm on the right track?**
A: If you can generate a DilithiumKey, sign a hash, and verify it - you're done with Week 1 Day 1.

---

## Final Checklist Before Starting

- [ ] Read `ARCHITECTURE-DECISION-ADDITIVE-INTEGRATION.md`
- [ ] Verify Bitcoin Core at commit 638690f
- [ ] Verify crypto layer present in `src/crypto/dilithium/`
- [ ] Create `src/dilithium/` directory
- [ ] Follow Step 1-6 above
- [ ] Test everything works

---

**Status:** ✅ READY TO GO

**Estimated Time to Working Code:** 3 hours

**Good luck! You have everything you need.** 🚀

---

**Last Session:** Session 6 - Architecture Pivot
**Next Session:** Session 7 - DilithiumKey Implementation
**Overall Progress:** Phase 2 Week 1 - Day 1 of 15
