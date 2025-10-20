# Workflow: Implement Dilithium Cryptography

## Overview
This workflow guides the implementation of CRYSTALS-Dilithium cryptographic operations into the Bitcoin Core codebase.

## Prerequisites
- [ ] Bitcoin Core fork compiled successfully
- [ ] CRYSTALS-Dilithium specification reviewed (NIST FIPS 204)
- [ ] pq-crystals/dilithium library or liboqs integrated
- [ ] Development environment fully set up

## Phase 1: Library Integration

### Step 1: Add Dilithium Dependency
```bash
# Navigate to project root
cd dilithion

# Add as git submodule
git submodule add https://github.com/pq-crystals/dilithium.git depends/dilithium
git submodule update --init --recursive

# Or use liboqs for multiple PQ algorithms
git submodule add https://github.com/open-quantum-safe/liboqs.git depends/liboqs
```

### Step 2: Update Build System
```bash
# Edit configure.ac
nano configure.ac

# Add Dilithium library checks
# Add linker flags
# Update makefiles
```

### Step 3: Verify Build
```bash
./autogen.sh
./configure
make clean
make -j$(nproc)

# Should compile without errors
```

## Phase 2: Create Wrapper Layer

### Step 4: Create Dilithium Wrapper
```bash
mkdir -p src/crypto/dilithium
touch src/crypto/dilithium/dilithium.h
touch src/crypto/dilithium/dilithium.cpp
touch src/crypto/dilithium/params.h
```

### Step 5: Implement Basic Functions

**File: `src/crypto/dilithium/dilithium.h`**
```cpp
#ifndef BITCOIN_CRYPTO_DILITHIUM_H
#define BITCOIN_CRYPTO_DILITHIUM_H

#include <cstddef>
#include <cstdint>

namespace dilithium {

// Dilithium-2 parameters
static constexpr size_t PUBLIC_KEY_SIZE = 1312;
static constexpr size_t SECRET_KEY_SIZE = 2560;
static constexpr size_t SIGNATURE_SIZE = 2420;

/** Generate a new Dilithium key pair */
bool GenerateKeyPair(uint8_t* pk, uint8_t* sk);

/** Sign a message with Dilithium secret key */
bool Sign(uint8_t* sig, size_t* siglen,
          const uint8_t* msg, size_t msglen,
          const uint8_t* sk);

/** Verify a Dilithium signature */
bool Verify(const uint8_t* sig, size_t siglen,
            const uint8_t* msg, size_t msglen,
            const uint8_t* pk);

} // namespace dilithium

#endif // BITCOIN_CRYPTO_DILITHIUM_H
```

**File: `src/crypto/dilithium/dilithium.cpp`**
```cpp
#include <crypto/dilithium/dilithium.h>
#include <pqcrystals/dilithium2/api.h>
#include <cstring>

namespace dilithium {

bool GenerateKeyPair(uint8_t* pk, uint8_t* sk) {
    int ret = pqcrystals_dilithium2_ref_keypair(pk, sk);
    return ret == 0;
}

bool Sign(uint8_t* sig, size_t* siglen,
          const uint8_t* msg, size_t msglen,
          const uint8_t* sk) {
    int ret = pqcrystals_dilithium2_ref_signature(sig, siglen, msg, msglen, sk);
    return ret == 0;
}

bool Verify(const uint8_t* sig, size_t siglen,
            const uint8_t* msg, size_t msglen,
            const uint8_t* pk) {
    int ret = pqcrystals_dilithium2_ref_verify(sig, siglen, msg, msglen, pk);
    return ret == 0;
}

} // namespace dilithium
```

### Step 6: Write Unit Tests
```bash
touch src/test/dilithium_tests.cpp
```

**File: `src/test/dilithium_tests.cpp`**
```cpp
#include <boost/test/unit_test.hpp>
#include <crypto/dilithium/dilithium.h>
#include <util/strencodings.h>

BOOST_AUTO_TEST_SUITE(dilithium_tests)

BOOST_AUTO_TEST_CASE(dilithium_keygen) {
    uint8_t pk[dilithium::PUBLIC_KEY_SIZE];
    uint8_t sk[dilithium::SECRET_KEY_SIZE];

    bool success = dilithium::GenerateKeyPair(pk, sk);
    BOOST_CHECK(success);
}

BOOST_AUTO_TEST_CASE(dilithium_sign_verify) {
    // Generate keys
    uint8_t pk[dilithium::PUBLIC_KEY_SIZE];
    uint8_t sk[dilithium::SECRET_KEY_SIZE];
    BOOST_CHECK(dilithium::GenerateKeyPair(pk, sk));

    // Create message
    const char* msg = "test message";
    size_t msglen = strlen(msg);

    // Sign
    uint8_t sig[dilithium::SIGNATURE_SIZE];
    size_t siglen;
    BOOST_CHECK(dilithium::Sign(sig, &siglen, (const uint8_t*)msg, msglen, sk));
    BOOST_CHECK_EQUAL(siglen, dilithium::SIGNATURE_SIZE);

    // Verify
    BOOST_CHECK(dilithium::Verify(sig, siglen, (const uint8_t*)msg, msglen, pk));
}

BOOST_AUTO_TEST_CASE(dilithium_invalid_signature) {
    // Generate keys
    uint8_t pk[dilithium::PUBLIC_KEY_SIZE];
    uint8_t sk[dilithium::SECRET_KEY_SIZE];
    BOOST_CHECK(dilithium::GenerateKeyPair(pk, sk));

    // Create invalid signature (all zeros)
    uint8_t sig[dilithium::SIGNATURE_SIZE] = {0};
    const char* msg = "test message";

    // Should fail verification
    BOOST_CHECK(!dilithium::Verify(sig, dilithium::SIGNATURE_SIZE,
                                    (const uint8_t*)msg, strlen(msg), pk));
}

BOOST_AUTO_TEST_SUITE_END()
```

### Step 7: Run Tests
```bash
make check
# Unit tests should pass
```

## Phase 3: Integrate into Key Classes

### Step 8: Modify CKey Class

**File: `src/key.h`**
- Change keydata size from 32 to 2560 bytes
- Update all methods
- Add Dilithium-specific functions

**File: `src/key.cpp`**
- Reimplement `MakeNewKey()` with Dilithium
- Reimplement `Sign()` with Dilithium
- Update serialization

### Step 9: Modify CPubKey Class

**File: `src/pubkey.h`**
- Change vch size from 65 to 1312 bytes
- Update `Verify()` method
- Remove key recovery methods

**File: `src/pubkey.cpp`**
- Reimplement `Verify()` with Dilithium
- Update `GetID()` for 32-byte hash
- Update serialization

### Step 10: Update Key Tests
```bash
nano src/test/key_tests.cpp
# Update all tests for new key sizes
# Update signature size expectations
# Ensure all tests pass
```

## Phase 4: Validation

### Step 11: Test Against NIST Vectors
```bash
# Download NIST test vectors
wget https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Dilithium-Round3.zip

# Extract and run validation
# Ensure your implementation matches reference
```

### Step 12: Side-Channel Testing
```bash
# Use valgrind for memory issues
valgrind --leak-check=full ./src/test/test_bitcoin

# Check for constant-time operations
# Use specialized tools if available
```

### Step 13: Comprehensive Testing
```bash
# Run all unit tests
make check

# Run all functional tests
test/functional/test_runner.py

# Should all pass (with updates)
```

## Phase 5: Documentation

### Step 14: Document Changes
- Create `docs/dilithium-integration.md`
- Document all parameter choices
- Explain security assumptions
- Note deviations from reference

### Step 15: Update Developer Docs
- Add Dilithium build instructions
- Document new key formats
- Explain cryptographic changes

## Checklist

### Pre-Implementation
- [ ] Dilithium spec fully understood
- [ ] Bitcoin Core architecture studied
- [ ] Development environment ready
- [ ] Testing strategy defined

### Implementation
- [ ] Library integrated into build system
- [ ] Wrapper layer implemented
- [ ] Unit tests written and passing
- [ ] CKey class updated
- [ ] CPubKey class updated
- [ ] All tests passing

### Validation
- [ ] NIST test vectors validated
- [ ] Side-channel testing performed
- [ ] Memory leaks checked
- [ ] Constant-time operations verified
- [ ] Comprehensive test suite passing

### Documentation
- [ ] Implementation documented
- [ ] Security assumptions noted
- [ ] Developer docs updated
- [ ] Code comments complete

## Success Criteria

✅ **Phase Complete When:**
1. All tests pass with Dilithium signatures
2. NIST test vectors validate correctly
3. No timing side-channels detected
4. Memory is properly managed
5. Code reviewed by crypto specialist
6. Documentation is complete

## Next Workflow
After crypto implementation: `address-format-update.md`

## Resources
- NIST FIPS 204 specification
- pq-crystals/dilithium repository
- Bitcoin Core developer documentation
- Side-channel testing tools

## Notes
- Always prioritize security over performance
- Test exhaustively before moving to next phase
- Document every decision
- Get cryptographer review before proceeding
