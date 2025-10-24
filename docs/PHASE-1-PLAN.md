# Phase 1 Implementation Plan

**Phase:** Implementation - Signature System
**Duration:** 4-6 weeks (estimated)
**Target:** Months 4-6 (Accelerated)
**Status:** 🔵 Not Started
**Priority:** 🔴 Critical

---

## Phase 1 Overview

Phase 1 focuses on implementing the core cryptographic changes required to replace ECDSA signatures with CRYSTALS-Dilithium signatures in Bitcoin Core.

### Objectives

1. **Integrate Dilithium Library** into Bitcoin Core build system
2. **Modify CKey class** to support Dilithium private keys
3. **Modify CPubKey class** to support Dilithium public keys
4. **Implement key serialization** for Dilithium keys
5. **Validate against test vectors** (NIST + reference implementation)
6. **Ensure security properties** (constant-time, no memory leaks, no side-channels)

### Success Criteria

- ✅ Dilithium library integrated into build system
- ✅ CKey can generate Dilithium keypairs
- ✅ CPubKey can verify Dilithium signatures
- ✅ All NIST test vectors pass
- ✅ No memory leaks detected
- ✅ Constant-time operations verified
- ✅ Unit tests passing (100% coverage)
- ✅ Documentation complete

---

## Phase 1 Breakdown

### Month 4: Foundation & Integration (Weeks 1-2)

#### Week 1: Setup & CI/CD

**Tasks:**
1. Set up GitHub Actions CI/CD pipeline
2. Configure automated testing
3. Set up code quality tools (clang-format, cppcheck)
4. Create Phase 1 development branch
5. Configure Address Sanitizer (ASAN) and Undefined Behavior Sanitizer (UBSAN)

**Deliverables:**
- `.github/workflows/ci.yml` - CI/CD configuration
- `.clang-format` - Code formatting rules
- Development branch created

**Agent:** Test Engineer

**Estimated Time:** 3-5 days

#### Week 2: Dilithium Library Integration

**Tasks:**
1. Create `src/crypto/dilithium/` directory structure
2. Add Dilithium library to build system (CMake/Autotools)
3. Create C++ wrapper for Dilithium C functions
4. Implement basic key generation wrapper
5. Write initial unit tests

**Files to Create:**
- `src/crypto/dilithium/dilithium.h` - Wrapper header
- `src/crypto/dilithium/dilithium.cpp` - Wrapper implementation
- `src/test/dilithium_tests.cpp` - Unit tests

**Agent:** Crypto Specialist

**Estimated Time:** 5-7 days

**Success Criteria:**
```cpp
// Basic wrapper test
BOOST_AUTO_TEST_CASE(dilithium_keypair_generation) {
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];

    BOOST_CHECK(dilithium_keypair(pk, sk) == 0);
}
```

---

### Month 5: Core Implementation (Weeks 3-4)

#### Week 3: CKey Modification

**Tasks:**
1. Modify `CKey` class to store Dilithium secret keys
2. Implement `MakeNewKey()` for Dilithium keypair generation
3. Implement `Sign()` for Dilithium signature creation
4. Implement key serialization/deserialization
5. Add memory clearing for security
6. Write comprehensive unit tests

**Files to Modify:**
- `src/key.h` - CKey class definition
- `src/key.cpp` - CKey implementation
- `src/test/key_tests.cpp` - Key tests

**Agent:** Crypto Specialist + Bitcoin Core Expert

**Estimated Time:** 7-10 days

**Security Checklist:**
- [ ] Constant-time operations
- [ ] Memory properly cleared with `memory_cleanse()`
- [ ] No branches on secret data
- [ ] Random number generation validated
- [ ] Test vectors pass

**Implementation Example:**
```cpp
class CKey {
private:
    bool fValid;
    unsigned char keydata[DILITHIUM_SECRETKEYBYTES];

public:
    bool MakeNewKey(bool fCompressed = true);
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;
    CPubKey GetPubKey() const;

    // Serialization
    template <typename Stream>
    void Serialize(Stream& s) const {
        s.write((char*)keydata, DILITHIUM_SECRETKEYBYTES);
    }

    ~CKey() {
        memory_cleanse(keydata, sizeof(keydata));
    }
};
```

#### Week 4: CPubKey Modification

**Tasks:**
1. Modify `CPubKey` class to store Dilithium public keys
2. Implement `Verify()` for Dilithium signature verification
3. Implement public key serialization/deserialization
4. Add public key validation
5. Write comprehensive unit tests
6. Implement batch verification (if applicable)

**Files to Modify:**
- `src/pubkey.h` - CPubKey class definition
- `src/pubkey.cpp` - CPubKey implementation
- `src/test/key_tests.cpp` - Additional tests

**Agent:** Crypto Specialist + Bitcoin Core Expert

**Estimated Time:** 7-10 days

**Security Checklist:**
- [ ] Constant-time verification
- [ ] Input validation for public keys
- [ ] Input validation for signatures
- [ ] No timing leaks
- [ ] Test vectors pass

**Implementation Example:**
```cpp
class CPubKey {
private:
    unsigned char vch[DILITHIUM_PUBLICKEYBYTES];

public:
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;
    bool IsValid() const;

    // Serialization
    template <typename Stream>
    void Serialize(Stream& s) const {
        s.write((char*)vch, DILITHIUM_PUBLICKEYBYTES);
    }

    size_t size() const { return DILITHIUM_PUBLICKEYBYTES; }
};
```

---

### Month 6: Testing & Validation (Weeks 5-6)

#### Week 5: Comprehensive Testing

**Tasks:**
1. Test against all NIST test vectors
2. Implement fuzz testing
3. Run memory leak detection (Valgrind)
4. Run sanitizers (ASAN, UBSAN, MSAN)
5. Performance benchmarking
6. Side-channel testing (if tools available)

**Test Coverage:**
- Unit tests for all functions
- Edge case testing
- Error handling testing
- Cross-validation with reference implementation
- Integration tests

**Agent:** Test Engineer + Security Auditor

**Estimated Time:** 5-7 days

**Testing Strategy:**

```cpp
// Unit Tests
BOOST_AUTO_TEST_CASE(dilithium_sign_verify) {
    CKey key;
    key.MakeNewKey(true);

    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsValid());

    uint256 hash;
    GetRandBytes(hash.begin(), 32);

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    BOOST_CHECK(pubkey.Verify(hash, sig));

    // Test invalid signature
    sig[0] ^= 0xFF;
    BOOST_CHECK(!pubkey.Verify(hash, sig));
}

// Fuzz Testing
void FuzzDilithiumVerify(const uint8_t* data, size_t size) {
    if (size < DILITHIUM_PUBLICKEYBYTES + DILITHIUM_BYTES) return;

    CPubKey pubkey;
    pubkey.Set(data, data + DILITHIUM_PUBLICKEYBYTES);

    std::vector<unsigned char> sig(
        data + DILITHIUM_PUBLICKEYBYTES,
        data + DILITHIUM_PUBLICKEYBYTES + DILITHIUM_BYTES
    );

    uint256 hash;
    memcpy(hash.begin(), data, std::min(size_t(32), size));

    // Should not crash
    pubkey.Verify(hash, sig);
}
```

#### Week 6: Documentation & Review

**Tasks:**
1. Complete technical documentation
2. Document all security assumptions
3. Document API changes
4. Create migration guide
5. Internal security review
6. Prepare for external cryptographer review

**Deliverables:**
- API documentation
- Security analysis document
- Test coverage report
- Performance benchmarks
- Code review checklist

**Agent:** Documentation Writer + Security Auditor

**Estimated Time:** 3-5 days

---

## Technical Implementation Details

### Dilithium Library Wrapper

**Purpose:** Provide a clean C++ interface to the Dilithium C library

**Header (`src/crypto/dilithium/dilithium.h`):**
```cpp
#ifndef BITCOIN_CRYPTO_DILITHIUM_H
#define BITCOIN_CRYPTO_DILITHIUM_H

#include <cstdint>
#include <vector>

// Dilithium-2 parameters (NIST Level 2)
#define DILITHIUM_PUBLICKEYBYTES 1312
#define DILITHIUM_SECRETKEYBYTES 2528
#define DILITHIUM_BYTES 2420

namespace dilithium {

/**
 * Generate a Dilithium keypair.
 *
 * @param pk Output: public key (DILITHIUM_PUBLICKEYBYTES)
 * @param sk Output: secret key (DILITHIUM_SECRETKEYBYTES)
 * @return 0 on success, non-zero on failure
 */
int keypair(unsigned char* pk, unsigned char* sk);

/**
 * Sign a message with Dilithium.
 *
 * @param sig Output: signature (DILITHIUM_BYTES)
 * @param siglen Output: signature length
 * @param msg Input: message to sign
 * @param msglen Input: message length
 * @param sk Input: secret key (DILITHIUM_SECRETKEYBYTES)
 * @return 0 on success, non-zero on failure
 */
int sign(unsigned char* sig, size_t* siglen,
         const unsigned char* msg, size_t msglen,
         const unsigned char* sk);

/**
 * Verify a Dilithium signature (constant-time).
 *
 * @param sig Input: signature (DILITHIUM_BYTES)
 * @param siglen Input: signature length
 * @param msg Input: message that was signed
 * @param msglen Input: message length
 * @param pk Input: public key (DILITHIUM_PUBLICKEYBYTES)
 * @return 0 if valid, non-zero if invalid
 */
int verify(const unsigned char* sig, size_t siglen,
           const unsigned char* msg, size_t msglen,
           const unsigned char* pk);

} // namespace dilithium

#endif // BITCOIN_CRYPTO_DILITHIUM_H
```

**Implementation (`src/crypto/dilithium/dilithium.cpp`):**
```cpp
#include <crypto/dilithium/dilithium.h>
#include <support/cleanse.h>

// Include Dilithium reference implementation
extern "C" {
#include "../../depends/dilithium/ref/api.h"
#include "../../depends/dilithium/ref/sign.h"
}

namespace dilithium {

int keypair(unsigned char* pk, unsigned char* sk) {
    return pqcrystals_dilithium2_ref_keypair(pk, sk);
}

int sign(unsigned char* sig, size_t* siglen,
         const unsigned char* msg, size_t msglen,
         const unsigned char* sk) {
    return pqcrystals_dilithium2_ref_signature(sig, siglen, msg, msglen, sk);
}

int verify(const unsigned char* sig, size_t siglen,
           const unsigned char* msg, size_t msglen,
           const unsigned char* pk) {
    return pqcrystals_dilithium2_ref_verify(sig, siglen, msg, msglen, pk);
}

} // namespace dilithium
```

### CKey Class Modifications

**Key Changes:**
1. Change `keydata` size from 32 bytes (ECDSA) to `DILITHIUM_SECRETKEYBYTES` (2528 bytes)
2. Update `MakeNewKey()` to call `dilithium::keypair()`
3. Update `Sign()` to call `dilithium::sign()`
4. Update serialization to handle larger keys

**Before (ECDSA):**
```cpp
class CKey {
private:
    bool fValid;
    bool fCompressed;
    std::vector<unsigned char, secure_allocator<unsigned char>> keydata;
    // keydata is 32 bytes for secp256k1
};
```

**After (Dilithium):**
```cpp
class CKey {
private:
    bool fValid;
    unsigned char keydata[DILITHIUM_SECRETKEYBYTES];  // 2528 bytes

public:
    bool MakeNewKey(bool fCompressed = true);
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;
    CPubKey GetPubKey() const;

    ~CKey() {
        memory_cleanse(keydata, sizeof(keydata));
    }
};
```

### CPubKey Class Modifications

**Key Changes:**
1. Change `vch` size from 33 bytes (compressed ECDSA) to `DILITHIUM_PUBLICKEYBYTES` (1312 bytes)
2. Update `Verify()` to call `dilithium::verify()`
3. Update `IsValid()` to check Dilithium public key format
4. Remove compression logic (not applicable to Dilithium)

**Before (ECDSA):**
```cpp
class CPubKey {
private:
    unsigned char vch[CPubKey::PUBLIC_KEY_SIZE];  // 33 bytes compressed
};
```

**After (Dilithium):**
```cpp
class CPubKey {
private:
    unsigned char vch[DILITHIUM_PUBLICKEYBYTES];  // 1312 bytes

public:
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;
    bool IsValid() const;

    size_t size() const { return DILITHIUM_PUBLICKEYBYTES; }
};
```

---

## Security Considerations

### Constant-Time Operations

**Critical:** All cryptographic operations must be constant-time to prevent timing attacks.

**Verification:**
```bash
# Use valgrind to check for timing variations
valgrind --tool=cachegrind ./test_bitcoin --run_test=key_tests

# Check that cache misses are constant
# regardless of key/signature values
```

### Memory Safety

**Critical:** Secret keys must be properly cleared from memory.

**Implementation:**
```cpp
CKey::~CKey() {
    memory_cleanse(keydata, sizeof(keydata));
}
```

**Verification:**
```bash
# Use valgrind to check for memory leaks
valgrind --leak-check=full ./test_bitcoin --run_test=key_tests

# Should show: "All heap blocks were freed -- no leaks are possible"
```

### Side-Channel Protection

**Checklist:**
- [ ] No branches on secret data
- [ ] No secret-dependent memory access
- [ ] Constant-time comparison functions used
- [ ] No early returns based on secrets
- [ ] No secret-dependent loop iterations

### Test Vector Validation

**Critical:** Must validate against official NIST test vectors.

**Sources:**
1. NIST FIPS 204 test vectors
2. Dilithium reference implementation test vectors
3. Cross-validation with multiple implementations

---

## Risk Assessment

### High Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Timing side-channel | 🔴 Critical | Constant-time operations, validation |
| Memory leak of keys | 🔴 Critical | Proper memory clearing, sanitizers |
| Implementation bug | 🔴 Critical | Extensive testing, code review |
| Test vector failure | 🔴 Critical | Cross-validation, reference impl |

### Medium Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Performance issues | 🟡 Medium | Benchmarking, optimization |
| Integration complexity | 🟡 Medium | Incremental changes, testing |
| Build system issues | 🟡 Medium | CI/CD early, test on multiple platforms |

### Low Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Documentation gaps | 🟢 Low | Continuous documentation |
| Code style issues | 🟢 Low | Automated formatters |

---

## Testing Strategy

### Unit Tests

**Coverage Target:** 100% of cryptographic code

**Key Test Cases:**
1. Key generation
2. Signature creation
3. Signature verification
4. Invalid signature detection
5. Edge cases (null inputs, wrong sizes, etc.)
6. Serialization/deserialization
7. Memory clearing

### Integration Tests

**Test Scenarios:**
1. Key generation and immediate signing
2. Key serialization and deserialization
3. Multiple sign/verify operations
4. Cross-validation with reference implementation

### Fuzz Testing

**Targets:**
- `CPubKey::Verify()` - Most critical attack surface
- `CKey::Sign()` - Check for crashes/hangs
- Key serialization/deserialization

### Performance Benchmarks

**Metrics:**
- Key generation time
- Signature creation time
- Signature verification time
- Memory usage

**Targets:**
- Key generation: <10ms
- Signature creation: <10ms
- Signature verification: <10ms

---

## Deliverables

### Code
- [ ] `src/crypto/dilithium/dilithium.h`
- [ ] `src/crypto/dilithium/dilithium.cpp`
- [ ] Modified `src/key.h`
- [ ] Modified `src/key.cpp`
- [ ] Modified `src/pubkey.h`
- [ ] Modified `src/pubkey.cpp`
- [ ] `src/test/dilithium_tests.cpp`
- [ ] Updated `src/test/key_tests.cpp`

### Documentation
- [ ] API documentation for Dilithium wrapper
- [ ] Security analysis document
- [ ] Test coverage report
- [ ] Performance benchmark results
- [ ] Migration guide (ECDSA → Dilithium)

### Infrastructure
- [ ] GitHub Actions CI/CD pipeline
- [ ] Automated testing setup
- [ ] Code quality tools configured
- [ ] Sanitizers configured (ASAN, UBSAN, MSAN)

---

## Timeline

### Week-by-Week Plan

**Week 1: CI/CD & Setup**
- Days 1-2: GitHub Actions setup
- Days 3-4: Code quality tools
- Day 5: Branch strategy & planning review

**Week 2: Dilithium Integration**
- Days 1-3: Wrapper implementation
- Days 4-5: Initial unit tests
- Review: Wrapper API complete

**Week 3: CKey Implementation**
- Days 1-3: CKey modifications
- Days 4-5: CKey unit tests
- Review: Key generation working

**Week 4: CPubKey Implementation**
- Days 1-3: CPubKey modifications
- Days 4-5: CPubKey unit tests
- Review: Sign/verify working

**Week 5: Testing & Validation**
- Days 1-2: Test vector validation
- Days 3-4: Fuzz testing, sanitizers
- Day 5: Performance benchmarks

**Week 6: Documentation & Review**
- Days 1-2: Documentation
- Days 3-4: Security review
- Day 5: Phase 1 completion report

---

## Success Metrics

### Code Quality
- ✅ All unit tests passing
- ✅ 100% test coverage of crypto code
- ✅ No memory leaks (Valgrind clean)
- ✅ No sanitizer warnings (ASAN, UBSAN)
- ✅ Code review approved

### Security
- ✅ All NIST test vectors pass
- ✅ Constant-time operations verified
- ✅ No timing side-channels detected
- ✅ Memory properly cleared
- ✅ Fuzz testing completed

### Performance
- ✅ Key generation <10ms
- ✅ Signature creation <10ms
- ✅ Signature verification <10ms
- ✅ Memory usage acceptable

### Documentation
- ✅ API fully documented
- ✅ Security assumptions documented
- ✅ Test coverage documented
- ✅ Migration guide complete

---

## Decision Points

### End of Week 2
**Question:** Is the Dilithium wrapper API stable and tested?
**Criteria:**
- Wrapper compiles
- Basic tests pass
- API is clean

**If No:** Revise wrapper design before proceeding

### End of Week 4
**Question:** Can we generate keys and sign/verify successfully?
**Criteria:**
- CKey can generate keys
- CPubKey can verify signatures
- Basic test vectors pass

**If No:** Investigate issues before proceeding to extensive testing

### End of Week 6
**Question:** Is Phase 1 ready for external review?
**Criteria:**
- All tests passing
- No security issues found
- Documentation complete

**If No:** Extend Phase 1 until criteria met

---

## Next Phase Preview

### Phase 2: Data Structures & Consensus (Not Started)

After Phase 1 completes:
1. Update transaction format for larger signatures
2. Modify script interpreter for Dilithium verification
3. Update consensus rules for larger blocks
4. Implement address format changes
5. Update wallet key storage

**Dependencies:** Phase 1 must be 100% complete

---

## Agent Assignments

### Primary Agents
- **Crypto Specialist:** Lead on all cryptographic code
- **Bitcoin Core Expert:** Lead on Bitcoin Core integration
- **Test Engineer:** Lead on testing strategy
- **Security Auditor:** Lead on security review

### Secondary Agents
- **Consensus Validator:** Review for consensus compatibility
- **Documentation Writer:** Maintain documentation

---

## Resources

### Documentation
- [NIST FIPS 204](https://csrc.nist.gov/publications/detail/fips/204/final)
- [Dilithium Reference](https://github.com/pq-crystals/dilithium)
- [Bitcoin Core Developer Guide](https://bitcoin.org/en/developer-guide)

### Tools
- Valgrind (memory leak detection)
- ASAN/UBSAN/MSAN (sanitizers)
- AFL/libFuzzer (fuzz testing)
- Cachegrind (cache profiling)

### Agent Directives
- `.claude/agents/crypto-specialist.md`
- `.claude/standards/security-critical-code.md`
- `.claude/workflows/crypto-implementation.md`

---

## Approval

**Phase 1 Plan Status:** ✅ READY
**Approved For:** Implementation start
**Start Date:** TBD (after Phase 0 review)
**Estimated Completion:** 4-6 weeks from start

---

**Prepared By:** Claude Code AI Agent
**Date:** October 24, 2025
**Version:** 1.0
