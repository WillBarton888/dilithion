# Session 9 - Transaction Format Integration

**Date:** October 24, 2025
**Session Type:** Implementation - Phase 2 Week 1-2
**Status:** 🔵 READY TO START
**Branch:** dilithium-integration (Bitcoin Core fork)
**Objective:** Enable Dilithium signatures in Bitcoin Core transactions

---

## Executive Summary

Session 9 focuses on **transaction format integration** - updating Bitcoin Core's transaction data structures to handle Dilithium's larger signatures (2,420 bytes) and public keys (1,312 bytes). This is the critical bridge between our completed key management (Session 7) and address system (Session 8) to actual on-chain transactions.

**What We're Building:**
- Transaction support for 2,420-byte Dilithium signatures
- Network protocol updates for larger messages
- Transaction serialization/deserialization tests
- Foundation for script interpreter integration (Session 10)

---

## Prerequisites ✅

**Completed:**
- [x] DilithiumKey class (Session 7)
- [x] DilithiumPubKey class (Session 7)
- [x] DilithiumKeyID class (Session 7)
- [x] Address format with `dil1...` Bech32m encoding (Session 8)
- [x] CTxDestination integration (Session 8)
- [x] All tests passing (14 tests)

**Ready:**
- [x] Bitcoin Core v27.0 builds successfully
- [x] Crypto layer operational (dilithium::sign/verify)
- [x] Clean working directory

---

## Session 9 Objectives

### Primary Goals

1. **Verify Transaction Compatibility**
   - Confirm CTxIn/CTransaction can handle large signatures
   - Test current serialization with 2,420-byte data
   - Identify any size limit constraints

2. **Update Network Protocol Constants**
   - Increase MAX_TX_SIZE (100 KB → 500 KB)
   - Increase MAX_PROTOCOL_MESSAGE_LENGTH if needed
   - Update MAX_SCRIPT_ELEMENT_SIZE (520 bytes → 3 KB)

3. **Create Dilithium Transaction Tests**
   - Build transactions with Dilithium signatures
   - Test serialization/deserialization
   - Verify size calculations
   - Test transaction validation

4. **Document Integration Points**
   - Identify script interpreter changes needed
   - Document consensus rule requirements
   - Plan for script verification (Session 10)

### Secondary Goals

- Performance baseline for large transactions
- Memory usage analysis
- Fee calculation considerations

---

## Technical Approach

### Step 1: Understand Current Transaction Structure

**Files to Review:**
- `src/primitives/transaction.h` - CTxIn, CTxOut, CTransaction
- `src/script/script.h` - CScript class
- `src/policy/policy.h` - Size limits (MAX_TX_SIZE, etc.)

**Key Questions:**
1. Can CTxIn.scriptSig hold 2,420 bytes + 1,312 bytes = 3,732 bytes?
2. What are current size limits?
3. Where does signature verification happen?

### Step 2: Create Test Transaction

**Approach:**
```cpp
// src/test/dilithium_transaction_tests.cpp

BOOST_AUTO_TEST_CASE(dilithium_transaction_creation)
{
    // 1. Generate Dilithium key
    DilithiumKey key;
    key.MakeNewKey();
    DilithiumPubKey pubkey = key.GetPubKey();

    // 2. Create transaction
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vout.resize(1);

    // 3. Sign transaction hash
    uint256 txhash = GetRandHash();  // Simplified - normally SignatureHash()
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(txhash, sig));
    BOOST_CHECK_EQUAL(sig.size(), 2420);

    // 4. Build scriptSig: <sig> <pubkey>
    CScript scriptSig;
    scriptSig << sig << pubkey.GetVch();
    tx.vin[0].scriptSig = scriptSig;

    // 5. Test serialization
    BOOST_CHECK(tx.vin[0].scriptSig.size() >= 3732);  // sig + pubkey

    // 6. Serialize and deserialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;

    CTransaction tx_loaded;
    ss >> tx_loaded;

    BOOST_CHECK(tx_loaded.vin[0].scriptSig == tx.vin[0].scriptSig);
}
```

### Step 3: Check Size Limits

**Constants to Review:**
```cpp
// src/policy/policy.h
static constexpr unsigned int MAX_TX_SIZE = 100000;  // Need: 500000
static constexpr unsigned int MAX_SCRIPT_SIZE = 10000;  // Need: 50000
static constexpr unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;  // Need: 3000

// src/net.h
static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000;  // May need increase
```

**Action:**
- Document current limits
- Calculate required limits
- Plan conservative increases

### Step 4: Size Limit Updates (If Needed)

**If tests fail due to size limits:**

1. Update `src/policy/policy.h`:
```cpp
// Add Dilithium-specific constants
static constexpr unsigned int MAX_DILITHIUM_SIGNATURE_SIZE = 2420;
static constexpr unsigned int MAX_DILITHIUM_PUBKEY_SIZE = 1312;
static constexpr unsigned int MAX_DILITHIUM_SCRIPTSIG_SIZE = 4000;  // sig + pubkey + overhead

// Update general limits (conservative approach)
static constexpr unsigned int MAX_TX_SIZE = 500000;  // Was 100000
static constexpr unsigned int MAX_SCRIPT_ELEMENT_SIZE = 3000;  // Was 520
```

2. Test impact on existing tests:
```bash
cd ~/bitcoin-dilithium
./src/test/test_bitcoin --run_test=transaction_tests
```

3. Ensure backward compatibility for ECDSA transactions

### Step 5: Transaction Validation Tests

**Test Cases:**
1. Dilithium transaction creation
2. Serialization/deserialization
3. Size validation
4. Multiple inputs (multiple signatures)
5. Mixed ECDSA + Dilithium (if supported)
6. Edge cases (max size, empty, invalid)

---

## Implementation Plan (4-6 hours)

### Phase 1: Analysis (1 hour)
- [  ] Read transaction.h/transaction.cpp
- [  ] Read script.h to understand scriptSig
- [  ] Check current size limits in policy.h
- [  ] Review existing transaction tests
- [  ] Document findings

### Phase 2: Test Creation (2 hours)
- [  ] Create src/test/dilithium_transaction_tests.cpp
- [  ] Implement basic transaction creation test
- [  ] Test with current limits (expect failure)
- [  ] Document which limits are hit

### Phase 3: Size Limit Updates (1 hour)
- [  ] Update policy.h with new constants
- [  ] Re-run tests
- [  ] Verify backward compatibility
- [  ] Run full test suite

### Phase 4: Additional Tests (1-2 hours)
- [  ] Multi-input transactions
- [  ] Large transaction edge cases
- [  ] Serialization round-trip tests
- [  ] Performance measurements

### Phase 5: Documentation (30 min)
- [  ] Update SESSION-9 completion report
- [  ] Document changes made
- [  ] Identify Session 10 requirements
- [  ] Commit and push

---

## Success Criteria

**Must Have:**
- [  ] Can create transaction with 2,420-byte Dilithium signature
- [  ] Transaction serializes/deserializes correctly
- [  ] Size limits updated appropriately
- [  ] At least 5 new transaction tests passing
- [  ] Existing Bitcoin Core tests still pass
- [  ] No build warnings or errors

**Nice to Have:**
- [  ] Performance baseline established
- [  ] Memory usage profiled
- [  ] Mixed ECDSA+Dilithium transaction tested

---

## Expected Challenges

### Challenge 1: Size Limits
**Problem:** MAX_SCRIPT_ELEMENT_SIZE = 520 bytes, Dilithium signature = 2,420 bytes

**Solution:**
- Update MAX_SCRIPT_ELEMENT_SIZE to 3,000 bytes
- May require updating script interpreter validation
- Ensure change doesn't break existing functionality

### Challenge 2: Script Interpreter
**Problem:** Current OP_CHECKSIG expects ECDSA signatures (≤73 bytes)

**Solution (Session 10 scope):**
- Detect signature size to determine type
- If size == 2,420: call DilithiumPubKey::Verify()
- If size ≤ 73: call CPubKey::Verify() (ECDSA)
- Maintain backward compatibility

**For Session 9:** Just document the requirement

### Challenge 3: Consensus Rules
**Problem:** Larger transactions require block size increase

**Solution (Future scope):**
- Document for testnet deployment
- Session 9: Just ensure transactions can be created
- Later sessions: Consensus rules

---

## Files to Modify

### Review Only (No Changes)
- `src/primitives/transaction.h` - Understand structure
- `src/primitives/transaction.cpp` - Understand serialization
- `src/script/script.h` - Understand CScript

### Likely to Modify
- `src/policy/policy.h` - Update size constants
- `src/test/dilithium_transaction_tests.cpp` - NEW FILE (tests)

### Future Sessions
- `src/script/interpreter.cpp` - OP_CHECKSIG logic (Session 10)
- `src/validation.cpp` - Transaction validation (Session 10)
- `src/consensus/consensus.h` - Block size limits (Session 11)

---

## Testing Strategy

### Unit Tests (New)
```cpp
// src/test/dilithium_transaction_tests.cpp
BOOST_AUTO_TEST_SUITE(dilithium_transaction_tests)

BOOST_AUTO_TEST_CASE(create_dilithium_transaction)
BOOST_AUTO_TEST_CASE(serialize_dilithium_transaction)
BOOST_AUTO_TEST_CASE(dilithium_transaction_size)
BOOST_AUTO_TEST_CASE(multi_input_dilithium_transaction)
BOOST_AUTO_TEST_CASE(dilithium_signature_in_scriptsig)

BOOST_AUTO_TEST_SUITE_END()
```

### Regression Tests
```bash
# Ensure existing tests pass
./src/test/test_bitcoin --run_test=transaction_tests
./src/test/test_bitcoin --run_test=script_tests
```

---

## Documentation Requirements

**Session 9 Completion Report:**
- What was completed
- Size limits changed (with justification)
- Test results
- Known issues/limitations
- Session 10 requirements

**Code Comments:**
- Explain Dilithium-specific size constants
- Document backward compatibility considerations
- Reference NIST FIPS 204 where relevant

---

## Handoff to Session 10

**What Session 10 Needs:**
1. Working Dilithium transaction creation
2. Transaction serialization verified
3. Size limits appropriately set
4. Test infrastructure in place

**Session 10 Focus:**
- Script interpreter integration (OP_CHECKSIG)
- Signature verification in scripts
- End-to-end transaction validation

---

## Risk Assessment

**Low Risk:**
- Updating size constants (reversible)
- Adding test files (no production impact)
- Transaction creation (isolated testing)

**Medium Risk:**
- Size limit changes could affect other subsystems
- Need to verify no unintended side effects

**Mitigation:**
- Run full test suite after each change
- Keep changes minimal and focused
- Document all modifications

---

## Timeline Estimate

**Best Case:** 4 hours
- Everything works with minor size limit updates
- Tests pass quickly
- No unexpected issues

**Realistic:** 5-6 hours
- Some debugging of size limits
- Multiple test iterations
- Documentation time

**Worst Case:** 8 hours
- Unexpected compatibility issues
- Complex debugging required
- Multiple subsystems affected

**Estimated Completion:** Session 9 (this session)

---

## Quick Start Commands

```bash
# Navigate to Bitcoin Core repo
cd ~/bitcoin-dilithium

# Create test file
touch src/test/dilithium_transaction_tests.cpp

# Add to test include
# Edit src/Makefile.test.include

# Build
make -j20

# Run tests
./src/test/test_bitcoin --run_test=dilithium_transaction_tests --log_level=all

# Run all tests to check for regressions
./src/test/test_bitcoin
```

---

## References

**Internal Docs:**
- docs/PHASE-2-PLAN.md - Overall Phase 2 strategy
- docs/ARCHITECTURE-DECISION-ADDITIVE-INTEGRATION.md - Integration approach
- docs/SESSION-7-OPTION-1-IMPLEMENTATION.md - Key classes
- docs/SESSION-8-QUICK-START.txt - Address integration

**Bitcoin Core:**
- src/primitives/transaction.h - Transaction structure
- src/policy/policy.h - Size limits
- src/script/script.h - Script operations

**External:**
- NIST FIPS 204 - Dilithium specification
- Bitcoin Core developer docs

---

## Status

**Current State:** Ready to Start
**Prerequisites:** All met ✅
**Blocking Issues:** None
**Confidence:** High (95%)

**Next Steps:**
1. Read transaction.h to understand structure
2. Create basic Dilithium transaction test
3. Run test and identify size limit issues
4. Update size limits conservatively
5. Verify all tests pass
6. Document and commit

---

**Project:** Dilithion - Post-Quantum Bitcoin Fork
**Phase:** Phase 2 - Transaction Integration
**Week:** Weeks 1-2 - Transaction Format
**Session:** Session 9
**Status:** 🔵 READY TO BEGIN

Let's build Dilithium transaction support! 🚀
