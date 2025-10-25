# Session 10 - Script Interpreter Integration Plan (A++ Standard)

**Date:** October 24, 2025
**Quality Target:** 10/10 A++
**Session Type:** Critical Path Implementation
**Risk Level:** Medium-High (modifying consensus-critical code)
**Status:** 🔵 PLANNING COMPLETE - READY FOR EXECUTION

---

## Objective

Modify Bitcoin Core's script interpreter to **verify Dilithium signatures** via `OP_CHECKSIG` while maintaining **100% backward compatibility** with existing ECDSA signatures.

**Success Definition:**
- Dilithium signatures verified correctly
- ECDSA signatures still work
- Zero regressions
- Comprehensive test coverage
- Professional code quality

---

## Risk Assessment & Mitigation

### Critical Risks

**Risk 1: Breaking ECDSA Verification** ⚠️ CRITICAL
- **Impact:** All Bitcoin transactions fail
- **Probability:** Medium (if we modify ECDSA code path)
- **Mitigation:**
  - Only add new code path for Dilithium
  - Never modify existing ECDSA logic
  - Test ECDSA thoroughly after changes

**Risk 2: Consensus Incompatibility** ⚠️ CRITICAL
- **Impact:** Fork from Bitcoin network
- **Probability:** Low (our changes are additive)
- **Mitigation:**
  - Document consensus implications
  - Test against Bitcoin test vectors
  - Verify signature format compatibility

**Risk 3: Performance Degradation** ⚠️ MEDIUM
- **Impact:** Slower block validation
- **Probability:** Low (Dilithium verification is fast)
- **Mitigation:**
  - Benchmark before/after
  - Optimize hot path
  - Consider caching

**Risk 4: Incomplete Edge Case Handling** ⚠️ MEDIUM
- **Impact:** Unexpected failures in production
- **Probability:** Medium (complex script logic)
- **Mitigation:**
  - Comprehensive test cases
  - Fuzz testing
  - Code review checklist

---

## Prerequisites Verification

### Must Verify Before Starting
- [ ] All 16 Dilithium tests passing
- [ ] Clean git working directory
- [ ] Bitcoin Core builds successfully
- [ ] Script test infrastructure working
- [ ] DilithiumPubKey::Verify() method available
- [ ] Transaction tests prove signatures work

### Files to Understand
- `src/script/interpreter.h` - Script interpreter interface
- `src/script/interpreter.cpp` - OP_CHECKSIG implementation
- `src/script/sign.h` - Signing infrastructure
- `src/test/script_tests.cpp` - Script test patterns

---

## Phase 1: Analysis & Understanding (45 min)

### Step 1.1: Locate OP_CHECKSIG Implementation
```bash
cd ~/bitcoin-dilithium
grep -n "case OP_CHECKSIG" src/script/interpreter.cpp
grep -n "CheckSig" src/script/interpreter.cpp | head -20
```

**Document:**
- Line numbers where OP_CHECKSIG is handled
- Function signature of signature verification
- Data structures involved
- Error handling patterns

### Step 1.2: Understand Signature Extraction
**Questions to answer:**
1. How are signatures extracted from the stack?
2. How are public keys extracted?
3. What format are they in? (valtype = vector<unsigned char>)
4. What validations are performed?

**Code to read:**
```cpp
// Find this pattern in interpreter.cpp
case OP_CHECKSIG:
{
    if (stack.size() < 2)
        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

    valtype& vchSig = stacktop(-2);
    valtype& vchPubKey = stacktop(-1);

    // ... verification logic ...
}
```

### Step 1.3: Analyze Current Verification Flow
**Map the flow:**
1. Extract signature from stack → `vchSig`
2. Extract pubkey from stack → `vchPubKey`
3. Check signature format/encoding
4. Create CPubKey from vchPubKey
5. Call verification: `CPubKey::Verify(hash, sig)`
6. Push result to stack

**Critical:** Identify where ECDSA-specific code exists

### Step 1.4: Review Test Infrastructure
```bash
cd ~/bitcoin-dilithium
cat src/test/script_tests.cpp | grep -A10 "OP_CHECKSIG"
```

**Understand:**
- How script tests are structured
- JSON test format
- How to add new test cases
- Existing ECDSA test coverage

---

## Phase 2: Design (30 min)

### Design Principles

1. **Additive Only** - Never modify existing ECDSA code paths
2. **Size-Based Detection** - Use signature/pubkey size to detect type
3. **Fail Safe** - Unknown formats fail verification (don't crash)
4. **Minimal Changes** - Smallest possible modification to achieve goal
5. **Clear Documentation** - Every decision documented inline

### Signature Type Detection Strategy

```cpp
// Signature type detection by size
bool IsDilithiumSignature(const valtype& vchSig) {
    return vchSig.size() == 2420;  // Dilithium3 signature size
}

bool IsDilithiumPubKey(const valtype& vchPubKey) {
    return vchPubKey.size() == 1312;  // Dilithium3 public key size
}

bool IsECDSASignature(const valtype& vchSig) {
    // ECDSA signatures: 71-73 bytes typically (DER encoded)
    return vchSig.size() >= 9 && vchSig.size() <= 73;
}
```

### Verification Logic Design

```cpp
// Pseudo-code for OP_CHECKSIG modification
case OP_CHECKSIG:
{
    // ... existing stack checks ...

    valtype& vchSig = stacktop(-2);
    valtype& vchPubKey = stacktop(-1);

    bool fSuccess = false;

    // Determine signature type by size
    if (IsDilithiumSignature(vchSig) && IsDilithiumPubKey(vchPubKey)) {
        // Dilithium verification path
        DilithiumPubKey pubkey(vchPubKey);
        if (pubkey.IsValid()) {
            fSuccess = pubkey.Verify(hash, vchSig);
        }
    } else if (IsECDSASignature(vchSig)) {
        // Existing ECDSA verification path (UNCHANGED)
        // ... existing code ...
    } else {
        // Unknown signature type - fail verification
        fSuccess = false;
    }

    popstack(stack);
    popstack(stack);
    stack.push_back(fSuccess ? vchTrue : vchFalse);
}
```

### Edge Cases to Handle

1. **Mismatched types:** Dilithium sig + ECDSA key → Fail
2. **Invalid sizes:** Size detection must be precise
3. **Null signatures:** Empty vectors → Fail
4. **Script context:** Ensure hash calculation is correct
5. **Signature hash flags:** Preserve SIGHASH_* behavior

---

## Phase 3: Implementation (90 min)

### Step 3.1: Add Helper Functions (15 min)

**File:** `src/script/interpreter.cpp`

**Add at top (after includes):**
```cpp
namespace {

/** Check if signature is Dilithium format based on size */
bool IsDilithiumSignature(const valtype& vchSig) {
    return vchSig.size() == 2420;  // DILITHIUM_BYTES from crypto layer
}

/** Check if public key is Dilithium format based on size */
bool IsDilithiumPubKey(const valtype& vchPubKey) {
    return vchPubKey.size() == 1312;  // DILITHIUM_PUBLICKEYBYTES
}

} // anonymous namespace
```

**Rationale:**
- Encapsulated in anonymous namespace (internal linkage)
- Clear, self-documenting names
- Size constants match crypto layer definitions

### Step 3.2: Add Dilithium Include (5 min)

**File:** `src/script/interpreter.cpp`

**Add after existing includes:**
```cpp
#include <dilithium/dilithiumpubkey.h>  // For Dilithium signature verification
```

**Verify:**
- Include path is correct
- DilithiumPubKey class is available
- Verify() method exists

### Step 3.3: Modify OP_CHECKSIG (45 min)

**File:** `src/script/interpreter.cpp`

**Strategy:** Minimal modification to existing code

**Find the OP_CHECKSIG case:**
```bash
grep -n "case OP_CHECKSIG:" src/script/interpreter.cpp
```

**Modify verification logic:**
```cpp
case OP_CHECKSIG:
case OP_CHECKSIGVERIFY:
{
    // ... existing stack size checks (KEEP UNCHANGED) ...

    valtype& vchSig = stacktop(-2);
    valtype& vchPubKey = stacktop(-1);

    // NEW: Check for Dilithium signature/pubkey
    bool fSuccess = false;

    if (IsDilithiumSignature(vchSig) && IsDilithiumPubKey(vchPubKey)) {
        // Dilithium verification path (NEW)

        // Create DilithiumPubKey from stack data
        DilithiumPubKey pubkey(vchPubKey);

        // Verify signature against message hash
        if (pubkey.IsValid()) {
            fSuccess = pubkey.Verify(hashSignature, vchSig);
        } else {
            fSuccess = false;  // Invalid public key
        }

    } else {
        // EXISTING ECDSA PATH (UNCHANGED)
        // ... keep all existing ECDSA code exactly as-is ...
    }

    // ... rest of OP_CHECKSIG logic (KEEP UNCHANGED) ...
}
```

**Critical:**
- Only add new code before existing ECDSA path
- Move existing code into else block
- Never modify existing ECDSA logic
- Preserve all error handling

### Step 3.4: Handle OP_CHECKMULTISIG (Optional - 25 min)

**Decision Point:**
- Should we support Dilithium in OP_CHECKMULTISIG?
- **Recommendation:** Skip for Session 10, add in Session 11
- **Rationale:**
  - OP_CHECKSIG is higher priority
  - Multisig is complex, needs separate testing
  - Better to perfect single sig first

**Document:** Add TODO comment for future work

---

## Phase 4: Testing (60 min)

### Step 4.1: Create Script Test File (30 min)

**File:** `src/test/dilithium_script_tests.cpp`

**Test cases to implement:**

1. **dilithium_checksig_valid**
   - Create valid Dilithium signature
   - Build script: <sig> <pubkey> OP_CHECKSIG
   - Verify returns true

2. **dilithium_checksig_invalid_sig**
   - Create invalid signature (random bytes)
   - Build script: <bad_sig> <pubkey> OP_CHECKSIG
   - Verify returns false

3. **dilithium_checksig_wrong_key**
   - Sign with key A
   - Verify with key B
   - Verify returns false

4. **dilithium_checksig_empty_sig**
   - Empty signature vector
   - Verify returns false

5. **dilithium_checksig_mismatched_types**
   - Dilithium sig + ECDSA key
   - Verify returns false

6. **ecdsa_checksig_still_works**
   - Create ECDSA signature
   - Verify ECDSA path unchanged
   - Verify returns true (CRITICAL for backward compat)

**Template:**
```cpp
#include <boost/test/unit_test.hpp>
#include <script/interpreter.h>
#include <script/script.h>
#include <dilithium/dilithiumkey.h>
#include <dilithium/dilithiumpubkey.h>
#include <test/util/random.h>

BOOST_AUTO_TEST_SUITE(dilithium_script_tests)

BOOST_AUTO_TEST_CASE(dilithium_checksig_valid)
{
    // Generate key
    DilithiumKey key;
    BOOST_CHECK(key.MakeNewKey());
    DilithiumPubKey pubkey = key.GetPubKey();

    // Create message hash
    uint256 hash = InsecureRand256();

    // Sign
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));

    // Build script: <sig> <pubkey> OP_CHECKSIG
    CScript script;
    script << sig << pubkey.GetVch() << OP_CHECKSIG;

    // Execute script
    ScriptExecutionData execdata;
    BaseSignatureChecker checker;  // Need proper checker with hash
    ScriptError error;

    bool result = EvalScript(stack, script, flags, checker, sigversion, execdata, &error);

    BOOST_CHECK(result);
    BOOST_CHECK(error == SCRIPT_ERR_OK);
    BOOST_CHECK(stack.size() == 1);
    BOOST_CHECK(CastToBool(stack.back()));  // True on stack
}

// ... more test cases ...

BOOST_AUTO_TEST_SUITE_END()
```

### Step 4.2: Update Test Makefile (5 min)

**File:** `src/Makefile.test.include`

Add:
```makefile
test/dilithium_script_tests.cpp \
```

### Step 4.3: Build and Test (15 min)

```bash
cd ~/bitcoin-dilithium
make -j20
./src/test/test_bitcoin --run_test=dilithium_script_tests --log_level=all
```

**Expected:** All new tests pass

### Step 4.4: Regression Testing (10 min)

```bash
# Test ALL Dilithium tests
./src/test/test_bitcoin --run_test=dilithium_* --log_level=test_suite

# Test ECDSA script tests (CRITICAL)
./src/test/test_bitcoin --run_test=script_tests --log_level=test_suite

# Test ECDSA key tests (CRITICAL)
./src/test/test_bitcoin --run_test=key_tests --log_level=test_suite
```

**Success Criteria:**
- All Dilithium tests pass (should be 16+ now)
- No new failures in script_tests
- No new failures in key_tests
- Pre-existing failures unchanged

---

## Phase 5: Validation & Polish (30 min)

### Step 5.1: Code Review Checklist

**Code Quality:**
- [ ] No magic numbers (use named constants)
- [ ] All branches have comments explaining rationale
- [ ] Error cases handled explicitly
- [ ] No memory leaks (stack-based objects)
- [ ] Const correctness maintained
- [ ] Follows Bitcoin Core style guide

**Security:**
- [ ] No buffer overflows possible
- [ ] Integer overflow checks if needed
- [ ] Constant-time operations where required
- [ ] Input validation on all external data
- [ ] Error messages don't leak information

**Testing:**
- [ ] All edge cases covered
- [ ] Both success and failure paths tested
- [ ] ECDSA backward compatibility verified
- [ ] Invalid input handling tested
- [ ] Empty/null input tested

**Documentation:**
- [ ] Inline comments explain "why" not "what"
- [ ] Function-level documentation if needed
- [ ] TODO comments for future work
- [ ] Commit message is detailed

### Step 5.2: Performance Validation

**Benchmark:**
```bash
cd ~/bitcoin-dilithium
./src/bench/bench_bitcoin -filter=".*CheckSig.*"
```

**Measure:**
- OP_CHECKSIG execution time before/after
- Verify no performance regression for ECDSA
- Document Dilithium verification performance

### Step 5.3: Documentation

**Update files:**
1. `docs/SESSION-10-COMPLETION.md` - Detailed report
2. `docs/PHASE-2-PLAN.md` - Update progress
3. Code comments - Inline documentation

---

## Phase 6: Commit (15 min)

### Commit Message Template

```
Session 10: Add Dilithium signature verification to script interpreter

Implement OP_CHECKSIG support for Dilithium post-quantum signatures while
maintaining 100% backward compatibility with existing ECDSA signatures.

**What was implemented:**
- Size-based signature type detection (2420 bytes = Dilithium)
- Dilithium verification path in OP_CHECKSIG handler
- Helper functions: IsDilithiumSignature(), IsDilithiumPubKey()
- Comprehensive test suite (6+ test cases)

**Key design decisions:**
1. Additive approach - ECDSA code path completely untouched
2. Size-based detection - simple, reliable, no ambiguity
3. Fail-safe - unknown signature types fail verification
4. Minimal changes - only modified OP_CHECKSIG handler

**Testing:**
✅ dilithium_checksig_valid - Valid signatures verify correctly
✅ dilithium_checksig_invalid_sig - Invalid sigs rejected
✅ dilithium_checksig_wrong_key - Wrong key fails verification
✅ dilithium_checksig_empty_sig - Empty sigs handled
✅ dilithium_checksig_mismatched_types - Type mismatches fail
✅ ecdsa_checksig_still_works - ECDSA backward compatibility

**Backward compatibility:**
- Zero changes to ECDSA verification path
- All existing script_tests pass (no new failures)
- ECDSA signatures work exactly as before

**Performance:**
- No measurable impact on ECDSA verification
- Dilithium verification: ~XXX μs (documented)

**Files modified:**
- src/script/interpreter.cpp (added Dilithium verification)
- src/test/dilithium_script_tests.cpp (NEW - 6 test cases)
- src/Makefile.test.include (added new test file)

**Total tests:** 22+ passing (16 existing + 6 new)

**Next steps:**
- End-to-end transaction validation
- RPC interface for Dilithium transactions
- Mempool acceptance testing

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Success Criteria (10/10 A++ Standard)

### Must Have (All required)
- [ ] Dilithium signatures verify correctly in scripts
- [ ] ECDSA signatures still work (zero regressions)
- [ ] All edge cases tested (6+ test cases)
- [ ] Code follows Bitcoin Core standards
- [ ] Inline documentation complete
- [ ] Performance validated (no ECDSA regression)
- [ ] Security review checklist complete
- [ ] Backward compatibility proven
- [ ] Commit message is professional
- [ ] Completion report is comprehensive

### A++ Quality Indicators
- [ ] **Zero assumptions** - Everything verified
- [ ] **Risk mitigation** - All critical risks addressed
- [ ] **Professional process** - Systematic approach documented
- [ ] **Comprehensive testing** - Edge cases covered
- [ ] **Clear rationale** - Design decisions explained
- [ ] **Future-proof** - Easy to extend (e.g., OP_CHECKMULTISIG)
- [ ] **Maintainable** - Next developer can understand easily
- [ ] **Production-ready** - Code quality suitable for mainnet

---

## Estimated Timeline

| Phase | Task | Time | Cumulative |
|-------|------|------|------------|
| 1 | Analysis & Understanding | 45 min | 0:45 |
| 2 | Design | 30 min | 1:15 |
| 3 | Implementation | 90 min | 2:45 |
| 4 | Testing | 60 min | 3:45 |
| 5 | Validation & Polish | 30 min | 4:15 |
| 6 | Commit & Documentation | 15 min | 4:30 |

**Total Estimated:** 4.5 hours
**Buffer (A++ standard):** +30 min
**Target Completion:** 5 hours

---

## Contingency Plans

### If OP_CHECKSIG is more complex than expected
- **Fallback:** Implement minimal version, document complexity
- **Alternative:** Add new opcode OP_CHECKSIG_DILITHIUM
- **Timeline:** +2 hours

### If test infrastructure is difficult
- **Fallback:** Start with unit tests, add script tests later
- **Alternative:** Manual testing with regtest
- **Timeline:** +1 hour

### If ECDSA regression occurs
- **Action:** Immediately revert changes
- **Debug:** Identify exact code that caused regression
- **Fix:** More conservative modification approach
- **Timeline:** +1-2 hours

---

## Pre-Flight Checklist

Before starting implementation:
- [ ] Read this entire document
- [ ] Understand all risks and mitigations
- [ ] Verify all 16 existing tests pass
- [ ] Clean git working directory
- [ ] Bitcoin Core builds successfully
- [ ] Have backup plan if main approach fails
- [ ] Commit to A++ quality standard

**Confidence Level:** High (90%)
**Risk Level:** Medium (modifying consensus code)
**Quality Target:** 10/10 A++

---

**Status:** ✅ PLAN COMPLETE - READY FOR EXECUTION

Let's build A++ quality code! 🚀
