# 🚀 NEXT SESSION: Complete Session 11 E2E Test

**Status:** 90% Complete - ONE FIX NEEDED
**Branch:** `dilithium-integration`
**Commit:** `e9badf3`
**Time Remaining:** ~30 min

---

## Quick Summary

Session 11 created comprehensive end-to-end transaction tests. **All core functionality works** (16/16 original tests passing), but the E2E test has a **signature hash mismatch** that needs fixing.

**The Issue:**
- Test signs: `Hash(scriptPubKey)`
- Interpreter verifies: `Hash(scriptCode)`
- These don't match → signature verification fails

---

## Start Commands

```bash
# Check current state
cd ~/bitcoin-dilithium
git log --oneline -3
git status

# Verify original tests still pass
./src/test/test_bitcoin --run_test=dilithium_key_tests,dilithium_address_tests,dilithium_transaction_tests
# Should show: *** No errors detected

# Run E2E test (currently failing)
./src/test/test_bitcoin --run_test=dilithium_e2e_tests --log_level=message
# Error: SCRIPT_ERR_EVAL_FALSE (error 2) - hash mismatch
```

---

## Quick Fix Option 1: Skip FindAndDelete for Dilithium

**File:** `src/script/interpreter.cpp`
**Line:** ~343

**Change:**
```cpp
// Drop the signature in pre-segwit scripts but not segwit scripts
if (sigversion == SigVersion::BASE) {
    // Skip FindAndDelete for Dilithium signatures (they're not in scriptCode)
    if (!IsDilithiumSignature(vchSig)) {  // ADD THIS CHECK
        int found = FindAndDelete(scriptCode, CScript() << vchSig);
        if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
            return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
    }
}
```

**Then rebuild and test:**
```bash
make -j20
./src/test/test_bitcoin --run_test=dilithium_e2e_tests
```

---

## Quick Fix Option 2: Match Hashes in Test

**File:** `src/test/dilithium_e2e_tests.cpp`
**Line:** ~71

**Add debug to see what interpreter is hashing:**
1. In `interpreter.cpp` line ~358, add:
   ```cpp
   LogPrintf("Dilithium hash: %s\n", sighash.ToString());
   ```

2. In `dilithium_e2e_tests.cpp` line ~71, add:
   ```cpp
   BOOST_TEST_MESSAGE("Test hash: " << sighash.ToString());
   ```

3. Rebuild, run, compare hashes

---

## Files to Review

1. **`docs/SESSION-11-STATUS.md`** - Full status and analysis
2. **`src/test/dilithium_e2e_tests.cpp`** - E2E test code
3. **`src/script/interpreter.cpp`** lines 348-377 - Dilithium verification

---

## Success Criteria

```bash
./src/test/test_bitcoin --run_test=dilithium_e2e_tests

# Expected output:
✅ Phase 1: Key pair generated
✅ Phase 2: scriptPubKey created
✅ Phase 3: Previous transaction created
✅ Phase 4: Spending transaction created
✅ Phase 5: Transaction signed
✅ Phase 6: scriptSig built
✅ Phase 7: Script verification SUCCESSFUL!  # <-- Currently failing
✅ Invalid signature correctly rejected
✅ Mismatched pubkey correctly rejected

*** No errors detected  # <-- Goal!
```

---

## After Fix: Commit and Complete

```bash
# Test everything
./src/test/test_bitcoin --run_test=dilithium_*

# Commit
git add src/script/interpreter.cpp src/test/dilithium_e2e_tests.cpp
git commit -m "Session 11 Complete: E2E transaction validation working

Fixed signature hash mismatch.

- All 3 E2E tests passing
- 19 total Dilithium tests (16 + 3 new)
- Complete transaction lifecycle validated

Phase 2 COMPLETE!"

# Create completion report
# docs/SESSION-11-COMPLETION.md
```

---

## Background

**Sessions Completed:**
- Session 7: Key Management ✅
- Session 8: Address System ✅
- Session 9: Transaction Format ✅
- Session 10: Script Interpreter ✅
- Session 11: E2E Validation (90%) ⏳

**What Works:**
- Dilithium key generation
- Signing (2420-byte signatures)
- Address encoding (dil1...)
- Transaction serialization
- OP_CHECKSIG detection

**What Needs Fix:**
- Hash matching between test and interpreter

---

**Estimated Time:** 30 minutes
**Confidence:** Very High (95%)

**LET'S FINISH SESSION 11!** 🚀
