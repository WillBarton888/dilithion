# Session 12 Plan: Proper SignatureHash Implementation

**Goal:** Replace simplified Hash(scriptCode) with proper Bitcoin SignatureHash()

**Time:** ~2 hours

## Current Implementation (Simplified)

```cpp
// In interpreter.cpp:
uint256 sighash = Hash(scriptCode);
```

**Problem:** Doesn't include transaction context, hash types, or follow Bitcoin standards.

## Target Implementation (Proper)

```cpp
// Should use:
uint256 sighash = SignatureHash(
    scriptCode,
    txTo,           // spending transaction
    nIn,            // input index
    nHashType,      // SIGHASH_ALL, etc.
    amount,         // input amount
    sigversion,     // BASE or WITNESS
    cache           // precomputed hashes
);
```

## Steps

1. **Understand SignatureHash()** - Study src/script/interpreter.cpp existing implementation
2. **Update Dilithium signing** - Add hash type parameter to signature
3. **Update interpreter** - Call SignatureHash() instead of Hash()
4. **Update tests** - Fix E2E tests to use proper signature hash
5. **Validate** - Ensure all 19 tests still pass

## Files to Modify

- src/script/interpreter.cpp (Dilithium verification)
- src/key.h / src/key.cpp (DilithiumKey::Sign - add hash type)
- src/test/dilithium_e2e_tests.cpp (use proper SignatureHash)

## Success Criteria

✅ All 19 tests passing
✅ Proper transaction context in signature
✅ Hash type support (at minimum SIGHASH_ALL)
✅ No simplified Hash() shortcuts

**Ready to start?**
