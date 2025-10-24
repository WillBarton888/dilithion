# Session 15 Quick Start Guide

**Date:** October 25, 2025
**Previous Session:** 14 (100% Complete)
**Current Branch:** phase-2-transaction-integration
**Test Status:** ✅ 39/39 passing
**Phase 2 Progress:** ~60%

---

## Quick Status Check

```bash
cd ~/bitcoin-dilithium
git status
git log --oneline -3

# Verify all tests passing
./src/test/test_bitcoin --run_test=dilithium_*,rpc_dilithium_tests
# Expected: *** No errors detected (39 tests)
```

---

## What Was Completed in Session 14

✅ **Dilithium Key Management System** (100% complete)
- Fixed key import to require privkey + pubkey (more secure)
- Added SetPubKey() method to DilithiumKey
- Fixed all public key encoding bugs
- Created 9 keystore unit tests
- Created 3 new RPC tests (import, list, getinfo)
- **Result:** 39/39 tests passing

**Key Files Modified:**
- src/dilithium/dilithiumkey.cpp & .h
- src/rpc/dilithium.cpp
- src/test/rpc_dilithium_tests.cpp
- src/test/dilithium_keystore_tests.cpp

---

## Current System Capabilities

### Working Features ✅

1. **Key Generation** - `generatedilithiumkeypair` RPC
2. **Message Signing** - `signmessagedilithium` RPC
3. **Message Verification** - `verifymessagedilithium` RPC
4. **Key Management** - `importdilithiumkey`, `listdilithiumkeys`, `getdilithiumkeyinfo` RPCs
5. **Address Generation** - Quantum-safe bech32m addresses
6. **Transaction Creation** - Build and serialize Dilithium transactions
7. **Script Verification** - OP_CHECKSIG with CheckDilithiumSignature
8. **E2E Validation** - Complete transaction lifecycle validated

### Test Coverage

- Core dilithium tests: 28 tests ✅
- RPC tests: 11 tests ✅
- **Total: 39/39 passing (100%)**

---

## Recommended Session 15 Objectives

### Option 1: Transaction RPC Commands (RECOMMENDED)

**Goal:** Complete the RPC story with transaction operations

**Tasks:**
1. Implement `createrawtransactiondilithium` RPC
   - Input: addresses, amounts, dilithium mode flag
   - Output: unsigned transaction hex

2. Implement `signrawtransactiondilithium` RPC
   - Input: transaction hex, private keys
   - Output: signed transaction hex

3. Add integration tests
   - Full create → sign → verify workflow
   - Multiple inputs/outputs

4. Update documentation
   - RPC API reference
   - User guide examples

**Time Estimate:** 2-3 hours
**Files to Modify:**
- src/rpc/dilithium.cpp (add 2 commands)
- src/test/rpc_dilithium_tests.cpp (add tests)
- docs/dilithium-rpc-api.md (update)

**Success Criteria:**
- 2 new RPC commands working
- Integration tests passing
- Documentation updated
- Can create/sign transactions via RPC

---

### Option 2: Wallet Integration

**Goal:** Native wallet support for Dilithium

**Tasks:**
1. Add Dilithium key support to CWallet
2. Implement `getnewdilithiumaddress` RPC
3. Implement `listdilithiumaddresses` RPC
4. Update wallet database schema

**Time Estimate:** 3-4 hours
**Complexity:** High (wallet system is complex)

**Success Criteria:**
- Wallet can store Dilithium keys
- Can generate new addresses
- Can list all Dilithium addresses

---

### Option 3: Testing & Hardening

**Goal:** Increase robustness and production readiness

**Tasks:**
1. Add fuzz tests for transaction parsing
2. Add stress tests for key management
3. Performance benchmarking
4. Memory profiling (ASAN/Valgrind)

**Time Estimate:** 2-3 hours

**Success Criteria:**
- Fuzz tests running (1M+ iterations)
- No memory leaks
- Performance benchmarks documented

---

## Project Manager Recommendation

**Choose Option 1: Transaction RPC Commands**

**Rationale:**
1. **Incremental Progress** - Builds directly on Session 14's key management
2. **Complete Story** - Creates full RPC workflow (gen → sign → verify → create → send)
3. **Testing Enablement** - Enables thorough testing before wallet integration
4. **User Value** - Developers can integrate Dilithium without wallet changes
5. **Lower Risk** - RPC is simpler than wallet internals
6. **Documentation Flow** - Natural extension of existing RPC docs

**Next Steps After Option 1:**
- Session 16: Wallet integration (Option 2)
- Session 17: Fee estimation
- Session 18: Consensus rules
- Session 19-20: Testing & polish

---

## Phase 2 Remaining Work

**Current:** ~60% complete
**Remaining:** ~8 sessions (4-6 weeks)

### High Priority (Next 3 Sessions)
1. Transaction RPC commands (Session 15)
2. Wallet integration (Session 16-17)
3. Fee estimation (Session 17)

### Medium Priority (4-5 Sessions)
4. Consensus rules (Session 18-19)
5. Multi-signature support (Session 19-20)
6. Final testing & polish (Session 20-21)

**Target:** Phase 2 complete by Session 22-23

---

## Quick Commands for Session 15

```bash
# Start session
cd ~/bitcoin-dilithium
git checkout phase-2-transaction-integration
git pull

# Verify clean state
make clean
make -j20
./src/test/test_bitcoin --run_test=dilithium_*,rpc_dilithium_tests

# Begin Option 1 work
# Edit src/rpc/dilithium.cpp to add createrawtransactiondilithium
# Edit src/rpc/dilithium.cpp to add signrawtransactiondilithium
# Add tests to src/test/rpc_dilithium_tests.cpp

# Test as you go
make -j20
./src/test/test_bitcoin --run_test=rpc_dilithium_tests --log_level=message

# When complete
git add -A
git commit -m "Session 15: Transaction RPC commands complete"
```

---

## Files You'll Likely Edit (Option 1)

1. **src/rpc/dilithium.cpp** - Add 2 new RPC commands (~150 lines)
2. **src/test/rpc_dilithium_tests.cpp** - Add integration tests (~100 lines)
3. **docs/dilithium-rpc-api.md** - Document new commands
4. **docs/dilithium-rpc-guide.md** - Add usage examples

---

## Success Metrics for Session 15

- [ ] createrawtransactiondilithium working
- [ ] signrawtransactiondilithium working
- [ ] Integration test passing (full create/sign workflow)
- [ ] Documentation updated
- [ ] All 39+ tests still passing
- [ ] Clean build (no warnings)
- [ ] Changes committed

---

**Ready to begin Session 15!** 🚀

Choose your objective and proceed with Option A principles: complete it fully before moving on.
