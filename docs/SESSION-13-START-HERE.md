# Session 13 Start Guide

**Date:** October 25, 2025
**Previous Session:** 12 (completed) + Phase 3 RPC (completed)
**Next Goals:** (A) Expand RPC Commands + (D) Testing & Documentation

---

## Quick Start Command

```bash
cd ~/bitcoin-dilithium && \
git status && \
echo "Branch: $(git branch --show-current)" && \
echo "Last commit: $(git log --oneline -1)" && \
echo "Test status: Run ./src/test/test_bitcoin --run_test=dilithium_* to verify"
```

---

## Current Project Status

### ✅ Completed
- **Session 12:** Production-ready SignatureHash integration (19/19 tests passing)
- **Phase 3:** First Dilithium RPC command (`generatedilithiumkeypair`) working
- **Branch:** `dilithium-integration`
- **Commits:** d5a2c39, 640f34c, a65d010

### 📊 Statistics
- Total Dilithium tests: 19/19 passing (100%)
- RPC commands: 1 working (generatedilithiumkeypair)
- Code quality: Clean builds, no warnings
- Token usage from last session: 39.81% (safe for continuation)

---

## Session 13 Objectives

### Phase A: Expand RPC Commands

**Goal:** Add sign/verify message operations via RPC

**Tasks:**
1. **Add signmessagedilithium RPC**
   - Input: `privkey_hex` (2560 bytes), `message` (string)
   - Output: `signature_hex` (2421 bytes), `message_hash`
   - File: `src/rpc/dilithium.cpp`

2. **Add verifymessagedilithium RPC**
   - Input: `pubkey_hex` (1312 bytes), `signature_hex` (2421 bytes), `message` (string)
   - Output: `valid` (bool), verification details
   - File: `src/rpc/dilithium.cpp`

3. **Implement missing DilithiumKey methods** (if needed)
   - `SetPrivKey(vector<unsigned char>)` - Load private key
   - `GetPrivKey() const` - Export private key
   - Files: `src/dilithium/dilithiumkey.h`, `src/dilithium/dilithiumkey.cpp`

4. **Test complete workflow**
   ```bash
   # Generate
   bitcoin-cli generatedilithiumkeypair

   # Sign
   bitcoin-cli signmessagedilithium "<privkey>" "Hello PQC!"

   # Verify
   bitcoin-cli verifymessagedilithium "<pubkey>" "<signature>" "Hello PQC!"
   ```

**Expected Outcome:**
- 3 working RPC commands
- Complete generate → sign → verify workflow
- Clean build with all tests passing

---

### Phase D: Testing & Documentation

**Goal:** Create comprehensive tests and documentation

**Tasks:**

#### 1. Create RPC Test Suite

**File:** `src/test/rpc_dilithium_tests.cpp`

```cpp
// Test structure:
BOOST_AUTO_TEST_CASE(rpc_generatedilithiumkeypair)
{
    // Test key generation via RPC
    // Verify output format, sizes
}

BOOST_AUTO_TEST_CASE(rpc_signmessagedilithium)
{
    // Test message signing
    // Verify signature format, correctness
}

BOOST_AUTO_TEST_CASE(rpc_verifymessagedilithium)
{
    // Test signature verification
    // Test with valid/invalid signatures
}

BOOST_AUTO_TEST_CASE(rpc_dilithium_e2e_workflow)
{
    // Test complete generate → sign → verify workflow
}
```

**Integration:**
- Add to `src/Makefile.am`
- Update test suite to include RPC tests
- Run: `./src/test/test_bitcoin --run_test=rpc_dilithium_*`

#### 2. User Documentation

**File:** `docs/dilithium-rpc-guide.md`

**Content:**
- Introduction to Dilithium post-quantum signatures
- Why use Dilithium (quantum resistance)
- Installation/setup instructions
- Usage examples for each RPC command
- Common workflows and best practices
- Troubleshooting guide

#### 3. API Reference

**File:** `docs/dilithium-rpc-api.md`

**Content:**
- Complete API specification for each RPC command
- Parameter descriptions
- Return value formats
- Error codes and handling
- Code examples in multiple languages (bash, python, javascript)

**Expected Outcome:**
- RPC test suite with 100% pass rate
- User-friendly documentation
- Complete API reference
- All examples tested and verified

---

## Files to Modify

### Phase A Files
```
src/rpc/dilithium.cpp          - Add sign/verify commands
src/dilithium/dilithiumkey.h   - Add SetPrivKey/GetPrivKey declarations
src/dilithium/dilithiumkey.cpp - Implement SetPrivKey/GetPrivKey
```

### Phase D Files
```
src/test/rpc_dilithium_tests.cpp  - NEW: RPC test suite
src/Makefile.am                    - Add new test file
docs/dilithium-rpc-guide.md        - NEW: User guide
docs/dilithium-rpc-api.md          - NEW: API reference
```

---

## Technical Context

### DilithiumKey Current Interface

```cpp
class DilithiumKey {
    bool MakeNewKey();
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;
    DilithiumPubKey GetPubKey() const;
    bool IsValid() const;
    const std::vector<unsigned char>& GetKeyData() const;
    // MISSING: SetPrivKey, GetPrivKey (need to add)
};
```

### RPC Command Pattern

```cpp
static RPCHelpMan commandname() {
    return RPCHelpMan{"commandname",
        "Description\n",
        {
            {"param1", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Description"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "result", "Description"},
            }
        },
        RPCExamples{
            HelpExampleCli("commandname", "\"param1\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            // Implementation
            UniValue result(UniValue::VOBJ);
            result.pushKV("key", value);
            return result;
        },
    };
}
```

### Current RPC Registration

```cpp
void RegisterDilithiumRPCCommands(CRPCTable& t) {
    static const CRPCCommand commands[]{
        {"dilithium", &generatedilithiumkeypair},
        // Add: {"dilithium", &signmessagedilithium},
        // Add: {"dilithium", &verifymessagedilithium},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
```

---

## Success Criteria

### Phase A Success
- [ ] 3 RPC commands working (generate, sign, verify)
- [ ] Complete workflow functional
- [ ] Clean build (no errors/warnings)
- [ ] 19/19 Dilithium tests still passing
- [ ] Manual RPC testing successful

### Phase D Success
- [ ] RPC test suite created and passing
- [ ] User documentation complete with examples
- [ ] API reference comprehensive and accurate
- [ ] All documentation examples tested
- [ ] Ready for external users

---

## Build & Test Commands

```bash
# Build
cd ~/bitcoin-dilithium
make -j20

# Test all Dilithium tests
./src/test/test_bitcoin --run_test=dilithium_*

# Test RPC tests (after Phase D)
./src/test/test_bitcoin --run_test=rpc_dilithium_*

# Start bitcoind for manual RPC testing
./src/bitcoind -regtest -daemon

# Test RPC commands
./src/bitcoin-cli -regtest generatedilithiumkeypair
./src/bitcoin-cli -regtest signmessagedilithium "<privkey>" "Test message"
./src/bitcoin-cli -regtest verifymessagedilithium "<pubkey>" "<sig>" "Test message"

# Stop bitcoind
./src/bitcoin-cli -regtest stop
```

---

## Common Issues & Solutions

### Issue: SetPrivKey not found
**Solution:** Implement in `src/dilithium/dilithiumkey.cpp`:
```cpp
bool DilithiumKey::SetPrivKey(const std::vector<unsigned char>& vchPrivKey) {
    if (vchPrivKey.size() != DILITHIUM_SECRETKEYBYTES) return false;
    keydata = vchPrivKey;
    // Extract public key from secret key
    // Set fValid = true
    return true;
}
```

### Issue: Build errors after adding test file
**Solution:** Add to `src/Makefile.am` in BITCOIN_TESTS section

### Issue: RPC command not found
**Solution:** Verify registered in RegisterDilithiumRPCCommands() and restart bitcoind

---

## Session Completion Checklist

- [ ] All Phase A tasks complete
- [ ] All Phase D tasks complete
- [ ] All tests passing
- [ ] Documentation verified
- [ ] Changes committed to git
- [ ] Session summary created

---

## Git Status Reference

**Branch:** `dilithium-integration`

**Recent Commits:**
```
d5a2c39 - Phase 3: Dilithium RPC - generatedilithiumkeypair command working
640f34c - Production-ready SignatureHash integration complete
a65d010 - Session 12 Complete: SignatureHash integration framework 100%
```

**Modified Files (uncommitted):**
```
Run `git status` to check current state
```

---

## Previous Sessions Summary

### Session 12
- Fixed CheckDilithiumSignature duplicate code
- Upgraded to production SignatureHash
- Result: 19/19 tests passing

### Session 11
- Complete E2E transaction validation
- Full transaction lifecycle tests

### Session 10
- Script interpreter integration
- OP_CHECKSIG support for Dilithium

### Sessions 1-9
- Core Dilithium implementation
- Key generation, signing, verification
- Address integration
- Transaction integration

---

## Ready to Start!

1. Copy the quick start command above
2. Verify 19/19 tests passing
3. Begin Phase A: Expand RPC Commands
4. Proceed to Phase D: Testing & Documentation
5. Commit and celebrate!

**Estimated Time:**
- Phase A: 1-2 hours
- Phase D: 2-3 hours
- Total: 3-5 hours

Good luck! 🚀
