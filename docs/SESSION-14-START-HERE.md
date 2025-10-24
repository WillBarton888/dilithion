# Session 14 Start Guide

**Date:** October 25, 2025
**Previous Session:** 13 (complete - RPC Suite + Testing + Documentation)
**Session Focus:** Key Management RPC Commands

---

## Quick Start

```bash
cd ~/bitcoin-dilithium && \
git status && \
echo "Branch: $(git branch --show-current)" && \
echo "Last commit: $(git log --oneline -1)" && \
echo "All tests: " && \
./src/test/test_bitcoin --run_test=dilithium_*,rpc_dilithium_* 2>&1 | tail -2
```

---

## Current Status

### ✅ Completed (Session 13)
- **Phase A:** Full RPC suite (3 commands)
  - `generatedilithiumkeypair` - Generate new keys
  - `signmessagedilithium` - Sign messages
  - `verifymessagedilithium` - Verify signatures
- **Phase D:** Testing & Documentation
  - 8/8 RPC tests passing (100%)
  - User guide (12K)
  - API reference (15K)

### 📊 Statistics
- Total tests: 27/27 passing (100%)
- RPC commands: 3 working
- Documentation: Production-ready
- Code quality: A++

---

## Session 14 Objectives

### Goal: Complete Key Management System

Implement RPC commands for persistent key storage and management, enabling users to:
- Import existing Dilithium keys
- List all stored keys
- Query key metadata
- Export keys for backup

---

## Phase A: Import/Export Commands

### Task 1: `importdilithiumkey` RPC

**Purpose:** Import an existing Dilithium private key into the system

**Syntax:**
```bash
importdilithiumkey "privkey" "label"
```

**Parameters:**
- `privkey` (string, required) - Hex-encoded private key (2560 bytes)
- `label` (string, optional) - Human-readable label for the key

**Returns:**
```json
{
  "pubkey": "...",
  "label": "my-key",
  "imported": true,
  "keyid": "abc123..."
}
```

**Implementation Notes:**
- Validate private key size and format
- Generate public key from private key
- Store in keystore (file or memory)
- Return unique key identifier

**Files to Modify:**
- `src/rpc/dilithium.cpp` - Add RPC command
- `src/dilithium/dilithiumkeystore.h` - NEW: Keystore interface
- `src/dilithium/dilithiumkeystore.cpp` - NEW: Keystore implementation

---

### Task 2: `listdilithiumkeys` RPC

**Purpose:** List all stored Dilithium keys

**Syntax:**
```bash
listdilithiumkeys
```

**Parameters:** None

**Returns:**
```json
[
  {
    "keyid": "abc123...",
    "pubkey": "...",
    "label": "my-key",
    "created": "2025-10-25T12:00:00Z"
  },
  {
    "keyid": "def456...",
    "pubkey": "...",
    "label": "backup-key",
    "created": "2025-10-24T10:30:00Z"
  }
]
```

**Implementation Notes:**
- Query keystore for all keys
- Return metadata (no private keys!)
- Support filtering (future enhancement)

---

### Task 3: `getdilithiumkeyinfo` RPC

**Purpose:** Get detailed information about a specific key

**Syntax:**
```bash
getdilithiumkeyinfo "keyid"
```

**Parameters:**
- `keyid` (string, required) - Key identifier or public key

**Returns:**
```json
{
  "keyid": "abc123...",
  "pubkey": "...",
  "label": "my-key",
  "created": "2025-10-25T12:00:00Z",
  "usage_count": 42,
  "last_used": "2025-10-25T14:30:00Z"
}
```

**Implementation Notes:**
- Support lookup by keyid or pubkey
- Track usage statistics (optional)
- Return comprehensive metadata

---

## Phase B: Keystore Implementation

### DilithiumKeyStore Design

**Purpose:** Persistent storage for Dilithium keys

**Key Features:**
- Thread-safe key storage
- Encrypted storage (optional)
- Key lookup by ID or pubkey
- Metadata tracking

**Interface:**
```cpp
class DilithiumKeyStore {
public:
    // Add key to store
    bool AddKey(const DilithiumKey& key, const std::string& label);

    // Get key by ID
    bool GetKey(const std::string& keyid, DilithiumKey& key) const;

    // List all keys
    std::vector<DilithiumKeyInfo> ListKeys() const;

    // Remove key
    bool RemoveKey(const std::string& keyid);

private:
    std::map<std::string, DilithiumKey> keys;
    std::map<std::string, DilithiumKeyMetadata> metadata;
};
```

**Storage Options:**
1. **In-Memory (Session 14):** Simple map-based storage
2. **File-based (Future):** JSON or binary format
3. **Encrypted (Future):** Passphrase-protected

---

## Phase C: Testing

### Unit Tests

**File:** `src/test/dilithium_keystore_tests.cpp`

**Test Cases:**
1. `keystore_add_get` - Add and retrieve keys
2. `keystore_list` - List multiple keys
3. `keystore_duplicate` - Handle duplicate keys
4. `keystore_remove` - Remove keys
5. `keystore_metadata` - Metadata tracking

### RPC Tests

**File:** `src/test/rpc_dilithium_tests.cpp` (expand)

**New Test Cases:**
1. `rpc_importdilithiumkey` - Import key workflow
2. `rpc_importdilithiumkey_invalid` - Error handling
3. `rpc_listdilithiumkeys` - List keys
4. `rpc_getdilithiumkeyinfo` - Query key info
5. `rpc_keystore_workflow` - Complete import → list → query workflow

---

## Implementation Plan

### Step 1: Design Keystore (30 min)
- [ ] Design DilithiumKeyStore class
- [ ] Define DilithiumKeyInfo structure
- [ ] Plan storage format

### Step 2: Implement Keystore (1 hour)
- [ ] Create `dilithiumkeystore.h`
- [ ] Implement `dilithiumkeystore.cpp`
- [ ] Add unit tests
- [ ] Verify tests pass

### Step 3: Implement RPC Commands (1.5 hours)
- [ ] Add `importdilithiumkey` RPC
- [ ] Add `listdilithiumkeys` RPC
- [ ] Add `getdilithiumkeyinfo` RPC
- [ ] Register commands
- [ ] Build and test

### Step 4: Testing (45 min)
- [ ] Add RPC tests
- [ ] Manual testing workflow
- [ ] Verify all tests passing

### Step 5: Documentation (30 min)
- [ ] Update `dilithium-rpc-guide.md`
- [ ] Update `dilithium-rpc-api.md`
- [ ] Add keystore examples

### Step 6: Commit (15 min)
- [ ] Commit keystore implementation
- [ ] Commit RPC commands
- [ ] Commit tests and documentation

**Total Estimated Time:** 4-5 hours

---

## Success Criteria

### Must Have
- [ ] 3 new RPC commands working
- [ ] DilithiumKeyStore implemented
- [ ] All existing tests still passing
- [ ] New tests added and passing
- [ ] Documentation updated

### Nice to Have
- [ ] Encrypted keystore
- [ ] File-based persistence
- [ ] Key export command

---

## Technical Decisions

### Key ID Generation
**Option A:** Hash of public key (deterministic)
```cpp
std::string keyid = HexStr(Hash(pubkey.begin(), pubkey.end())).substr(0, 16);
```

**Option B:** Random UUID (unique)
```cpp
std::string keyid = GenerateUUID();
```

**Recommendation:** Option A (deterministic, reproducible)

### Storage Format
**Session 14:** In-memory (std::map)
**Future:** JSON file in datadir

### Thread Safety
**Session 14:** Single-threaded (no locks needed)
**Future:** Add mutex for multi-threaded access

---

## Example Workflow

```bash
# Import a key
bitcoin-cli importdilithiumkey "$PRIVKEY" "my-signing-key"

# List all keys
bitcoin-cli listdilithiumkeys

# Get key details
bitcoin-cli getdilithiumkeyinfo "abc123..."

# Sign with imported key (existing command)
bitcoin-cli signmessagedilithium "$PRIVKEY" "Hello!"
```

---

## Files to Create/Modify

### New Files
```
src/dilithium/dilithiumkeystore.h      - Keystore interface
src/dilithium/dilithiumkeystore.cpp    - Keystore implementation
src/test/dilithium_keystore_tests.cpp  - Keystore unit tests
```

### Modified Files
```
src/rpc/dilithium.cpp                  - Add 3 RPC commands
src/test/rpc_dilithium_tests.cpp       - Add RPC tests
src/Makefile.am                        - Add keystore files
src/Makefile.test.include              - Add keystore tests
doc/dilithium/dilithium-rpc-guide.md   - Update guide
doc/dilithium/dilithium-rpc-api.md     - Update API reference
```

---

## Potential Challenges

### Challenge 1: Key Persistence
**Issue:** Keys lost when bitcoind restarts
**Solution (Session 14):** Accept in-memory limitation
**Future:** Implement file-based storage

### Challenge 2: Key Security
**Issue:** Private keys stored unencrypted
**Solution (Session 14):** Document security warning
**Future:** Implement encryption with passphrase

### Challenge 3: Key ID Conflicts
**Issue:** Duplicate key IDs
**Solution:** Use deterministic hash-based IDs (no collisions for same key)

---

## Testing Strategy

### Unit Tests (Keystore)
- Test all CRUD operations
- Test edge cases (empty store, duplicates)
- Test metadata tracking

### RPC Tests
- Test all 3 new commands
- Test error conditions
- Test complete workflows

### Manual Testing
```bash
# Generate key
KEYS=$(bitcoin-cli generatedilithiumkeypair)
PRIVKEY=$(echo "$KEYS" | jq -r '.privkey')

# Import it
bitcoin-cli importdilithiumkey "$PRIVKEY" "test-key"

# List keys
bitcoin-cli listdilithiumkeys

# Get info
KEYID=$(bitcoin-cli listdilithiumkeys | jq -r '.[0].keyid')
bitcoin-cli getdilithiumkeyinfo "$KEYID"
```

---

## Session 14 Deliverables

1. **DilithiumKeyStore** - Complete keystore implementation
2. **3 RPC Commands** - Import, list, query
3. **Unit Tests** - Keystore tests passing
4. **RPC Tests** - New RPC tests passing
5. **Documentation** - Updated guides
6. **All Tests Passing** - 100% pass rate maintained

---

## Ready to Start!

Run the quick start command above to verify your environment, then proceed with:

1. Design DilithiumKeyStore
2. Implement keystore
3. Add RPC commands
4. Test everything
5. Update documentation
6. Commit work

**Estimated Duration:** 4-5 hours
**Expected Outcome:** Complete key management system

Good luck! 🚀
