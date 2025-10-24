# Session 14 Work In Progress State

**Date:** October 25, 2025
**Status:** ⚠️ IN PROGRESS (58% complete)
**Token Usage:** 96% (approaching auto-compact)

---

## Quick Resume Command

```bash
cd ~/bitcoin-dilithium && \
git status && \
echo "Branch: $(git branch --show-current)" && \
echo "Last commit: $(git log --oneline -1)" && \
cat docs/SESSION-14-WIP-STATE.md
```

---

## What Was Completed (58%)

### ✅ Phase 1: Keystore Design & Implementation (COMPLETE)

**Files Created:**
1. **`src/dilithium/dilithiumkeystore.h`** (147 lines)
   - DilithiumKeyMetadata struct
   - DilithiumKeyInfo struct
   - DilithiumKeyStore class with full interface
   - Global keystore instance declared

2. **`src/dilithium/dilithiumkeystore.cpp`** (162 lines)
   - All methods implemented
   - Deterministic key ID generation (SHA256 hash)
   - In-memory storage with maps
   - Usage tracking functionality

**Key Features Implemented:**
- ✅ AddKey() - Store keys with labels
- ✅ GetKey() - Retrieve by key ID
- ✅ GetKeyByPubKey() - Retrieve by public key
- ✅ ListKeys() - Get all stored keys
- ✅ UpdateUsage() - Track key usage
- ✅ RemoveKey() - Delete keys
- ✅ Clear() - Remove all keys

---

## What Still Needs To Be Done (42%)

### ⏳ Phase 2: RPC Commands (NOT STARTED)

**Need to add to `src/rpc/dilithium.cpp`:**

#### 1. importdilithiumkey RPC
```cpp
static RPCHelpMan importdilithiumkey()
{
    return RPCHelpMan{"importdilithiumkey",
        "Import a Dilithium private key\n",
        {
            {"privkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Private key hex"},
            {"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Label for key"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "keyid", "Generated key ID"},
                {RPCResult::Type::STR_HEX, "pubkey", "Public key"},
                {RPCResult::Type::STR, "label", "Key label"},
                {RPCResult::Type::BOOL, "imported", "Always true"},
            }
        },
        RPCExamples{
            HelpExampleCli("importdilithiumkey", "\"<privkey_hex>\" \"my-key\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string privkey_hex = request.params[0].get_str();
            std::string label = request.params.size() > 1 ? request.params[1].get_str() : "";

            // Decode and validate private key
            std::vector<unsigned char> privkey_data = ParseHex(privkey_hex);
            if (privkey_data.size() != DILITHIUM_SECRETKEYBYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid private key size: %d bytes", privkey_data.size()));
            }

            // Create key object
            DilithiumKey key;
            if (!key.SetPrivKey(privkey_data)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            }

            // Add to keystore
            std::string keyid;
            if (!g_dilithium_keystore.AddKey(key, label, keyid)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Key already exists in keystore");
            }

            // Return result
            UniValue result(UniValue::VOBJ);
            result.pushKV("keyid", keyid);
            result.pushKV("pubkey", HexStr(key.GetPubKey()));
            result.pushKV("label", label);
            result.pushKV("imported", true);

            return result;
        },
    };
}
```

#### 2. listdilithiumkeys RPC
```cpp
static RPCHelpMan listdilithiumkeys()
{
    return RPCHelpMan{"listdilithiumkeys",
        "List all stored Dilithium keys\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "keyid", "Key identifier"},
                    {RPCResult::Type::STR_HEX, "pubkey", "Public key"},
                    {RPCResult::Type::STR, "label", "Key label"},
                    {RPCResult::Type::NUM, "created", "Creation timestamp"},
                    {RPCResult::Type::NUM, "last_used", "Last used timestamp"},
                    {RPCResult::Type::NUM, "usage_count", "Usage count"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listdilithiumkeys", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::vector<DilithiumKeyInfo> keys = g_dilithium_keystore.ListKeys();

            UniValue result(UniValue::VARR);
            for (const auto& info : keys) {
                UniValue key_obj(UniValue::VOBJ);
                key_obj.pushKV("keyid", info.keyid);
                key_obj.pushKV("pubkey", HexStr(info.pubkey));
                key_obj.pushKV("label", info.label);
                key_obj.pushKV("created", info.created_time);
                key_obj.pushKV("last_used", info.last_used_time);
                key_obj.pushKV("usage_count", (int)info.usage_count);
                result.push_back(key_obj);
            }

            return result;
        },
    };
}
```

#### 3. getdilithiumkeyinfo RPC
```cpp
static RPCHelpMan getdilithiumkeyinfo()
{
    return RPCHelpMan{"getdilithiumkeyinfo",
        "Get information about a Dilithium key\n",
        {
            {"keyid", RPCArg::Type::STR, RPCArg::Optional::NO, "Key identifier"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "keyid", "Key identifier"},
                {RPCResult::Type::STR_HEX, "pubkey", "Public key"},
                {RPCResult::Type::STR, "label", "Key label"},
                {RPCResult::Type::NUM, "created", "Creation timestamp"},
                {RPCResult::Type::NUM, "last_used", "Last used timestamp"},
                {RPCResult::Type::NUM, "usage_count", "Usage count"},
            }
        },
        RPCExamples{
            HelpExampleCli("getdilithiumkeyinfo", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string keyid = request.params[0].get_str();

            DilithiumKey key;
            if (!g_dilithium_keystore.GetKey(keyid, key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Key not found");
            }

            DilithiumKeyMetadata meta;
            g_dilithium_keystore.GetMetadata(keyid, meta);

            UniValue result(UniValue::VOBJ);
            result.pushKV("keyid", meta.keyid);
            result.pushKV("pubkey", HexStr(key.GetPubKey()));
            result.pushKV("label", meta.label);
            result.pushKV("created", meta.created_time);
            result.pushKV("last_used", meta.last_used_time);
            result.pushKV("usage_count", (int)meta.usage_count);

            return result;
        },
    };
}
```

#### 4. Update RegisterDilithiumRPCCommands()
```cpp
void RegisterDilithiumRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"dilithium", &generatedilithiumkeypair},
        {"dilithium", &signmessagedilithium},
        {"dilithium", &verifymessagedilithium},
        {"dilithium", &importdilithiumkey},      // NEW
        {"dilithium", &listdilithiumkeys},       // NEW
        {"dilithium", &getdilithiumkeyinfo},     // NEW
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
```

**Add include at top:**
```cpp
#include <dilithium/dilithiumkeystore.h>
```

---

### ⏳ Phase 3: Build System Integration (NOT STARTED)

**Files to modify:**

#### `src/Makefile.am`
Add after other dilithium files (~line 450):
```makefile
  dilithium/dilithiumkeystore.cpp \
```

#### Copy files to WSL:
```bash
cp /mnt/c/Users/will/dilithion/src/dilithium/dilithiumkeystore.h ~/bitcoin-dilithium/src/dilithium/
cp /mnt/c/Users/will/dilithion/src/dilithium/dilithiumkeystore.cpp ~/bitcoin-dilithium/src/dilithium/
cp /mnt/c/Users/will/dilithion/src/rpc/dilithium.cpp ~/bitcoin-dilithium/src/rpc/
```

---

### ⏳ Phase 4: Testing (NOT STARTED)

#### Unit Tests Needed
Create `src/test/dilithium_keystore_tests.cpp`:
- Test AddKey, GetKey, ListKeys
- Test duplicate key handling
- Test RemoveKey
- Test metadata tracking

#### RPC Tests Needed
Add to `src/test/rpc_dilithium_tests.cpp`:
- Test importdilithiumkey
- Test listdilithiumkeys
- Test getdilithiumkeyinfo
- Test complete workflow

---

### ⏳ Phase 5: Documentation (NOT STARTED)

Update these files:
- `doc/dilithium/dilithium-rpc-guide.md` - Add key management section
- `doc/dilithium/dilithium-rpc-api.md` - Document 3 new commands

---

## Current File Locations

**Windows (source files):**
```
C:\Users\will\dilithion\src\dilithium\dilithiumkeystore.h    (NEW, 147 lines)
C:\Users\will\dilithion\src\dilithium\dilithiumkeystore.cpp  (NEW, 162 lines)
C:\Users\will\dilithion\src\rpc\dilithium.cpp                (needs 3 RPC commands added)
```

**WSL (build location):**
```
~/bitcoin-dilithium/src/dilithium/   (keystore files NOT copied yet)
~/bitcoin-dilithium/src/rpc/         (RPC file NOT updated yet)
```

---

## Next Steps (Priority Order)

1. **Add 3 RPC commands to dilithium.cpp** (30 min)
   - Copy code from above
   - Add include for dilithiumkeystore.h
   - Register commands

2. **Copy files to WSL** (2 min)
   - Copy keystore.h, keystore.cpp
   - Copy updated dilithium.cpp

3. **Update Makefile.am** (5 min)
   - Add dilithiumkeystore.cpp to build

4. **Build and test** (15 min)
   - Run make
   - Fix any compile errors
   - Test manually

5. **Add tests** (30 min)
   - Create keystore tests
   - Add RPC tests
   - Verify all pass

6. **Update documentation** (20 min)
   - Add to user guide
   - Add to API reference

7. **Commit** (5 min)
   - Commit all changes
   - Create session summary

**Total remaining time:** ~2 hours

---

## Testing Commands

```bash
# After implementation, test manually:

# Generate a key
KEYS=$(bitcoin-cli generatedilithiumkeypair)
PRIVKEY=$(echo "$KEYS" | jq -r '.privkey')

# Import it
bitcoin-cli importdilithiumkey "$PRIVKEY" "test-key"

# List all keys
bitcoin-cli listdilithiumkeys

# Get key info
KEYID=$(bitcoin-cli listdilithiumkeys | jq -r '.[0].keyid')
bitcoin-cli getdilithiumkeyinfo "$KEYID"
```

---

## Session 14 Progress Summary

### Completed
- [x] Design keystore architecture
- [x] Implement DilithiumKeyStore class
- [x] Create header file (dilithiumkeystore.h)
- [x] Create implementation file (dilithiumkeystore.cpp)

### In Progress
- [ ] Add RPC commands (0/3)
- [ ] Build system integration
- [ ] Testing
- [ ] Documentation
- [ ] Commit

**Overall Progress: 58% complete**

---

## Important Notes

1. **Files created but NOT in WSL yet** - Need to copy to build location
2. **RPC commands drafted above** - Ready to add to dilithium.cpp
3. **No compilation attempted yet** - May have minor syntax issues
4. **Token limit approaching** - Resume in next session

---

## Resume Instructions for Next Session

1. Read this file (SESSION-14-WIP-STATE.md)
2. Copy the 3 RPC command implementations above into `src/rpc/dilithium.cpp`
3. Copy keystore files to WSL
4. Update Makefile.am
5. Build and test
6. Complete documentation
7. Commit

**Estimated time to complete:** 2 hours

---

**Last Updated:** October 25, 2025 (Session 14 WIP)
**Next Session:** Session 14 continuation (complete remaining 42%)
