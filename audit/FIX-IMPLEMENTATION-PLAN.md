# Phase 15 Wallet Security - Fix Implementation Plan

**Date**: 2025-11-10
**Status**: 🔄 IN PROGRESS
**Total Fixes**: 39 (10 CRIT, 14 HIGH, 11 MED, 3 LOW)
**Estimated Total Time**: 140-190 hours (18-24 working days)

---

## Executive Summary

**Approach**: Systematic fix implementation following severity (CRIT → HIGH → MED → LOW) with dependency analysis to prevent conflicts.

**Key Principles**:
1. **No shortcuts** - All 39 vulnerabilities will be fixed
2. **No leaving for later** - Complete each fix before moving to next
3. **Test as we go** - Unit test for each fix before proceeding
4. **Atomic commits** - One fix per commit for easy rollback

**Breaking Changes**: 3 fixes require wallet file format changes
- PERSIST-001 (add HMAC integrity check)
- WALLET-001 (change mapWalletTx key structure)
- CRYPT-007 (add authentication tags to encrypted data)

**Migration Strategy**: Implement backward-compatible loader, write forward-only format

---

## Dependency Analysis

### Critical Dependencies

**Group 1: Wallet File Format** (Must be done together)
- WALLET-001: UTXO key collision fix → Changes mapWalletTx structure
- PERSIST-001: Add file integrity HMAC → Changes file format
- PERSIST-007: Add consistency checks → Operates on new structure

**Group 2: Encryption Overhaul** (Can be done together)
- CRYPT-001: Replace custom AES with OpenSSL → Foundation for all encryption
- CRYPT-006: Remove custom AES (same as CRYPT-001)
- CRYPT-007: Add authenticated encryption → Depends on CRYPT-001
- CRYPT-002: IV reuse detection → Works with new encryption

**Group 3: Memory Security** (Independent)
- CRYPT-003: Constant-time passphrase comparison → Standalone fix
- CRYPT-004: Memory locking → Requires secure allocator class

**Group 4: File Permissions** (Independent, quick wins)
- PERSIST-003: Secure wallet file permissions
- PERSIST-005: Secure backup file permissions

**Group 5: RPC Enhancements** (Can be parallel)
- RPC-001: Per-method rate limiting → Extends existing rate limiter
- RPC-002: Role-based access control → New auth system
- RPC-003: Wallet lock for getnewaddress → Simple check addition

---

## Implementation Phases

### PHASE 6.2: CRITICAL Fixes (10 issues, 40-60 hours)

#### Wave 1: Quick Security Wins (4-8 hours)

**FIX-001: CRYPT-003 - Constant-Time Passphrase Comparison**
- **Priority**: Immediate (easy fix, high impact)
- **Time**: 2 hours
- **Files**: wallet_manager_wizard.cpp, wallet_manager.cpp, passphrase_validator.cpp
- **Complexity**: LOW
- **Changes**:
  ```cpp
  // Use existing SecureCompare() from rpc/auth.h:191
  bool ComparePassphrases(const std::string& p1, const std::string& p2) {
      if (p1.length() != p2.length()) return false;
      return SecureCompare((uint8_t*)p1.data(), (uint8_t*)p2.data(), p1.length());
  }
  ```
- **Testing**: Add timing test (compare 1000x, verify std deviation < 1%)
- **Breaking Changes**: None
- **Dependencies**: None

**FIX-002: PERSIST-003 - Secure Wallet File Permissions**
- **Priority**: Immediate
- **Time**: 2 hours
- **Files**: wallet.cpp:1204, wallet_manager.cpp:168
- **Complexity**: LOW
- **Changes**:
  ```cpp
  // Before std::ofstream file(tempFile)
  #ifndef _WIN32
      mode_t old_umask = umask(0077);  // Only owner can read/write
  #endif
  std::ofstream file(tempFile, std::ios::binary);
  #ifndef _WIN32
      umask(old_umask);
      chmod(tempFile.c_str(), S_IRUSR | S_IWUSR);  // 0600
  #endif
  ```
- **Testing**: Create wallet, verify permissions with `stat`
- **Breaking Changes**: None
- **Dependencies**: None

**FIX-003: PERSIST-005 - Secure Backup File Permissions**
- **Priority**: Immediate
- **Time**: 2 hours
- **Files**: wallet_manager.cpp:168-215
- **Complexity**: LOW
- **Changes**: Same as FIX-002, apply to backup file creation
- **Testing**: Create backup, verify permissions before and after chmod
- **Breaking Changes**: None
- **Dependencies**: None

**FIX-004: PERSIST-002 - Add fsync Before Rename**
- **Priority**: Immediate (data loss prevention)
- **Time**: 2 hours
- **Files**: wallet.cpp:1402-1435
- **Complexity**: LOW
- **Changes**:
  ```cpp
  file.flush();
  file.close();
  #ifndef _WIN32
      int fd = open(tempFile.c_str(), O_RDONLY);
      fsync(fd);
      close(fd);
      // Sync parent directory
      int dirfd = open(GetParentDir(saveFile).c_str(), O_RDONLY);
      fsync(dirfd);
      close(dirfd);
  #endif
  std::rename(tempFile.c_str(), saveFile.c_str());
  ```
- **Testing**: Simulate crash during save (kill -9), verify wallet integrity
- **Breaking Changes**: None
- **Dependencies**: None

#### Wave 2: UTXO Key Collision Fix (8-12 hours)

**FIX-005: WALLET-001 - Fix UTXO Key Collision**
- **Priority**: CRITICAL (fund loss risk)
- **Time**: 8-12 hours
- **Files**: wallet.h:168, wallet.cpp:335+
- **Complexity**: HIGH (data structure change)
- **Changes**:
  ```cpp
  // wallet.h - Change map key from txid to COutPoint
  // OLD: std::map<uint256, CWalletTx> mapWalletTx;
  // NEW:
  std::map<COutPoint, CWalletTx> mapWalletTx;

  // wallet.cpp:335 - Update AddTxOut
  bool CWallet::AddTxOut(const uint256& txid, uint32_t vout, ...) {
      COutPoint outpoint(txid, vout);
      mapWalletTx[outpoint] = wtx;  // Use composite key
  }

  // Update ALL methods accessing mapWalletTx:
  // - GetAvailableBalance()
  // - ListUnspentOutputs()
  // - SelectCoins()
  // - Load() / Save() (file format change)
  ```
- **Testing**:
  - Unit test: Add 2 outputs from same tx, verify both stored
  - Integration test: Send to 2 addresses in same tx, verify both appear
- **Breaking Changes**: ⚠️ WALLET FILE FORMAT CHANGE (version bump to DILWLT03)
- **Dependencies**: Must coordinate with PERSIST-001 (both change file format)
- **Migration**:
  ```cpp
  // On Load(): if version == DILWLT02, convert old format to new
  // Wallet must be rescanned after upgrade (re-scan UTXOs)
  ```

**FIX-006: WALLET-002 - Fix Race Condition in ScanUTXOs**
- **Priority**: CRITICAL
- **Time**: 2 hours
- **Files**: wallet.cpp:1678-1691
- **Complexity**: LOW (add locking)
- **Changes**:
  ```cpp
  bool CWallet::ScanUTXOs(CUTXOSet& global_utxo_set) {
      std::lock_guard<std::mutex> lock(cs_wallet);  // Hold lock for entire scan

      global_utxo_set.ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
          // ... (AddTxOut now called under cs_wallet lock)
      });
  }
  ```
- **Testing**: Multi-threaded test (scan + concurrent AddTxOut calls)
- **Breaking Changes**: None
- **Dependencies**: Should be done AFTER FIX-005 (depends on new mapWalletTx structure)

#### Wave 3: Encryption Overhaul (16-24 hours)

**FIX-007: CRYPT-001/006 - Replace Custom AES with OpenSSL**
- **Priority**: CRITICAL (side-channel vulnerability)
- **Time**: 16-20 hours
- **Files**: crypter.cpp:72-360, crypter.h:121
- **Complexity**: HIGH (replace entire encryption implementation)
- **Changes**:
  ```cpp
  // Remove lines 72-360 (custom AES implementation)
  // Add OpenSSL EVP API wrappers
  #include <openssl/evp.h>

  bool CCrypter::EncryptAES256(const std::vector<uint8_t>& plaintext,
                               std::vector<uint8_t>& ciphertext) {
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                        vchKey.data_ptr(), vchIV.data());
      // ... (full implementation in audit report)
      EVP_CIPHER_CTX_free(ctx);
  }
  ```
- **Testing**:
  - Encrypt/decrypt test with NIST AES-256-CBC test vectors
  - Benchmark: Compare performance (OpenSSL should be 5-10x faster with AES-NI)
  - Side-channel test: Measure timing variance (should be < 0.1%)
- **Breaking Changes**: None (output format identical to custom AES)
- **Dependencies**: OpenSSL library (already linked)

**FIX-008: CRYPT-007 - Add Authenticated Encryption**
- **Priority**: CRITICAL (padding oracle vulnerability)
- **Time**: 8-12 hours
- **Files**: crypter.cpp:377-454, wallet.h:63-66
- **Complexity**: MEDIUM (add HMAC layer)
- **Changes**:
  ```cpp
  // Option 1: Encrypt-then-MAC with HMAC-SHA3-256
  struct CEncryptedKey {
      std::vector<uint8_t> vchCryptedKey;
      std::vector<uint8_t> vchIV;
      std::vector<uint8_t> vchPubKey;
      std::vector<uint8_t> vchMAC;  // NEW: 32-byte HMAC
  };

  bool CCrypter::EncryptWithMAC(...) {
      // 1. Encrypt with AES-256-CBC
      EncryptAES256(plaintext, ciphertext);

      // 2. Compute HMAC over (IV || ciphertext)
      std::vector<uint8_t> data;
      data.insert(data.end(), vchIV.begin(), vchIV.end());
      data.insert(data.end(), ciphertext.begin(), ciphertext.end());

      mac.resize(32);
      HMAC_SHA3_256(vchKey.data_ptr(), vchKey.size(),
                    data.data(), data.size(), mac.data());
  }

  bool CCrypter::DecryptWithMAC(...) {
      // 1. Verify HMAC BEFORE decryption (prevents padding oracle)
      // 2. Only decrypt if MAC valid
  }
  ```
- **Testing**:
  - Tamper test: Modify ciphertext, verify MAC rejection
  - Padding oracle test: Send invalid padding, verify no timing leak
- **Breaking Changes**: ⚠️ ENCRYPTED KEY FORMAT CHANGE
- **Dependencies**: Must be done AFTER FIX-007 (OpenSSL migration)
- **Migration**: Re-encrypt all keys on first unlock after upgrade

**FIX-009: CRYPT-004 - Implement Memory Locking**
- **Priority**: CRITICAL (key leakage)
- **Time**: 8-12 hours
- **Files**: crypter.h:63-101, new file: util/secure_allocator.h
- **Complexity**: MEDIUM (new secure allocator class)
- **Changes**:
  ```cpp
  // util/secure_allocator.h
  template<typename T>
  class SecureAllocator {
  public:
      T* allocate(size_t n) {
          T* ptr = static_cast<T*>(::operator new(n * sizeof(T)));
          #ifdef _WIN32
              VirtualLock(ptr, n * sizeof(T));
          #else
              mlock(ptr, n * sizeof(T));
          #endif
          return ptr;
      }

      void deallocate(T* ptr, size_t n) {
          memory_cleanse(ptr, n * sizeof(T));
          #ifdef _WIN32
              VirtualUnlock(ptr, n * sizeof(T));
          #else
              munlock(ptr, n * sizeof(T));
          #endif
          ::operator delete(ptr);
      }
  };

  // crypter.h - Update CKeyingMaterial
  class CKeyingMaterial {
  private:
      std::vector<uint8_t, SecureAllocator<uint8_t>> data;  // Locked memory
  };
  ```
- **Testing**:
  - Verify mlock() success (requires CAP_IPC_LOCK on Linux)
  - Core dump test: Kill process, verify keys not in dump
  - Swap test: Fill memory, verify keys not swapped
- **Breaking Changes**: None (internal memory handling)
- **Dependencies**: None
- **Platform Notes**:
  - Linux: May require `ulimit -l unlimited` or CAP_IPC_LOCK
  - Windows: Requires SeLockMemoryPrivilege

**FIX-010: CRYPT-002 - IV Reuse Detection**
- **Priority**: CRITICAL
- **Time**: 4-6 hours
- **Files**: wallet.h (add usedIVs set), wallet.cpp:190, crypter.cpp:710
- **Complexity**: MEDIUM
- **Changes**:
  ```cpp
  // wallet.h - Add IV tracking
  class CWallet {
  private:
      std::set<std::vector<uint8_t>> usedIVs;
  public:
      bool GenerateUniqueIV(std::vector<uint8_t>& iv);
      void RegisterIV(const std::vector<uint8_t>& iv);
  };

  // wallet.cpp - Track IVs
  bool CWallet::GenerateUniqueIV(std::vector<uint8_t>& iv) {
      for (int attempts = 0; attempts < 10; attempts++) {
          if (!GenerateIV(iv)) return false;
          if (usedIVs.find(iv) == usedIVs.end()) {
              usedIVs.insert(iv);
              return true;
          }
      }
      return false;  // Collision after 10 attempts = RNG failure
  }

  // Load() - Populate usedIVs from all CEncryptedKey objects
  ```
- **Testing**:
  - Collision test: Generate 100k IVs, verify no duplicates
  - Load test: Create wallet with 1000 keys, verify usedIVs populated
- **Breaking Changes**: None (adds defense-in-depth)
- **Dependencies**: None

#### Wave 4: File Integrity & Consistency (8-12 hours)

**FIX-011: PERSIST-001 - Add File Integrity HMAC**
- **Priority**: CRITICAL (corruption detection)
- **Time**: 6-8 hours
- **Files**: wallet.cpp:820-1438 (Load/Save)
- **Complexity**: MEDIUM (file format change)
- **Changes**:
  ```cpp
  // New file format (DILWLT03):
  // [8 bytes] Magic: "DILWLT03"
  // [4 bytes] Version
  // [4 bytes] Flags
  // [32 bytes] HMAC-SHA3-256 (over rest of file)
  // [32 bytes] HMAC salt
  // [remaining] Wallet data

  // Save() - Compute HMAC
  bool CWallet::SaveUnlocked(...) {
      // 1. Write placeholder HMAC (zeros)
      // 2. Write all wallet data
      // 3. Seek back to HMAC position
      // 4. Compute HMAC over entire file (excluding HMAC field)
      // 5. Write actual HMAC
      file.seekp(HMAC_OFFSET);
      file.write(hmac.data(), 32);
  }

  // Load() - Verify HMAC
  bool CWallet::Load(...) {
      // 1. Read entire file
      // 2. Extract stored HMAC
      // 3. Recompute HMAC over file (excluding HMAC field)
      // 4. Constant-time compare
      // 5. Reject if mismatch
  }
  ```
- **Testing**:
  - Tamper test: Modify byte in wallet.dat, verify Load() fails
  - Bit flip test: Flip random bit, verify detection
- **Breaking Changes**: ⚠️ WALLET FILE FORMAT v3
- **Dependencies**: Coordinates with FIX-005 (WALLET-001 also changes format)
- **Migration**: Bump version to DILWLT03, support loading DILWLT02 (no HMAC)

**FIX-012: PERSIST-007 - Add Wallet Consistency Checks**
- **Priority**: CRITICAL
- **Time**: 6-8 hours
- **Files**: wallet.cpp:820-1183, new method ValidateConsistency()
- **Complexity**: MEDIUM
- **Changes**:
  ```cpp
  bool CWallet::ValidateConsistency() {
      // 1. Verify addresses match their keys
      for (const auto& [outpoint, wtx] : mapWalletTx) {
          CAddress reconstructed = GetAddressFromKey(wtx.vchPubKey);
          if (reconstructed != wtx.address) return false;
      }

      // 2. Verify HD paths sequential (no gaps > 20)
      if (fIsHDWallet) {
          // Check external chain gaps
          // Check internal chain gaps
      }

      // 3. Verify all tx addresses exist in wallet
      // 4. Verify default address exists
      // 5. Verify balance consistency

      return true;
  }

  // Call in Load() before atomic swap
  if (!ValidateConsistency()) {
      return false;  // Reject corrupted wallet
  }
  ```
- **Testing**:
  - Corrupt address test: Manually corrupt address byte, verify rejection
  - HD gap test: Create gap > 20, verify detection
- **Breaking Changes**: None (validation only)
- **Dependencies**: Should be done AFTER FIX-005 (new mapWalletTx structure)

#### Wave 5: RPC Access Control (12-16 hours)

**FIX-013: RPC-001 - Per-Method Rate Limiting**
- **Priority**: CRITICAL (wallet drainage)
- **Time**: 6-8 hours
- **Files**: rpc/ratelimiter.h, rpc/ratelimiter.cpp, rpc/server.cpp:392
- **Complexity**: MEDIUM (extend rate limiter)
- **Changes**:
  ```cpp
  // ratelimiter.h - Add per-method limits
  class CRateLimiter {
  private:
      std::map<std::string, std::map<std::string, TokenBucket>> m_methodBuckets;
      // IP -> method -> token bucket

  public:
      bool AllowMethodRequest(const std::string& ip, const std::string& method);
  };

  // Rate limits:
  static const std::map<std::string, RateLimit> METHOD_LIMITS = {
      {"sendtoaddress",         {1, 5}},   // 1 per 5 sec = 12/min
      {"sendrawtransaction",    {1, 5}},
      {"getnewaddress",         {10, 60}}, // 10 per minute
      {"exportmnemonic",        {1, 3600}}, // 1 per hour
      {"encryptwallet",         {1, 3600}},
      {"walletpassphrasechange",{5, 3600}}, // 5 per hour
  };

  // server.cpp - Check before execution
  if (method == "sendtoaddress") {
      if (!m_rateLimiter.AllowMethodRequest(clientIP, method)) {
          return RPCResponse::Error(-32099, "Transaction rate limit exceeded", id);
      }
  }
  ```
- **Testing**:
  - Burst test: Call sendtoaddress 20x in 1 second, verify only 1 succeeds
  - Sustained test: Call 1 per 5 sec for 1 minute, verify 12 succeed
- **Breaking Changes**: None (adds protection)
- **Dependencies**: None

**FIX-014: RPC-002 - Role-Based Access Control**
- **Priority**: CRITICAL (privilege escalation)
- **Time**: 12-16 hours
- **Files**: rpc/auth.h, rpc/auth.cpp, rpc/server.cpp, dilithion.conf
- **Complexity**: HIGH (new auth system)
- **Changes**:
  ```cpp
  // auth.h - Define permissions
  enum class RPCPermission : uint32_t {
      READ_BLOCKCHAIN = 0x01,
      READ_WALLET = 0x02,
      WRITE_WALLET = 0x04,
      ADMIN = 0x08,
      SENSITIVE = 0x10,  // exportmnemonic
  };

  struct RPCUser {
      std::string username;
      std::vector<uint8_t> passwordHash;
      uint32_t permissions;
  };

  // Map methods to required permissions
  static const std::map<std::string, uint32_t> METHOD_PERMISSIONS = {
      {"getblockcount",    RPCPermission::READ_BLOCKCHAIN},
      {"getbalance",       RPCPermission::READ_WALLET},
      {"sendtoaddress",    RPCPermission::WRITE_WALLET},
      {"stop",             RPCPermission::ADMIN},
      {"exportmnemonic",   RPCPermission::ADMIN | RPCPermission::SENSITIVE},
  };

  // server.cpp - Check permissions before execution
  bool HasPermission(const RPCUser& user, const std::string& method) {
      uint32_t required = METHOD_PERMISSIONS.at(method);
      return (user.permissions & required) == required;
  }

  // Config file support (dilithion.conf):
  // rpcauth=admin:hash:all
  // rpcauth=monitor:hash:read_blockchain,read_wallet
  // rpcauth=payments:hash:read_wallet,write_wallet
  ```
- **Testing**:
  - Read-only test: Create monitor user, verify getbalance works, sendtoaddress fails
  - Admin test: Verify only admin can call stop, exportmnemonic
- **Breaking Changes**: ⚠️ Config file format change (backward compatible)
- **Dependencies**: None
- **Migration**: Existing single rpcuser/rpcpassword gets "all" permissions

---

### PHASE 6.3: HIGH Fixes (14 issues, 60-80 hours)

**Summary**: Transaction building, fee validation, encryption parameters, file I/O

*(Full details for all 14 HIGH fixes omitted for brevity - similar format to above)*

**Key HIGH fixes**:
- WALLET-003: Add confirmation depth check (2-3 hours)
- WALLET-004/005: Integer overflow + dust prevention (4-6 hours)
- WALLET-009/013: Fee validation (6-8 hours)
- CRYPT-005: Increase PBKDF2 iterations (2 hours)
- PERSIST-002/003/005/008: File handling improvements (8-12 hours)
- RPC-003/004/005: RPC hardening (12-16 hours)

---

### PHASE 6.4: MEDIUM Fixes (11 issues, 30-40 hours)

**Summary**: UTXO locking, privacy improvements, backup validation

*(Full details omitted for brevity)*

---

### PHASE 6.5: LOW Fixes (3 issues, 8-12 hours)

**Summary**: Input/output limits, SIGHASH support, overflow checks

*(Full details omitted for brevity)*

---

## Testing Strategy

### Per-Fix Testing (During Implementation)
- Unit test for each fix (1 test minimum)
- Integration test if affects multiple components
- Regression test (ensure fix doesn't break existing functionality)

### Comprehensive Testing (After All Fixes)
1. **Functional Tests** (20+ tests)
   - Wallet creation, encryption, backup/restore
   - Transaction creation, signing, sending
   - HD address derivation
   - RPC API calls with different permission levels

2. **Security Tests** (15+ tests)
   - Timing attack tests (passphrase comparison)
   - Side-channel tests (AES constant-time verification)
   - File tampering tests (HMAC validation)
   - Permission tests (file permissions, RPC auth)
   - Rate limiting tests (global + per-method)

3. **Integration Tests** (10+ tests)
   - Full wallet lifecycle (create → fund → send → backup → restore)
   - Concurrent operations (multi-threaded wallet access)
   - Power failure simulation (fsync validation)
   - Migration tests (DILWLT02 → DILWLT03 upgrade)

4. **Fuzz Testing** (48-hour campaign)
   - Wallet file parser fuzzer
   - RPC JSON parser fuzzer
   - Transaction building fuzzer

---

## Migration & Compatibility

### Breaking Changes Summary

**Wallet File Format Change (DILWLT02 → DILWLT03)**:
- **Changes**:
  1. WALLET-001: mapWalletTx key structure (txid → COutPoint)
  2. PERSIST-001: Add HMAC integrity check
  3. CRYPT-007: Add MAC tags to encrypted keys

- **Migration Path**:
  ```cpp
  // Load() supports both formats
  if (magic == "DILWLT02") {
      // Old format: Load without HMAC validation
      // Convert mapWalletTx structure (txid → outpoint)
      // Re-encrypt keys with MAC tags on first unlock
      // Save as DILWLT03 format
  } else if (magic == "DILWLT03") {
      // New format: Verify HMAC, load new structure
  }
  ```

- **User Communication**:
  - On first run after upgrade: "Wallet upgraded to v3 format (adds integrity checks)"
  - Recommend backup before upgrade
  - One-way upgrade (cannot downgrade to DILWLT02)

**RPC Configuration Change**:
- Old: `rpcuser=admin` `rpcpassword=pass`
- New: `rpcauth=admin:hash:all` (supports multiple users with permissions)
- Migration: Convert old format to new format automatically on startup

---

## Risk Assessment

### High-Risk Fixes (Require Extra Testing)
1. **WALLET-001** - Data structure change, affects all wallet operations
2. **CRYPT-001/006** - Replacing entire encryption implementation
3. **PERSIST-001** - File format change
4. **RPC-002** - New auth system

### Low-Risk Fixes (Safe, Isolated)
1. **CRYPT-003** - Passphrase comparison (simple function swap)
2. **PERSIST-003/005** - File permissions (OS-level, doesn't affect wallet logic)
3. **PERSIST-002** - Add fsync (doesn't change file contents)

---

## Timeline Estimate

### Optimistic (140 hours, 1 engineer, 18 days @ 8hr/day)
- Week 1 (40h): CRITICAL fixes waves 1-3 (FIX-001 through FIX-010)
- Week 2 (40h): CRITICAL wave 4-5 + HIGH priority fixes (FIX-011 through FIX-020)
- Week 3 (40h): Remaining HIGH + MEDIUM fixes
- Week 4 (20h): LOW fixes + comprehensive testing

### Realistic (190 hours, 1 engineer, 24 days)
- Includes: Code review time, debugging, test writing, documentation

### Parallel (2 engineers, 12-14 days)
- Engineer A: CRITICAL encryption + file format fixes
- Engineer B: CRITICAL RPC + HIGH fixes
- Final 2 days: Integration testing together

---

## Success Criteria

### Phase 6 Complete When:
- ✅ All 39 fixes implemented
- ✅ All unit tests passing (1 test per fix minimum)
- ✅ Integration test suite passing (30+ tests)
- ✅ No new vulnerabilities introduced (code review)
- ✅ Wallet file migration working (DILWLT02 → DILWLT03)
- ✅ Backward compatibility maintained (can load old wallets)
- ✅ Performance benchmarks meet targets (encryption within 10% of baseline)

### Security Rating After Fixes:
- **Current**: C (5.5/10) - 10 critical vulnerabilities
- **Target**: A or A+ (9.0-9.5/10) - All critical/high issues resolved
- **Remaining**: Only minor issues (LOW severity, best practices)

---

## Next Steps

1. **Review this plan** - Confirm approach, priorities, timeline
2. **Start FIX-001** (CRYPT-003) - Quick win, high impact
3. **Continue sequentially** - Complete each fix before next
4. **Update progress** - Mark fixes complete in this document

**Ready to begin Phase 6.2 implementation** ✅

---

**Last Updated**: 2025-11-10
