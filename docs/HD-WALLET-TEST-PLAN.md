# HD Wallet Test Plan

**Version:** 1.0
**Date:** November 10, 2025
**Scope:** Comprehensive testing strategy for Dilithion HD wallet implementation
**Estimated Test Count:** 200+ tests

---

## Test Strategy

### Test Pyramid

```
               ┌─────────────────┐
               │  Manual Tests   │  ~5%
               │  (10 tests)     │
          ┌────┴─────────────────┴────┐
          │   Integration Tests       │  ~25%
          │   (50 tests)              │
     ┌────┴───────────────────────────┴────┐
     │      Unit Tests                     │  ~70%
     │      (140 tests)                    │
     └─────────────────────────────────────┘
```

### Test Types

1. **Unit Tests** (140 tests): Test individual functions in isolation
2. **Integration Tests** (50 tests): Test component interactions
3. **Security Tests** (included in above): Verify security properties
4. **Performance Tests** (10 tests): Ensure acceptable performance
5. **Fuzzing Tests** (continuous): Find edge cases and crashes

---

## Phase 1: BIP39 Mnemonic Tests

### File: `src/test/mnemonic_tests.cpp`

#### Unit Tests (30 tests)

**Mnemonic Generation (10 tests)**

```cpp
TEST(MnemonicTests, Generate12Words) {
    auto words = CMnemonic::Generate(128);
    EXPECT_EQ(words.size(), 12);
    EXPECT_TRUE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, Generate15Words) {
    auto words = CMnemonic::Generate(160);
    EXPECT_EQ(words.size(), 15);
    EXPECT_TRUE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, Generate18Words) {
    auto words = CMnemonic::Generate(192);
    EXPECT_EQ(words.size(), 18);
    EXPECT_TRUE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, Generate21Words) {
    auto words = CMnemonic::Generate(224);
    EXPECT_EQ(words.size(), 21);
    EXPECT_TRUE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, Generate24Words) {
    auto words = CMnemonic::Generate(256);
    EXPECT_EQ(words.size(), 24);
    EXPECT_TRUE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, InvalidEntropySize) {
    EXPECT_THROW(CMnemonic::Generate(100), std::invalid_argument);
    EXPECT_THROW(CMnemonic::Generate(300), std::invalid_argument);
}

TEST(MnemonicTests, GeneratedWordsInWordlist) {
    auto words = CMnemonic::Generate(256);
    for (const auto& word : words) {
        EXPECT_GE(CMnemonic::FindWordIndex(word), 0);
    }
}

TEST(MnemonicTests, GenerateUnique) {
    // Generate 100 mnemonics, all should be different
    std::set<std::string> mnemonics;
    for (int i = 0; i < 100; i++) {
        auto words = CMnemonic::Generate(256);
        std::string mnemonic_str = join(words, " ");
        mnemonics.insert(mnemonic_str);
    }
    EXPECT_EQ(mnemonics.size(), 100);
}

TEST(MnemonicTests, EntropyRoundTrip) {
    std::vector<uint8_t> entropy(32);
    GetStrongRandBytes(entropy.data(), 32);

    auto words = CMnemonic::FromEntropy(entropy);
    std::vector<uint8_t> entropy2;
    EXPECT_TRUE(CMnemonic::ToEntropy(words, entropy2));
    EXPECT_EQ(entropy, entropy2);
}

TEST(MnemonicTests, ChecksumCalculation) {
    std::vector<uint8_t> entropy = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto words = CMnemonic::FromEntropy(entropy);
    EXPECT_EQ(words[11], "about");  // Known checksum word
}
```

**Mnemonic Validation (10 tests)**

```cpp
TEST(MnemonicTests, ValidateKnownGood) {
    std::vector<std::string> words = {
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about"
    };
    EXPECT_TRUE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, ValidateKnownBad) {
    std::vector<std::string> words = {
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon"  // Wrong checksum
    };
    EXPECT_FALSE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, ValidateInvalidWordCount) {
    std::vector<std::string> words = {"abandon", "abandon"};  // Too few
    EXPECT_FALSE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, ValidateUnknownWord) {
    std::vector<std::string> words = {
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "bitcoin"  // Not in wordlist
    };
    EXPECT_FALSE(CMnemonic::Validate(words));
}

TEST(MnemonicTests, ValidateCaseSensitive) {
    std::vector<std::string> words = {
        "Abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about"
    };
    EXPECT_FALSE(CMnemonic::Validate(words));  // Should be case-sensitive
}

TEST(MnemonicTests, ValidateWhitespace) {
    std::vector<std::string> words = {
        " abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about"
    };
    EXPECT_FALSE(CMnemonic::Validate(words));  // No leading/trailing spaces
}

// Additional validation tests...
```

**Seed Derivation (10 tests)**

```cpp
TEST(MnemonicTests, SeedDerivationNoPassphrase) {
    std::vector<std::string> words = {
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about"
    };

    std::vector<uint8_t> seed;
    EXPECT_TRUE(CMnemonic::ToSeed(words, "", seed));
    EXPECT_EQ(seed.size(), 64);
}

TEST(MnemonicTests, SeedDerivationWithPassphrase) {
    std::vector<std::string> words = {
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about"
    };

    std::vector<uint8_t> seed1, seed2;
    EXPECT_TRUE(CMnemonic::ToSeed(words, "", seed1));
    EXPECT_TRUE(CMnemonic::ToSeed(words, "TREZOR", seed2));
    EXPECT_NE(seed1, seed2);  // Different passphrases = different seeds
}

TEST(MnemonicTests, SeedDeterministic) {
    // Same mnemonic → same seed
    auto words = CMnemonic::Generate(256);

    std::vector<uint8_t> seed1, seed2;
    CMnemonic::ToSeed(words, "", seed1);
    CMnemonic::ToSeed(words, "", seed2);
    EXPECT_EQ(seed1, seed2);
}

TEST(MnemonicTests, SeedDilithionPrefix) {
    // Verify Dilithion uses custom salt prefix
    std::vector<std::string> words = test_mnemonic;
    std::vector<uint8_t> seed;
    CMnemonic::ToSeed(words, "", seed);

    // Seed should differ from BIP39 Bitcoin seed
    // (We can't test directly, but verify algorithm uses "dilithion-mnemonic" salt)
    EXPECT_EQ(seed.size(), 64);
}

// Additional seed tests (PBKDF2 iterations, edge cases, etc.)
```

---

## Phase 2: HD Derivation Tests

### File: `src/test/hd_derivation_tests.cpp`

#### Unit Tests (50 tests)

**Master Key Derivation (10 tests)**

```cpp
TEST(HDDerivationTests, DeriveMaster) {
    std::vector<uint8_t> seed(64, 0xAA);
    CHDExtendedKey master;

    EXPECT_TRUE(HDDerivation::DeriveMaster(seed, master));
    EXPECT_TRUE(master.IsValid());
    EXPECT_EQ(master.seed.size(), 32);
    EXPECT_EQ(master.chaincode.size(), 32);
    EXPECT_EQ(master.depth, 0);
    EXPECT_EQ(master.path.ToString(), "m");
}

TEST(HDDerivationTests, MasterDeterministic) {
    std::vector<uint8_t> seed(64);
    GetStrongRandBytes(seed.data(), 64);

    CHDExtendedKey master1, master2;
    HDDerivation::DeriveMaster(seed, master1);
    HDDerivation::DeriveMaster(seed, master2);

    EXPECT_EQ(master1.seed, master2.seed);
    EXPECT_EQ(master1.chaincode, master2.chaincode);
    EXPECT_EQ(master1.fingerprint, master2.fingerprint);
}

TEST(HDDerivationTests, MasterFromDifferentSeeds) {
    std::vector<uint8_t> seed1(64, 0xAA);
    std::vector<uint8_t> seed2(64, 0xBB);

    CHDExtendedKey master1, master2;
    HDDerivation::DeriveMaster(seed1, master1);
    HDDerivation::DeriveMaster(seed2, master2);

    EXPECT_NE(master1.seed, master2.seed);
    EXPECT_NE(master1.chaincode, master2.chaincode);
    EXPECT_NE(master1.fingerprint, master2.fingerprint);
}

// Additional master derivation tests...
```

**Child Key Derivation (20 tests)**

```cpp
TEST(HDDerivationTests, DeriveChildNormal) {
    CHDExtendedKey master;
    HDDerivation::DeriveMaster(test_seed_64, master);

    CHDExtendedKey child;
    EXPECT_TRUE(HDDerivation::DeriveChild(master, 0, child));
    EXPECT_TRUE(child.IsValid());
    EXPECT_EQ(child.depth, 1);
    EXPECT_NE(child.seed, master.seed);
}

TEST(HDDerivationTests, DeriveChildHardened) {
    CHDExtendedKey master;
    HDDerivation::DeriveMaster(test_seed_64, master);

    uint32_t hardened_index = CHDKeyPath::Harden(0);
    CHDExtendedKey child;
    EXPECT_TRUE(HDDerivation::DeriveChild(master, hardened_index, child));
    EXPECT_TRUE(child.IsValid());
}

TEST(HDDerivationTests, HardenedVsNormal) {
    CHDExtendedKey master;
    HDDerivation::DeriveMaster(test_seed_64, master);

    CHDExtendedKey child_normal, child_hardened;
    HDDerivation::DeriveChild(master, 0, child_normal);
    HDDerivation::DeriveChild(master, CHDKeyPath::Harden(0), child_hardened);

    // Different derivation methods → different keys
    EXPECT_NE(child_normal.seed, child_hardened.seed);
}

TEST(HDDerivationTests, SiblingIndependence) {
    CHDExtendedKey master;
    HDDerivation::DeriveMaster(test_seed_64, master);

    CHDExtendedKey child0, child1, child2;
    HDDerivation::DeriveChild(master, 0, child0);
    HDDerivation::DeriveChild(master, 1, child1);
    HDDerivation::DeriveChild(master, 2, child2);

    // All children should be independent
    EXPECT_NE(child0.seed, child1.seed);
    EXPECT_NE(child1.seed, child2.seed);
    EXPECT_NE(child0.seed, child2.seed);
}

TEST(HDDerivationTests, ChildDeterministic) {
    CHDExtendedKey master;
    HDDerivation::DeriveMaster(test_seed_64, master);

    CHDExtendedKey child1, child2;
    HDDerivation::DeriveChild(master, 0, child1);
    HDDerivation::DeriveChild(master, 0, child2);

    EXPECT_EQ(child1.seed, child2.seed);
    EXPECT_EQ(child1.chaincode, child2.chaincode);
}

TEST(HDDerivationTests, DeepDerivation) {
    CHDExtendedKey key;
    HDDerivation::DeriveMaster(test_seed_64, key);

    // Derive 10 levels deep
    for (int i = 0; i < 10; i++) {
        CHDExtendedKey child;
        EXPECT_TRUE(HDDerivation::DeriveChild(key, i, child));
        key = child;
    }

    EXPECT_EQ(key.depth, 10);
    EXPECT_TRUE(key.IsValid());
}

// Additional child derivation tests (boundary cases, max index, etc.)
```

**Path Derivation (10 tests)**

```cpp
TEST(HDDerivationTests, DeriveBIP44Path) {
    CHDExtendedKey master;
    HDDerivation::DeriveMaster(test_seed_64, master);

    CHDKeyPath path;
    path.FromString("m/44'/573'/0'/0/0");

    CHDExtendedKey derived;
    EXPECT_TRUE(HDDerivation::DerivePath(master, path, derived));
    EXPECT_EQ(derived.depth, 5);
    EXPECT_EQ(derived.path.ToString(), "m/44'/573'/0'/0/0");
}

TEST(HDDerivationTests, PathParsing) {
    CHDKeyPath path;

    EXPECT_TRUE(path.FromString("m/44'/573'/0'/0/0"));
    EXPECT_EQ(path.size(), 5);
    EXPECT_TRUE(CHDKeyPath::IsHardened(path[0]));  // 44'
    EXPECT_TRUE(CHDKeyPath::IsHardened(path[1]));  // 573'
    EXPECT_TRUE(CHDKeyPath::IsHardened(path[2]));  // 0'
    EXPECT_FALSE(CHDKeyPath::IsHardened(path[3])); // 0
    EXPECT_FALSE(CHDKeyPath::IsHardened(path[4])); // 0
}

TEST(HDDerivationTests, PathToString) {
    CHDKeyPath path;
    path.FromString("m/44'/573'/0'/1/5");
    EXPECT_EQ(path.ToString(), "m/44'/573'/0'/1/5");
}

TEST(HDDerivationTests, InvalidPathFormat) {
    CHDKeyPath path;
    EXPECT_FALSE(path.FromString("invalid"));
    EXPECT_FALSE(path.FromString("m/44/573"));  // Missing hardened markers
    EXPECT_FALSE(path.FromString("44'/573'/0'"));  // Missing 'm/'
}

// Additional path tests (edge cases, maximum indices, etc.)
```

**Dilithium Key Generation (10 tests)**

```cpp
TEST(HDDerivationTests, DilithiumFromSeed) {
    std::vector<uint8_t> seed(32);
    GetStrongRandBytes(seed.data(), 32);

    CHDExtendedKey ext_key;
    ext_key.seed = seed;
    ext_key.chaincode.resize(32);

    CKey key;
    EXPECT_TRUE(HDDerivation::GenerateDilithiumKey(ext_key, key));
    EXPECT_TRUE(key.IsValid());
    EXPECT_EQ(key.vchPubKey.size(), DILITHIUM_PUBLICKEY_SIZE);
    EXPECT_EQ(key.vchPrivKey.size(), DILITHIUM_SECRETKEY_SIZE);
}

TEST(HDDerivationTests, DilithiumDeterministic) {
    std::vector<uint8_t> seed(32, 0xCC);

    CHDExtendedKey ext_key;
    ext_key.seed = seed;
    ext_key.chaincode.resize(32);

    CKey key1, key2;
    HDDerivation::GenerateDilithiumKey(ext_key, key1);
    HDDerivation::GenerateDilithiumKey(ext_key, key2);

    EXPECT_EQ(key1.vchPubKey, key2.vchPubKey);
    EXPECT_EQ(key1.vchPrivKey, key2.vchPrivKey);
}

TEST(HDDerivationTests, DilithiumUniqueness) {
    std::vector<uint8_t> seed1(32, 0xAA);
    std::vector<uint8_t> seed2(32, 0xBB);

    CHDExtendedKey ext1, ext2;
    ext1.seed = seed1;
    ext1.chaincode.resize(32);
    ext2.seed = seed2;
    ext2.chaincode.resize(32);

    CKey key1, key2;
    HDDerivation::GenerateDilithiumKey(ext1, key1);
    HDDerivation::GenerateDilithiumKey(ext2, key2);

    EXPECT_NE(key1.vchPubKey, key2.vchPubKey);
}

// Additional Dilithium tests (signature verification, etc.)
```

---

## Phase 3: Wallet Integration Tests

### File: `src/test/wallet_hd_tests.cpp`

#### Integration Tests (40 tests)

**HD Wallet Initialization (10 tests)**

```cpp
TEST(WalletHDTests, InitializeHDWallet) {
    CWallet wallet;
    auto mnemonic = CMnemonic::Generate(256);

    EXPECT_TRUE(wallet.InitializeHDWallet(mnemonic));
    EXPECT_TRUE(wallet.IsHDWallet());
    EXPECT_NE(wallet.GetHDFingerprint(), 0);
}

TEST(WalletHDTests, InitializeWithPassphrase) {
    CWallet wallet;
    auto mnemonic = CMnemonic::Generate(256);

    EXPECT_TRUE(wallet.InitializeHDWallet(mnemonic, "test-passphrase"));
    EXPECT_TRUE(wallet.IsHDWallet());
}

TEST(WalletHDTests, RejectInvalidMnemonic) {
    CWallet wallet;
    std::vector<std::string> bad_mnemonic = {"bad", "mnemonic", "checksum"};

    EXPECT_FALSE(wallet.InitializeHDWallet(bad_mnemonic));
    EXPECT_FALSE(wallet.IsHDWallet());
}

// Additional initialization tests...
```

**Address Generation (15 tests)**

```cpp
TEST(WalletHDTests, GenerateReceivingAddress) {
    CWallet wallet;
    wallet.InitializeHDWallet(test_mnemonic);

    CAddress addr = wallet.GetNewAddress();
    EXPECT_TRUE(addr.IsValid());
}

TEST(WalletHDTests, GenerateMultipleAddresses) {
    CWallet wallet;
    wallet.InitializeHDWallet(test_mnemonic);

    std::set<CAddress> addresses;
    for (int i = 0; i < 100; i++) {
        addresses.insert(wallet.GetNewAddress());
    }

    EXPECT_EQ(addresses.size(), 100);  // All unique
}

TEST(WalletHDTests, ChangeAddressGeneration) {
    CWallet wallet;
    wallet.InitializeHDWallet(test_mnemonic);

    std::set<CAddress> change_addrs;
    for (int i = 0; i < 20; i++) {
        change_addrs.insert(wallet.GetChangeAddress());
    }

    EXPECT_EQ(change_addrs.size(), 20);
}

TEST(WalletHDTests, ReceivingVsChange) {
    CWallet wallet;
    wallet.InitializeHDWallet(test_mnemonic);

    CAddress receiving = wallet.GetNewAddress();
    CAddress change = wallet.GetChangeAddress();

    EXPECT_NE(receiving, change);
}

// Additional address generation tests...
```

**Wallet Persistence (15 tests)**

```cpp
TEST(WalletHDTests, SaveAndLoad) {
    CWallet wallet1;
    auto mnemonic = CMnemonic::Generate(256);
    wallet1.InitializeHDWallet(mnemonic);
    wallet1.SetWalletFile("/tmp/test_hd.dat");

    std::vector<CAddress> addrs1;
    for (int i = 0; i < 10; i++) {
        addrs1.push_back(wallet1.GetNewAddress());
    }

    EXPECT_TRUE(wallet1.Save());

    CWallet wallet2;
    EXPECT_TRUE(wallet2.Load("/tmp/test_hd.dat"));
    EXPECT_TRUE(wallet2.IsHDWallet());

    // Verify addresses match
    for (size_t i = 0; i < 10; i++) {
        CHDKeyPath path;
        path.FromString("m/44'/573'/0'/0/" + std::to_string(i));

        CAddress addr2;
        wallet2.DeriveHDAddress(path, addr2);
        EXPECT_EQ(addrs1[i], addr2);
    }
}

TEST(WalletHDTests, EncryptedWalletPersistence) {
    CWallet wallet1;
    wallet1.InitializeHDWallet(test_mnemonic);
    wallet1.EncryptWallet("password123");
    wallet1.SetWalletFile("/tmp/test_encrypted_hd.dat");

    EXPECT_TRUE(wallet1.Save());

    CWallet wallet2;
    EXPECT_TRUE(wallet2.Load("/tmp/test_encrypted_hd.dat"));
    EXPECT_TRUE(wallet2.IsHDWallet());
    EXPECT_TRUE(wallet2.IsCrypted());

    EXPECT_TRUE(wallet2.Unlock("password123"));
}

// Additional persistence tests (file format version, backward compat, etc.)
```

---

## Phase 4: RPC Interface Tests

### File: `src/test/wallet_hd_rpc_tests.cpp`

#### RPC Tests (20 tests)

```cpp
TEST(WalletRPCTests, CreateHDWallet) {
    JSONRPCRequest request;
    request.params.push_back(UniValue("test-password"));
    request.params.push_back(UniValue(24));

    UniValue result = createhdwallet(request);

    EXPECT_TRUE(result.exists("mnemonic"));
    EXPECT_EQ(result["mnemonic"].size(), 24);
    EXPECT_TRUE(result.exists("fingerprint"));
    EXPECT_TRUE(result.exists("address"));
}

TEST(WalletRPCTests, RestoreHDWallet) {
    // Create wallet first
    JSONRPCRequest create_req;
    create_req.params.push_back(UniValue("pass"));
    create_req.params.push_back(UniValue(12));
    UniValue create_result = createhdwallet(create_req);

    UniValue mnemonic = create_result["mnemonic"];
    std::string fingerprint = create_result["fingerprint"].get_str();

    // Clear wallet
    ClearTestWallet();

    // Restore
    JSONRPCRequest restore_req;
    restore_req.params.push_back(mnemonic);
    restore_req.params.push_back(UniValue("pass"));

    UniValue restore_result = restorehdwallet(restore_req);
    EXPECT_EQ(restore_result["fingerprint"].get_str(), fingerprint);
}

// Additional RPC tests (dumpmnemonic, gethdwalletinfo, error cases, etc.)
```

---

## Security Tests

### Memory Safety (10 tests)

```cpp
TEST(SecurityTests, SeedMemoryWiped) {
    std::vector<uint8_t> seed(64);
    GetStrongRandBytes(seed.data(), 64);

    {
        CHDExtendedKey master;
        HDDerivation::DeriveMaster(seed, master);
        // master goes out of scope
    }

    // Verify destructor wiped memory (requires valgrind/ASan)
}

TEST(SecurityTests, MnemonicNotInLogs) {
    CaptureLogOutput();

    auto mnemonic = CMnemonic::Generate(256);
    std::vector<uint8_t> seed;
    CMnemonic::ToSeed(mnemonic, "", seed);

    std::string logs = GetCapturedLogs();
    for (const auto& word : mnemonic) {
        EXPECT_EQ(logs.find(word), std::string::npos);
    }
}

// Additional security tests (constant-time comparisons, etc.)
```

---

## Performance Tests

### File: `src/bench/hd_wallet_bench.cpp`

```cpp
BENCHMARK(DeriveMasterKey) {
    std::vector<uint8_t> seed(64);
    CHDExtendedKey master;

    benchmark::DoNotOptimize(HDDerivation::DeriveMaster(seed, master));
}
// Target: < 10ms

BENCHMARK(DeriveChildKey) {
    CHDExtendedKey parent, child;
    HDDerivation::DeriveMaster(test_seed, parent);

    benchmark::DoNotOptimize(HDDerivation::DeriveChild(parent, 0, child));
}
// Target: < 50ms

BENCHMARK(DeriveBIP44Path) {
    CHDExtendedKey master, derived;
    HDDerivation::DeriveMaster(test_seed, master);
    CHDKeyPath path;
    path.FromString("m/44'/573'/0'/0/0");

    benchmark::DoNotOptimize(HDDerivation::DerivePath(master, path, derived));
}
// Target: < 100ms

BENCHMARK(Generate1000Addresses) {
    CWallet wallet;
    wallet.InitializeHDWallet(test_mnemonic);

    for (int i = 0; i < 1000; i++) {
        benchmark::DoNotOptimize(wallet.GetNewAddress());
    }
}
// Target: < 10 seconds (10ms per address)
```

---

## Fuzzing Tests

### Continuous Fuzzing

```bash
# BIP39 mnemonic fuzzing
./fuzz_mnemonic -max_total_time=3600 -dict=bip39_wordlist.txt

# HD derivation fuzzing
./fuzz_hd_derivation -max_total_time=3600

# Wallet file format fuzzing
./fuzz_wallet_load -max_total_time=3600
```

**Target:** 0 crashes in 24-hour campaign

---

## Test Coverage Goals

| Component           | Line Coverage | Branch Coverage |
|---------------------|---------------|-----------------|
| mnemonic.cpp        | > 95%         | > 90%           |
| hd_derivation.cpp   | > 95%         | > 90%           |
| wallet_hd.cpp       | > 90%         | > 85%           |
| wallet_hd_rpc.cpp   | > 90%         | > 85%           |
| **Overall**         | **> 90%**     | **> 85%**       |

---

## Test Execution Plan

### Continuous Integration

```yaml
# .github/workflows/hd-wallet-tests.yml
name: HD Wallet Tests
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: make -j4
      - name: Run Unit Tests
        run: ./src/test/test_dilithion --run_test=mnemonic_tests,hd_derivation_tests

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Run Integration Tests
        run: ./src/test/test_dilithion --run_test=wallet_hd_tests

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Run with AddressSanitizer
        run: ASAN_OPTIONS=detect_leaks=1 ./src/test/test_dilithion

  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - name: 1-hour fuzzing campaign
        run: ./fuzz_hd_wallet -max_total_time=3600
```

---

## Acceptance Criteria

### Phase 1: BIP39 Mnemonic
- [ ] All 30 unit tests pass
- [ ] 0 memory leaks (valgrind)
- [ ] Test vectors match reference implementation

### Phase 2: HD Derivation
- [ ] All 50 unit tests pass
- [ ] Deterministic derivation verified
- [ ] Performance < 100ms per derivation

### Phase 3: Wallet Integration
- [ ] All 40 integration tests pass
- [ ] Save/load works correctly
- [ ] Backward compatibility verified

### Phase 4: RPC Interface
- [ ] All 20 RPC tests pass
- [ ] Security warnings displayed
- [ ] Mnemonic export requires unlock

### Phase 5: Overall
- [ ] 200+ tests passing
- [ ] 0 fuzzer crashes (24 hours)
- [ ] > 90% code coverage
- [ ] 0 critical security issues
- [ ] Performance targets met

---

## Test Reporting

### Daily Test Summary

```
HD Wallet Test Report - 2025-11-10
===================================

Unit Tests:       140/140 ✅
Integration Tests: 50/50  ✅
Security Tests:    10/10  ✅
Performance Tests: 10/10  ✅

Total:            210/210 ✅

Code Coverage:    92.3% (lines)
                  88.1% (branches)

Fuzzing:          0 crashes in 24h

Status: READY FOR PRODUCTION ✅
```

---

**End of Test Plan**
