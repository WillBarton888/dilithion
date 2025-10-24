# Standard: Security-Critical Code

## Overview
Guidelines for writing, reviewing, and modifying security-critical code in the Dilithion project.

## Definition

**Security-critical code** is any code where bugs could result in:
- Loss of funds
- Private key compromise
- Consensus failures
- Network splits
- Cryptographic vulnerabilities

## Security-Critical Areas

### 🔴 Tier 1: Cryptographic Operations
**Files:**
- `src/crypto/dilithium/*`
- `src/key.cpp` / `src/key.h`
- `src/pubkey.cpp` / `src/pubkey.h`
- `src/random.cpp` / `src/random.h`

**Requirements:**
- Constant-time operations mandatory
- Memory must be securely cleared
- No side-channel leaks
- Test against official vectors
- External cryptographer review required

### 🔴 Tier 1: Consensus Rules
**Files:**
- `src/validation.cpp`
- `src/consensus/*`
- `src/script/interpreter.cpp`
- `src/pow.cpp`

**Requirements:**
- Exhaustive testing
- Behavior must match specification exactly
- Any change requires extensive review
- Testnet validation before mainnet

### 🟡 Tier 2: Transaction Handling
**Files:**
- `src/primitives/transaction.h`
- `src/script/sign.cpp`
- `src/wallet/*`

**Requirements:**
- Comprehensive unit tests
- Memory safety checks
- Edge case handling
- Code review required

### 🟡 Tier 2: Network Protocol
**Files:**
- `src/net_processing.cpp`
- `src/protocol.h`
- `src/net.cpp`

**Requirements:**
- DoS attack resistance
- Input validation
- Resource limits
- Integration testing

## Coding Standards for Security-Critical Code

### 1. Constant-Time Operations

**Rule:** Cryptographic operations must not leak timing information.

**Bad:**
```cpp
bool VerifySignature(const uint8_t* sig, const uint8_t* msg, const uint8_t* pk) {
    for (size_t i = 0; i < SIGNATURE_SIZE; i++) {
        if (sig[i] != expected[i]) {
            return false;  // TIMING LEAK: returns early
        }
    }
    return true;
}
```

**Good:**
```cpp
bool VerifySignature(const uint8_t* sig, const uint8_t* msg, const uint8_t* pk) {
    uint8_t diff = 0;
    for (size_t i = 0; i < SIGNATURE_SIZE; i++) {
        diff |= sig[i] ^ expected[i];  // Constant-time compare
    }
    return diff == 0;
}
```

### 2. Memory Clearing

**Rule:** Sensitive data must be cleared from memory.

**Bad:**
```cpp
void SignTransaction() {
    uint8_t privkey[SECRET_KEY_SIZE];
    LoadPrivateKey(privkey);

    // Use private key...

    // MEMORY LEAK: privkey not cleared
}
```

**Good:**
```cpp
void SignTransaction() {
    uint8_t privkey[SECRET_KEY_SIZE];
    LoadPrivateKey(privkey);

    // Use private key...

    // Clear sensitive data
    memory_cleanse(privkey, SECRET_KEY_SIZE);
}
```

### 3. No Secret-Dependent Branches

**Rule:** Don't branch on secret data.

**Bad:**
```cpp
if (privkey[0] > 128) {  // SIDE-CHANNEL: branch on secret
    // Do something...
}
```

**Good:**
```cpp
uint8_t mask = (privkey[0] > 128) ? 0xFF : 0x00;  // Constant-time
result = (result & ~mask) | (alternative & mask);
```

### 4. Input Validation

**Rule:** Validate all inputs exhaustively.

**Bad:**
```cpp
void ProcessTransaction(const Transaction& tx) {
    // Assume tx is valid
    for (auto& input : tx.inputs) {
        ProcessInput(input);  // DANGER: no validation
    }
}
```

**Good:**
```cpp
bool ProcessTransaction(const Transaction& tx) {
    // Validate first
    if (tx.inputs.empty()) return false;
    if (tx.inputs.size() > MAX_TX_INPUTS) return false;

    for (const auto& input : tx.inputs) {
        if (!ValidateInput(input)) return false;
    }

    // Now process
    for (const auto& input : tx.inputs) {
        ProcessInput(input);
    }
    return true;
}
```

### 5. Error Handling

**Rule:** Handle all errors securely.

**Bad:**
```cpp
bool DecryptWallet(const char* password) {
    if (strlen(password) < 8) {
        throw std::runtime_error("Password too short");  // LEAK: reveals info
    }
    // ...
}
```

**Good:**
```cpp
bool DecryptWallet(const char* password) {
    // Constant-time length check
    bool valid = (strlen(password) >= 8);

    // Always perform full operation (constant-time)
    bool result = PerformDecryption(password);

    // Only return success if both checks pass
    return valid && result;
}
```

## Review Checklist

Before approving security-critical code:

### Cryptographic Code
- [ ] Uses constant-time operations
- [ ] No branching on secrets
- [ ] Memory is properly cleared
- [ ] No cache side-channels
- [ ] No timing side-channels
- [ ] Validated against test vectors
- [ ] Reviewed by cryptographer

### Consensus Code
- [ ] Behavior matches specification
- [ ] All edge cases handled
- [ ] Extensive unit tests
- [ ] Functional tests added
- [ ] Testnet validation performed
- [ ] Multiple reviewers approved

### General Security
- [ ] All inputs validated
- [ ] Buffer overflows prevented
- [ ] Integer overflows checked
- [ ] No use-after-free
- [ ] No uninitialized memory
- [ ] Resource limits enforced
- [ ] Error handling is safe

## Testing Requirements

### Unit Tests
```cpp
// Test ALL edge cases
BOOST_AUTO_TEST_CASE(test_signature_verification) {
    // Test valid signature
    BOOST_CHECK(VerifySignature(valid_sig, msg, pk));

    // Test invalid signature
    BOOST_CHECK(!VerifySignature(invalid_sig, msg, pk));

    // Test wrong message
    BOOST_CHECK(!VerifySignature(sig, wrong_msg, pk));

    // Test wrong public key
    BOOST_CHECK(!VerifySignature(sig, msg, wrong_pk));

    // Test corrupted signature (all bytes)
    for (size_t i = 0; i < SIGNATURE_SIZE; i++) {
        uint8_t corrupted[SIGNATURE_SIZE];
        memcpy(corrupted, valid_sig, SIGNATURE_SIZE);
        corrupted[i] ^= 0xFF;
        BOOST_CHECK(!VerifySignature(corrupted, msg, pk));
    }
}
```

### Fuzz Testing
```cpp
// Fuzz critical functions
void FuzzSignatureVerification(const uint8_t* data, size_t size) {
    if (size < PUBLIC_KEY_SIZE + SIGNATURE_SIZE) return;

    const uint8_t* pk = data;
    const uint8_t* sig = data + PUBLIC_KEY_SIZE;
    const uint8_t* msg = data + PUBLIC_KEY_SIZE + SIGNATURE_SIZE;
    size_t msglen = size - PUBLIC_KEY_SIZE - SIGNATURE_SIZE;

    // Should not crash
    VerifySignature(sig, msg, msglen, pk);
}
```

### Side-Channel Testing
```bash
# Test for timing variations
valgrind --tool=cachegrind ./test_signature 1000

# Analyze cache access patterns
# Should be constant regardless of input
```

## Documentation Requirements

All security-critical code must be documented:

```cpp
/**
 * Verify a Dilithium signature in constant time.
 *
 * This function MUST complete in constant time regardless of
 * the signature, message, or public key contents to prevent
 * timing side-channel attacks.
 *
 * @param sig Signature to verify (must be SIGNATURE_SIZE bytes)
 * @param msg Message that was signed
 * @param msglen Length of message
 * @param pk Public key (must be PUBLIC_KEY_SIZE bytes)
 * @return true if signature is valid, false otherwise
 *
 * Security assumptions:
 * - Dilithium reference implementation is correct
 * - Random number generator is cryptographically secure
 * - Memory clearing prevents key recovery
 *
 * @note This function is consensus-critical. Any changes must
 *       be extensively tested and reviewed.
 */
bool VerifySignature(const uint8_t* sig,
                     const uint8_t* msg, size_t msglen,
                     const uint8_t* pk);
```

## Common Vulnerabilities to Avoid

### 1. Timing Attacks
- Early returns based on secret data
- Variable-time comparisons
- Secret-dependent loops

### 2. Side-Channel Leaks
- Cache timing attacks
- Branch prediction leaks
- Memory access patterns

### 3. Memory Safety
- Buffer overflows
- Use-after-free
- Uninitialized memory
- Memory leaks of secrets

### 4. Integer Issues
- Integer overflows
- Integer underflows
- Type confusion

### 5. Consensus Bugs
- Non-deterministic behavior
- Floating-point arithmetic
- Platform-dependent code
- Undefined behavior

## Tools

### Static Analysis
```bash
# Use clang static analyzer
scan-build make

# Use cppcheck
cppcheck --enable=all src/
```

### Dynamic Analysis
```bash
# Memory safety
valgrind --leak-check=full ./test_bitcoin

# Undefined behavior
export UBSAN_OPTIONS=print_stacktrace=1
./configure CXXFLAGS="-fsanitize=undefined"
make && make check

# Address sanitizer
./configure CXXFLAGS="-fsanitize=address"
make && make check
```

### Fuzzing
```bash
# AFL fuzzing
afl-fuzz -i testcases -o findings ./target
```

## Escalation

### When to Escalate

Immediately escalate if you discover:
- Timing side-channel
- Memory leak of private keys
- Consensus rule violation
- Remote code execution
- DoS vulnerability
- Any critical security issue

### Who to Escalate To

1. **Crypto Specialist** - For cryptographic issues
2. **Security Auditor** - For security vulnerabilities
3. **Project Lead** - For consensus changes
4. **External Experts** - For critical discoveries

## References

- [Bitcoin Core Security Process](https://github.com/bitcoin/bitcoin/blob/master/SECURITY.md)
- [NIST Post-Quantum Guidelines](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Timing Attack Prevention](https://www.bearssl.org/ctmul.html)
- [Memory Safety in C++](https://isocpp.github.io/CppCoreGuidelines/)

## Success Criteria

Code meets security standards when:
- ✅ All security checks pass
- ✅ No side-channels detected
- ✅ Comprehensive tests written
- ✅ Multiple reviewers approved
- ✅ Documentation complete
- ✅ Fuzz testing performed
- ✅ Static analysis clean

---

**Remember:** When in doubt about security, ask for help. It's better to be slow and secure than fast and vulnerable.
