# Phase 6.5 - LOW Priority Issues TODO

**Date Created:** 2025-11-10
**Status:** Deferred (non-critical documentation improvements)

---

## Overview

These 3 LOW priority issues from Phase 6.5 are **documentation and code comment improvements only**. They have **zero functional or security impact** and can be addressed during code review or documentation sprint.

All CRITICAL, HIGH, and MEDIUM issues (12 total) have been fixed.

---

## WL-013 (LOW): Missing Documentation for Edge Case Handling

**Severity:** LOW (Documentation only)
**File:** `src/wallet/hd_derivation.cpp`
**Issue:** Edge case handling in key derivation not fully documented

**Current State:**
- Code handles edge cases correctly
- Missing detailed comments explaining behavior

**Required Fix:**
```cpp
// Add detailed comments explaining:
// - What happens when derivation index overflows
// - How hardened vs non-hardened paths are handled
// - Edge cases in fingerprint calculation
```

**Effort:** 15 minutes
**Impact:** Improves code maintainability, no functional change

---

## WL-014 (LOW): Code Comments Could Be More Detailed

**Severity:** LOW (Documentation only)
**File:** `src/wallet/crypter.cpp`
**Issue:** Some cryptographic operations lack detailed inline comments

**Current State:**
- Cryptographic code is correct and secure
- Some functions have brief comments that could be expanded

**Required Fix:**
```cpp
// Expand comments in:
// 1. AES encryption/decryption loops (explain block cipher mode)
// 2. PBKDF2 iteration logic (explain why specific round count)
// 3. Key derivation steps (reference relevant RFCs/standards)
```

**Effort:** 30 minutes
**Impact:** Helps future developers understand cryptographic design decisions

---

## WL-015 (LOW): Function Parameter Descriptions Incomplete

**Severity:** LOW (Documentation only)
**File:** `src/wallet/wallet.h`
**Issue:** Some function declarations lack complete @param documentation

**Current State:**
- Functions work correctly
- Doxygen comments missing or incomplete for some parameters

**Required Fix:**
```cpp
// Complete Doxygen documentation:
/**
 * @param timeout Auto-lock timeout in seconds (0 = never)
 * @param stakingOnly If true, unlock only for staking operations
 * @return true on success, false if passphrase wrong or rate limited
 */
bool Unlock(const std::string& passphrase, int64_t timeout = 0);
```

**Effort:** 20 minutes
**Impact:** Better IDE tooltips and generated documentation

---

## When to Address

**Option 1: During Code Review**
- Reviewer can flag incomplete documentation
- Developer adds comments as part of PR cleanup

**Option 2: Documentation Sprint**
- Schedule dedicated time for documentation improvements
- Address all LOW priority docs issues across all phases

**Option 3: Never**
- These are "nice to have" not "must have"
- Code works perfectly without them
- Only address if time permits

---

## Recommendation

**Defer indefinitely.** These issues:
- Have zero security impact
- Have zero functional impact
- Only improve developer experience slightly
- Not worth delaying Phase 7 or other security work

Mark as "closed-wontfix" or "documentation-backlog" and move on.

---

## NET-016 (LOW): Information Disclosure in Error Messages

**Severity:** LOW (Information disclosure)
**Files:** Multiple (net.cpp, peers.cpp, async_broadcaster.cpp)
**Issue:** Error messages leak peer IDs, internal state, and connection details

**Current State:**
- Error messages contain detailed debugging information
- Could help attackers map network topology
- Minimal practical attack value

**Required Fix:**
```cpp
// Sanitize error messages to remove:
// - Internal peer IDs
// - Connection state details
// - Network topology hints
// Use generic error messages for production
```

**Effort:** 30 minutes
**Impact:** Reduces information leakage to attackers

---

## NET-017 (LOW): Missing Null Terminator Validation

**Severity:** LOW (Validation gap)
**File:** `src/net/protocol.h:82`
**Issue:** Command validation doesn't check for internal null bytes in command strings

**Current State:**
- Validates command length (12 bytes)
- Doesn't check for embedded null terminators
- Commands could contain "version\0xxxx"

**Required Fix:**
```cpp
// Add validation to reject commands with internal nulls:
for (size_t i = 0; i < command.size(); i++) {
    if (command[i] == '\0' && i < command.size() - 1) {
        return false;  // Embedded null
    }
}
```

**Effort:** 10 minutes
**Impact:** Closes minor protocol validation gap

---

**Total Estimated Effort:** 105 minutes (65 wallet + 40 network)
**Total Issues:** 5 (3 wallet + 2 network)
**Priority:** Very Low
**Blocking:** Nothing
