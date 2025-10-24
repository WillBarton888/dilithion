// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_DILITHIUM_PARANOID_H
#define BITCOIN_CRYPTO_DILITHIUM_PARANOID_H

#include <crypto/dilithium/dilithium.h>
#include <cstddef>
#include <cstdint>

/**
 * DILITHIUM PARANOID SECURITY LAYER
 *
 * This module implements defense-in-depth security enhancements for the
 * Dilithium cryptographic wrapper. These features provide additional
 * protection beyond the standard implementation:
 *
 * - Canary-based memory protection (buffer overflow detection)
 * - Double-verification pattern (fault injection resistance)
 * - Secure memory clearing verification (compiler optimization protection)
 * - Runtime invariant checking (assertion-based validation)
 * - Enhanced entropy validation (statistical testing)
 *
 * WHEN TO USE:
 * - High-security environments
 * - When under potential attack
 * - When maximum assurance is required
 * - Production systems handling valuable assets
 *
 * PERFORMANCE IMPACT:
 * - ~5-10% slower than basic implementation
 * - Worth the tradeoff for critical security
 *
 * SECURITY LEVEL: "FORT KNOX" 🔐
 * - Multiple redundant security layers
 * - Fail-safe error handling
 * - Comprehensive validation
 * - Attack-resistant design
 */

namespace dilithium {
namespace paranoid {

//
// Secure Key Storage with Canary Protection
//

/**
 * SecureKeyBuffer: Protected secret key storage
 *
 * This structure provides canary-based memory protection for secret keys.
 * Canaries are placed before and after the key data to detect buffer
 * overflows, use-after-free, and other memory corruption issues.
 *
 * SECURITY PROPERTIES:
 * - Automatic canary validation
 * - Secure cleanup on destruction
 * - Detects memory corruption
 * - Fails safely on violation
 *
 * Example usage:
 * @code
 *   SecureKeyBuffer key_storage;
 *   if (dilithium::keypair(pk, key_storage.data()) == 0) {
 *       // Use key...
 *       if (!key_storage.verify_integrity()) {
 *           // CRITICAL: Memory corruption detected!
 *       }
 *   }
 *   // Automatic secure cleanup on scope exit
 * @endcode
 */
struct SecureKeyBuffer {
    // Magic canary values (detect buffer overflows)
    static constexpr uint64_t CANARY_BEFORE = 0xDEADBEEFCAFEBABEULL;
    static constexpr uint64_t CANARY_AFTER = 0xFEEDFACEDEADC0DEULL;

    uint64_t canary_before;
    unsigned char key_data[DILITHIUM_SECRETKEYBYTES];
    uint64_t canary_after;

    /**
     * Constructor: Initialize canaries and clear key data
     */
    SecureKeyBuffer();

    /**
     * Destructor: Verify canaries and securely clear key data
     *
     * If canaries are corrupted, this terminates the program
     * to prevent use of corrupted cryptographic keys.
     */
    ~SecureKeyBuffer();

    /**
     * Get pointer to key data
     */
    unsigned char* data() { return key_data; }
    const unsigned char* data() const { return key_data; }

    /**
     * Verify canary integrity
     *
     * @return true if canaries are intact, false if corrupted
     */
    bool verify_integrity() const;

    /**
     * Manually trigger secure cleanup
     *
     * Verifies canaries and clears key data.
     * Called automatically by destructor.
     */
    void secure_cleanup();

    // Prevent copying (security hazard)
    SecureKeyBuffer(const SecureKeyBuffer&) = delete;
    SecureKeyBuffer& operator=(const SecureKeyBuffer&) = delete;

    // Prevent moving (security hazard)
    SecureKeyBuffer(SecureKeyBuffer&&) = delete;
    SecureKeyBuffer& operator=(SecureKeyBuffer&&) = delete;
};

//
// Enhanced Cryptographic Operations
//

/**
 * Generate keypair with paranoid validation.
 *
 * This function adds additional security checks beyond the standard
 * keypair() function:
 * - Enhanced entropy validation (statistical testing)
 * - Multiple RNG quality checks
 * - Cross-verification of key generation
 * - Timing-attack resistance verification
 *
 * @param pk Output: public key
 * @param sk Output: secret key (recommend using SecureKeyBuffer)
 * @return 0 on success, negative on failure
 */
int keypair_paranoid(unsigned char* pk, unsigned char* sk)
    __attribute__((warn_unused_result))
    __attribute__((nonnull(1, 2)));

/**
 * Sign with paranoid validation.
 *
 * This function adds additional security checks:
 * - Pre-signing key validation
 * - Post-signing signature validation
 * - Signature uniqueness check (prevent duplicate signatures)
 * - Timing consistency verification
 *
 * @param sig Output: signature
 * @param siglen Output: signature length
 * @param msg Input: message to sign
 * @param msglen Input: message length
 * @param sk Input: secret key
 * @return 0 on success, negative on failure
 */
int sign_paranoid(unsigned char* sig, size_t* siglen,
                  const unsigned char* msg, size_t msglen,
                  const unsigned char* sk)
    __attribute__((warn_unused_result))
    __attribute__((nonnull(1, 2, 5)));

/**
 * Verify with double-verification (fault injection resistance).
 *
 * This function verifies the signature TWICE independently and compares
 * results. This protects against fault injection attacks where an
 * attacker causes a single bit flip to bypass verification.
 *
 * SECURITY: This is the most paranoid verification mode.
 * - Performs verification twice
 * - Compares results
 * - Detects fault injection
 * - Constant-time for both verifications
 *
 * @param sig Input: signature
 * @param siglen Input: signature length
 * @param msg Input: message
 * @param msglen Input: message length
 * @param pk Input: public key
 * @return 0 if VALID, non-zero if INVALID or fault detected
 */
int verify_paranoid(const unsigned char* sig, size_t siglen,
                    const unsigned char* msg, size_t msglen,
                    const unsigned char* pk)
    __attribute__((warn_unused_result))
    __attribute__((nonnull(1, 3, 5)));

//
// Memory Safety Utilities
//

/**
 * Secure memory clearing with verification.
 *
 * This function clears memory AND verifies it was actually cleared.
 * This prevents compiler optimizations from removing the clearing.
 *
 * If the memory is not cleared after memory_cleanse(), this function
 * will terminate the program (fail-safe behavior).
 *
 * @param ptr Pointer to memory to clear
 * @param len Length of memory to clear
 */
void secure_cleanse_verify(void* ptr, size_t len)
    __attribute__((nonnull(1)));

/**
 * Validate memory buffer is non-zero.
 *
 * Used to verify that cryptographic operations actually wrote data
 * and didn't leave buffers as all zeros.
 *
 * @param buffer Buffer to check
 * @param len Length of buffer
 * @return true if buffer contains non-zero data
 */
bool buffer_is_nonzero(const unsigned char* buffer, size_t len)
    __attribute__((nonnull(1)));

//
// Entropy Validation
//

/**
 * Enhanced entropy validation.
 *
 * Performs statistical tests on RNG output to detect weak entropy:
 * - Chi-squared test
 * - Frequency test
 * - Runs test
 * - All-zero/all-one detection
 *
 * @return true if entropy appears healthy, false if suspect
 */
bool validate_entropy_enhanced();

/**
 * Continuous entropy monitoring.
 *
 * Checks RNG quality before every cryptographic operation.
 * Maintains statistics on entropy quality over time.
 *
 * @return true if RNG is healthy, false if degraded
 */
bool monitor_entropy_continuous();

//
// Runtime Invariant Checking
//

#ifdef ENABLE_CRYPTO_PARANOIA

/**
 * CRYPTO_ASSERT: Runtime assertion for cryptographic invariants.
 *
 * When ENABLE_CRYPTO_PARANOIA is defined, this macro checks critical
 * invariants at runtime. If an invariant is violated, the program
 * terminates immediately (fail-safe behavior).
 *
 * This catches programming errors and attack attempts.
 *
 * Example:
 * @code
 *   CRYPTO_ASSERT(siglen == DILITHIUM_BYTES, "Invalid signature length");
 * @endcode
 */
#define CRYPTO_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            crypto_assert_fail(__FILE__, __LINE__, #cond, msg); \
        } \
    } while(0)

/**
 * Internal function called when assertion fails.
 * Do not call directly - use CRYPTO_ASSERT macro.
 */
[[noreturn]] void crypto_assert_fail(const char* file, int line,
                                     const char* condition, const char* msg);

#else
// In release builds, CRYPTO_ASSERT compiles to nothing
#define CRYPTO_ASSERT(cond, msg) ((void)0)
#endif

//
// Security Statistics
//

/**
 * Cryptographic operation statistics.
 *
 * Tracks security-relevant metrics for monitoring and auditing.
 */
struct SecurityStats {
    uint64_t keypairs_generated;    // Total keypairs generated
    uint64_t signatures_created;    // Total signatures created
    uint64_t signatures_verified;   // Total signatures verified
    uint64_t verification_failures; // Total verification failures
    uint64_t entropy_checks;        // Total entropy checks performed
    uint64_t entropy_failures;      // Total entropy check failures
    uint64_t memory_corruptions;    // Total memory corruption detections
    uint64_t fault_injections;      // Total fault injection detections
};

/**
 * Get current security statistics.
 *
 * @return Current statistics snapshot
 */
SecurityStats get_security_stats();

/**
 * Reset security statistics.
 *
 * Clears all counters (for testing/development).
 */
void reset_security_stats();

} // namespace paranoid
} // namespace dilithium

#endif // BITCOIN_CRYPTO_DILITHIUM_PARANOID_H
