// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_PASSPHRASE_VALIDATOR_H
#define DILITHION_WALLET_PASSPHRASE_VALIDATOR_H

#include <string>
#include <vector>

/**
 * Passphrase validation result
 */
struct PassphraseValidationResult {
    bool is_valid;
    int strength_score;  // 0-100
    std::string error_message;
    std::vector<std::string> warnings;

    PassphraseValidationResult()
        : is_valid(false), strength_score(0) {}

    PassphraseValidationResult(bool valid, int score, const std::string& error)
        : is_valid(valid), strength_score(score), error_message(error) {}
};

/**
 * Passphrase Validator
 *
 * Enforces strong passphrase requirements for wallet encryption:
 * - Minimum 16 characters (WL-009: increased from 12)
 * - Must contain uppercase, lowercase, digit, and special character
 * - Rejects common passwords
 * - Detects repeating patterns
 * - Calculates strength score (0-100)
 * - Minimum score of 60 required (WL-009: increased from 40)
 *
 * Usage:
 *   PassphraseValidator validator;
 *   auto result = validator.Validate("MyStr0ng!P@ssw0rd");
 *   if (!result.is_valid) {
 *       std::cerr << "Error: " << result.error_message << std::endl;
 *   }
 */
class PassphraseValidator {
private:
    // WL-009 FIX: Strengthen passphrase requirements
    // Increased from 12 to 16 characters (NIST SP 800-63B recommends 15+ for user-chosen passwords)
    // Increased score from 40 to 60 (reject weak passphrases that barely meet character requirements)
    static const size_t MIN_LENGTH = 16;
    static const size_t RECOMMENDED_LENGTH = 20;
    static const int MIN_ACCEPTABLE_SCORE = 60;  // Minimum score to be considered valid

    // Common passwords list (top 100 most common)
    static const std::vector<std::string> COMMON_PASSWORDS;

    /**
     * Check if passphrase contains uppercase letters
     */
    bool HasUppercase(const std::string& passphrase) const;

    /**
     * Check if passphrase contains lowercase letters
     */
    bool HasLowercase(const std::string& passphrase) const;

    /**
     * Check if passphrase contains digits
     */
    bool HasDigit(const std::string& passphrase) const;

    /**
     * Check if passphrase contains special characters
     */
    bool HasSpecialChar(const std::string& passphrase) const;

    /**
     * Check if passphrase is a common password
     */
    bool IsCommonPassword(const std::string& passphrase) const;

    /**
     * Check for repeating characters (e.g., "aaa", "111")
     */
    bool HasRepeatingChars(const std::string& passphrase) const;

    /**
     * Check for sequential characters (e.g., "abc", "123")
     */
    bool HasSequentialChars(const std::string& passphrase) const;

    /**
     * Calculate character diversity score (0-25)
     */
    int CalculateDiversityScore(const std::string& passphrase) const;

    /**
     * Calculate length score (0-25)
     */
    int CalculateLengthScore(const std::string& passphrase) const;

    /**
     * Calculate complexity score (0-30)
     */
    int CalculateComplexityScore(const std::string& passphrase) const;

    /**
     * Calculate entropy score (0-20)
     */
    int CalculateEntropyScore(const std::string& passphrase) const;

public:
    /**
     * Validate a passphrase against all requirements
     *
     * @param passphrase The passphrase to validate
     * @return Validation result with score and error/warning messages
     */
    PassphraseValidationResult Validate(const std::string& passphrase) const;

    /**
     * Get passphrase strength description
     *
     * @param score Strength score (0-100)
     * @return Human-readable strength description
     */
    static std::string GetStrengthDescription(int score);
};

#endif // DILITHION_WALLET_PASSPHRASE_VALIDATOR_H
