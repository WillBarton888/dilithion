// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/passphrase_validator.h>
#include <rpc/auth.h>  // FIX-001 (CRYPT-003): Constant-time comparison
#include <algorithm>
#include <cctype>
#include <set>
#include <cmath>

// Top 100 most common passwords (security best practice: reject these)
const std::vector<std::string> PassphraseValidator::COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "password1", "123123", "1234567890", "000000", "abc123", "qwerty",
    "iloveyou", "welcome", "monkey", "dragon", "master", "sunshine",
    "princess", "football", "baseball", "shadow", "michael", "jordan",
    "111111", "jennifer", "pussy", "trustno1", "batman", "thomas",
    "robert", "jessica", "matthew", "charlie", "andrew", "letmein",
    "qwerty123", "admin", "welcome123", "solo", "love", "passw0rd",
    "password123", "123qwe", "zxcvbnm", "p@ssw0rd", "pass@word1",
    "superman", "hello", "starwars", "whatever", "computer", "internet",
    "Secret", "Password!", "P@ssword", "Pass123", "test123", "default",
    "admin123", "root", "toor", "123321", "654321", "696969", "qwertyuiop",
    "Login", "Password1!", "changeme", "temp123", "Welcome1", "Security",
    "Access", "test", "demo", "guest", "user", "ninja", "killer",
    "pepper", "cheese", "letmein123", "charlie1", "freedom", "qazwsx",
    "mustang", "maggie", "hunter", "soccer", "jordan23", "harley",
    "ranger", "buster", "cookie", "tigger", "summer", "flower",
    "ginger", "silver", "purple", "orange", "biteme", "pepper1"
};

bool PassphraseValidator::HasUppercase(const std::string& passphrase) const {
    return std::any_of(passphrase.begin(), passphrase.end(),
                      [](char c) { return std::isupper(static_cast<unsigned char>(c)); });
}

bool PassphraseValidator::HasLowercase(const std::string& passphrase) const {
    return std::any_of(passphrase.begin(), passphrase.end(),
                      [](char c) { return std::islower(static_cast<unsigned char>(c)); });
}

bool PassphraseValidator::HasDigit(const std::string& passphrase) const {
    return std::any_of(passphrase.begin(), passphrase.end(),
                      [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
}

bool PassphraseValidator::HasSpecialChar(const std::string& passphrase) const {
    return std::any_of(passphrase.begin(), passphrase.end(),
                      [](char c) {
                          unsigned char uc = static_cast<unsigned char>(c);
                          return !std::isalnum(uc) && !std::isspace(uc);
                      });
}

bool PassphraseValidator::IsCommonPassword(const std::string& passphrase) const {
    // Convert to lowercase for case-insensitive comparison
    std::string lower_passphrase = passphrase;
    std::transform(lower_passphrase.begin(), lower_passphrase.end(),
                  lower_passphrase.begin(),
                  [](unsigned char c) { return std::tolower(c); });

    // FIX-001 (CRYPT-003): Check if it matches any common password
    // Use constant-time comparison for defense-in-depth
    for (const auto& common : COMMON_PASSWORDS) {
        // Skip if lengths don't match (optimization, lengths are public)
        if (lower_passphrase.length() != common.length()) {
            continue;
        }

        // Constant-time comparison
        if (RPCAuth::SecureCompare(
                (const uint8_t*)lower_passphrase.data(),
                (const uint8_t*)common.data(),
                common.length())) {
            return true;
        }
    }

    // Also check if common password is a substring
    for (const auto& common : COMMON_PASSWORDS) {
        if (common.length() >= 6 && lower_passphrase.find(common) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool PassphraseValidator::HasRepeatingChars(const std::string& passphrase) const {
    // Check for 3+ consecutive repeating characters
    for (size_t i = 0; i < passphrase.length() - 2; ++i) {
        if (passphrase[i] == passphrase[i + 1] &&
            passphrase[i] == passphrase[i + 2]) {
            return true;
        }
    }
    return false;
}

bool PassphraseValidator::HasSequentialChars(const std::string& passphrase) const {
    // Check for 3+ sequential characters (ascending or descending)
    for (size_t i = 0; i < passphrase.length() - 2; ++i) {
        char c1 = passphrase[i];
        char c2 = passphrase[i + 1];
        char c3 = passphrase[i + 2];

        // Check ascending sequence
        if (c2 == c1 + 1 && c3 == c2 + 1) {
            return true;
        }

        // Check descending sequence
        if (c2 == c1 - 1 && c3 == c2 - 1) {
            return true;
        }
    }
    return false;
}

int PassphraseValidator::CalculateDiversityScore(const std::string& passphrase) const {
    int score = 0;

    // Award points for each character type present
    if (HasUppercase(passphrase)) score += 6;
    if (HasLowercase(passphrase)) score += 6;
    if (HasDigit(passphrase)) score += 6;
    if (HasSpecialChar(passphrase)) score += 7;

    return std::min(score, 25);
}

int PassphraseValidator::CalculateLengthScore(const std::string& passphrase) const {
    size_t len = passphrase.length();

    if (len < MIN_LENGTH) {
        return 0;  // Too short
    }

    // Linear scoring: 12 chars = 10 points, 16+ chars = 25 points
    if (len >= RECOMMENDED_LENGTH) {
        return 25;
    }

    // Interpolate between 10 and 25 for lengths 12-15
    return 10 + ((len - MIN_LENGTH) * 15) / (RECOMMENDED_LENGTH - MIN_LENGTH);
}

int PassphraseValidator::CalculateComplexityScore(const std::string& passphrase) const {
    int score = 30;  // Start at max

    // Penalize for weaknesses
    if (HasRepeatingChars(passphrase)) {
        score -= 10;
    }

    if (HasSequentialChars(passphrase)) {
        score -= 10;
    }

    // Check for keyboard patterns (basic detection)
    std::string lower = passphrase;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                  [](unsigned char c) { return std::tolower(c); });

    // Common keyboard patterns
    const std::vector<std::string> patterns = {
        "qwerty", "asdfgh", "zxcvbn", "12345", "qazwsx"
    };

    for (const auto& pattern : patterns) {
        if (lower.find(pattern) != std::string::npos) {
            score -= 5;
            break;
        }
    }

    return std::max(0, score);
}

int PassphraseValidator::CalculateEntropyScore(const std::string& passphrase) const {
    // Calculate character set size
    std::set<char> unique_chars(passphrase.begin(), passphrase.end());
    size_t charset_size = 0;

    if (HasLowercase(passphrase)) charset_size += 26;
    if (HasUppercase(passphrase)) charset_size += 26;
    if (HasDigit(passphrase)) charset_size += 10;
    if (HasSpecialChar(passphrase)) charset_size += 32;  // Estimate

    // Calculate entropy: log2(charset_size^length)
    // Simplified: entropy = length * log2(charset_size)
    double entropy = passphrase.length() * (std::log2(charset_size));

    // Good entropy is around 60-80+ bits
    // Scale to 0-20 points
    int score = static_cast<int>((entropy / 80.0) * 20.0);

    return std::min(score, 20);
}

PassphraseValidationResult PassphraseValidator::Validate(const std::string& passphrase) const {
    PassphraseValidationResult result;

    // Check minimum length
    if (passphrase.length() < MIN_LENGTH) {
        result.is_valid = false;
        result.strength_score = 0;
        result.error_message = "Passphrase must be at least " +
                              std::to_string(MIN_LENGTH) + " characters long";
        return result;
    }

    // Check character type requirements
    bool has_upper = HasUppercase(passphrase);
    bool has_lower = HasLowercase(passphrase);
    bool has_digit = HasDigit(passphrase);
    bool has_special = HasSpecialChar(passphrase);

    if (!has_upper || !has_lower || !has_digit || !has_special) {
        result.is_valid = false;
        result.strength_score = 0;

        result.error_message = "Passphrase must contain: ";
        std::vector<std::string> missing;
        if (!has_upper) missing.push_back("uppercase letter");
        if (!has_lower) missing.push_back("lowercase letter");
        if (!has_digit) missing.push_back("digit");
        if (!has_special) missing.push_back("special character");

        for (size_t i = 0; i < missing.size(); ++i) {
            if (i > 0) {
                result.error_message += (i == missing.size() - 1) ? " and " : ", ";
            }
            result.error_message += missing[i];
        }

        return result;
    }

    // Check for common passwords
    if (IsCommonPassword(passphrase)) {
        result.is_valid = false;
        result.strength_score = 0;
        result.error_message = "This passphrase is too common and easily guessable. "
                              "Please choose a more unique passphrase";
        return result;
    }

    // Calculate strength score (0-100)
    int diversity_score = CalculateDiversityScore(passphrase);
    int length_score = CalculateLengthScore(passphrase);
    int complexity_score = CalculateComplexityScore(passphrase);
    int entropy_score = CalculateEntropyScore(passphrase);

    result.strength_score = diversity_score + length_score + complexity_score + entropy_score;

    // Check if score meets minimum threshold
    if (result.strength_score < MIN_ACCEPTABLE_SCORE) {
        result.is_valid = false;
        result.error_message = "Passphrase is too weak (strength score: " +
                              std::to_string(result.strength_score) + "/100). " +
                              "Please use a longer, more complex passphrase";
        return result;
    }

    // Passphrase is valid, but provide warnings for improvements
    result.is_valid = true;

    if (HasRepeatingChars(passphrase)) {
        result.warnings.push_back("Contains repeating characters (reduces strength)");
    }

    if (HasSequentialChars(passphrase)) {
        result.warnings.push_back("Contains sequential characters (reduces strength)");
    }

    if (passphrase.length() < RECOMMENDED_LENGTH) {
        result.warnings.push_back("Consider using " + std::to_string(RECOMMENDED_LENGTH) +
                                 "+ characters for better security");
    }

    if (result.strength_score < 60) {
        result.warnings.push_back("Passphrase strength is moderate. Consider making it more complex");
    }

    return result;
}

std::string PassphraseValidator::GetStrengthDescription(int score) {
    if (score < 40) {
        return "Weak";
    } else if (score < 60) {
        return "Moderate";
    } else if (score < 80) {
        return "Strong";
    } else {
        return "Very Strong";
    }
}
