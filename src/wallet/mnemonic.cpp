// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/mnemonic.h>
#include <wallet/bip39_wordlist.h>
#include <crypto/sha3.h>
#include <crypto/pbkdf2_sha3.h>
#include <cstring>
#include <algorithm>
#include <sstream>

// Include Dilithium randombytes for secure random generation
extern "C" {
    #include <randombytes.h>
}

// BIP39 word count mappings
static const size_t VALID_ENTROPY_BITS[] = {128, 160, 192, 224, 256};
static const size_t VALID_WORD_COUNTS[] = {12, 15, 18, 21, 24};
static const size_t NUM_VALID_LENGTHS = 5;

// BIP39 wordlist size
static const size_t WORDLIST_SIZE = 2048;

// Helper: Check if entropy bits is valid
static bool IsValidEntropyBits(size_t entropy_bits) {
    for (size_t i = 0; i < NUM_VALID_LENGTHS; i++) {
        if (VALID_ENTROPY_BITS[i] == entropy_bits) {
            return true;
        }
    }
    return false;
}

// Helper: Check if word count is valid
static bool IsValidWordCount(size_t word_count) {
    for (size_t i = 0; i < NUM_VALID_LENGTHS; i++) {
        if (VALID_WORD_COUNTS[i] == word_count) {
            return true;
        }
    }
    return false;
}

size_t CMnemonic::GetWordCount(size_t entropy_bits) {
    if (!IsValidEntropyBits(entropy_bits)) {
        return 0;
    }
    // Each word represents 11 bits
    // Total bits = entropy_bits + (entropy_bits / 32) checksum bits
    size_t total_bits = entropy_bits + (entropy_bits / 32);
    return total_bits / 11;
}

size_t CMnemonic::GetEntropyBits(size_t word_count) {
    if (!IsValidWordCount(word_count)) {
        return 0;
    }
    // Total bits = word_count * 11
    // entropy_bits + (entropy_bits / 32) = total_bits
    // entropy_bits * 33/32 = total_bits
    // entropy_bits = total_bits * 32/33
    size_t total_bits = word_count * 11;
    return (total_bits * 32) / 33;
}

void CMnemonic::SplitWords(const std::string& mnemonic, std::vector<std::string>& words) {
    words.clear();
    std::istringstream iss(mnemonic);
    std::string word;
    while (iss >> word) {
        // Convert to lowercase for case-insensitive matching
        std::transform(word.begin(), word.end(), word.begin(), ::tolower);
        words.push_back(word);
    }
}

int CMnemonic::FindWordIndex(const std::string& word) {
    // Binary search in sorted wordlist
    for (size_t i = 0; i < WORDLIST_SIZE; i++) {
        if (word == BIP39_WORDLIST_ENGLISH[i]) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

uint8_t CMnemonic::ComputeChecksum(const uint8_t* entropy, size_t entropy_len,
                                    size_t checksum_bits) {
    // Hash entropy with SHA3-256
    uint8_t hash[32];
    SHA3_256(entropy, entropy_len, hash);

    // Extract first checksum_bits bits from hash
    // Return as right-aligned uint8_t (checksum_bits <= 8)
    uint8_t checksum = 0;
    for (size_t i = 0; i < checksum_bits; i++) {
        size_t byte_index = i / 8;
        size_t bit_index = 7 - (i % 8);
        uint8_t bit = (hash[byte_index] >> bit_index) & 1;
        checksum = (checksum << 1) | bit;
    }

    return checksum;
}

void CMnemonic::IndicesToMnemonic(const std::vector<uint16_t>& indices, std::string& mnemonic) {
    mnemonic.clear();
    for (size_t i = 0; i < indices.size(); i++) {
        if (i > 0) {
            mnemonic += " ";
        }
        mnemonic += BIP39_WORDLIST_ENGLISH[indices[i]];
    }
}

bool CMnemonic::MnemonicToIndices(const std::vector<std::string>& words,
                                   std::vector<uint16_t>& indices) {
    indices.clear();
    indices.reserve(words.size());

    for (const auto& word : words) {
        int index = FindWordIndex(word);
        if (index < 0) {
            return false;  // Invalid word
        }
        indices.push_back(static_cast<uint16_t>(index));
    }

    return true;
}

bool CMnemonic::Generate(size_t entropy_bits, std::string& mnemonic) {
    // Validate entropy size
    if (!IsValidEntropyBits(entropy_bits)) {
        return false;
    }

    size_t entropy_bytes = entropy_bits / 8;
    uint8_t* entropy = new uint8_t[entropy_bytes];

    // Generate random entropy
    randombytes(entropy, entropy_bytes);

    // Convert to mnemonic
    bool result = FromEntropy(entropy, entropy_bytes, mnemonic);

    // Wipe entropy
    std::memset(entropy, 0, entropy_bytes);
    delete[] entropy;

    return result;
}

bool CMnemonic::FromEntropy(const uint8_t* entropy, size_t entropy_len, std::string& mnemonic) {
    // Validate entropy length
    size_t entropy_bits = entropy_len * 8;
    if (!IsValidEntropyBits(entropy_bits)) {
        return false;
    }

    // Calculate checksum
    size_t checksum_bits = entropy_bits / 32;
    uint8_t checksum = ComputeChecksum(entropy, entropy_len, checksum_bits);

    // Concatenate entropy and checksum into bits
    // Total bits = entropy_bits + checksum_bits
    size_t total_bits = entropy_bits + checksum_bits;
    std::vector<bool> bits(total_bits);

    // Add entropy bits
    for (size_t i = 0; i < entropy_bits; i++) {
        size_t byte_index = i / 8;
        size_t bit_index = 7 - (i % 8);
        bits[i] = (entropy[byte_index] >> bit_index) & 1;
    }

    // Add checksum bits
    for (size_t i = 0; i < checksum_bits; i++) {
        size_t bit_index = checksum_bits - 1 - i;
        bits[entropy_bits + i] = (checksum >> bit_index) & 1;
    }

    // Convert bits to 11-bit indices
    size_t word_count = total_bits / 11;
    std::vector<uint16_t> indices(word_count);

    for (size_t i = 0; i < word_count; i++) {
        uint16_t index = 0;
        for (size_t j = 0; j < 11; j++) {
            index = (index << 1) | (bits[i * 11 + j] ? 1 : 0);
        }
        indices[i] = index;
    }

    // Convert indices to mnemonic words
    IndicesToMnemonic(indices, mnemonic);

    return true;
}

bool CMnemonic::Validate(const std::string& mnemonic) {
    // Split into words
    std::vector<std::string> words;
    SplitWords(mnemonic, words);

    // Check word count
    if (!IsValidWordCount(words.size())) {
        return false;
    }

    // Convert words to indices
    std::vector<uint16_t> indices;
    if (!MnemonicToIndices(words, indices)) {
        return false;  // Invalid word in mnemonic
    }

    // Convert indices to bits
    size_t total_bits = words.size() * 11;
    std::vector<bool> bits(total_bits);

    for (size_t i = 0; i < indices.size(); i++) {
        uint16_t index = indices[i];
        for (size_t j = 0; j < 11; j++) {
            size_t bit_index = 10 - j;
            bits[i * 11 + j] = (index >> bit_index) & 1;
        }
    }

    // Split into entropy and checksum
    size_t entropy_bits = GetEntropyBits(words.size());
    size_t checksum_bits = total_bits - entropy_bits;

    // Extract entropy bytes
    size_t entropy_bytes = entropy_bits / 8;
    uint8_t* entropy = new uint8_t[entropy_bytes];
    std::memset(entropy, 0, entropy_bytes);

    for (size_t i = 0; i < entropy_bits; i++) {
        size_t byte_index = i / 8;
        size_t bit_index = 7 - (i % 8);
        if (bits[i]) {
            entropy[byte_index] |= (1 << bit_index);
        }
    }

    // Extract expected checksum
    uint8_t checksum_expected = 0;
    for (size_t i = 0; i < checksum_bits; i++) {
        checksum_expected = (checksum_expected << 1) | (bits[entropy_bits + i] ? 1 : 0);
    }

    // Calculate actual checksum
    uint8_t checksum_actual = ComputeChecksum(entropy, entropy_bytes, checksum_bits);

    // Wipe entropy
    std::memset(entropy, 0, entropy_bytes);
    delete[] entropy;

    // Verify checksum
    return checksum_expected == checksum_actual;
}

bool CMnemonic::ToEntropy(const std::string& mnemonic, std::vector<uint8_t>& entropy) {
    entropy.clear();

    // Validate mnemonic first
    if (!Validate(mnemonic)) {
        return false;
    }

    // Split into words
    std::vector<std::string> words;
    SplitWords(mnemonic, words);

    // Convert words to indices
    std::vector<uint16_t> indices;
    if (!MnemonicToIndices(words, indices)) {
        return false;
    }

    // Convert indices to bits
    size_t total_bits = words.size() * 11;
    std::vector<bool> bits(total_bits);

    for (size_t i = 0; i < indices.size(); i++) {
        uint16_t index = indices[i];
        for (size_t j = 0; j < 11; j++) {
            size_t bit_index = 10 - j;
            bits[i * 11 + j] = (index >> bit_index) & 1;
        }
    }

    // Extract entropy (excluding checksum)
    size_t entropy_bits = GetEntropyBits(words.size());
    size_t entropy_bytes = entropy_bits / 8;
    entropy.resize(entropy_bytes, 0);

    for (size_t i = 0; i < entropy_bits; i++) {
        size_t byte_index = i / 8;
        size_t bit_index = 7 - (i % 8);
        if (bits[i]) {
            entropy[byte_index] |= (1 << bit_index);
        }
    }

    return true;
}

bool CMnemonic::ToSeed(const std::string& mnemonic, const std::string& passphrase,
                       uint8_t seed[64]) {
    // Validate mnemonic
    if (!Validate(mnemonic)) {
        return false;
    }

    // Use BIP39_MnemonicToSeed from PBKDF2 module
    BIP39_MnemonicToSeed(mnemonic.c_str(), mnemonic.length(),
                         passphrase.c_str(), passphrase.length(),
                         seed);

    return true;
}
