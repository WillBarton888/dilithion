// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_MNEMONIC_H
#define DILITHION_WALLET_MNEMONIC_H

#include <stdint.h>
#include <string>
#include <vector>

/**
 * BIP39 Mnemonic Phrase Implementation
 *
 * BIP39 defines a method for converting entropy into a mnemonic phrase
 * (sequence of words from a predefined wordlist) and deriving a seed
 * from that phrase using PBKDF2.
 *
 * Word counts and entropy:
 *   12 words = 128 bits entropy + 4 bits checksum = 132 bits
 *   15 words = 160 bits entropy + 5 bits checksum = 165 bits
 *   18 words = 192 bits entropy + 6 bits checksum = 198 bits
 *   21 words = 224 bits entropy + 7 bits checksum = 231 bits
 *   24 words = 256 bits entropy + 8 bits checksum = 264 bits
 *
 * Checksum: First (entropy_bits / 32) bits of SHA256(entropy)
 * Each word represents 11 bits (2048 = 2^11 words in wordlist)
 */

class CMnemonic {
public:
    /**
     * Generate a new mnemonic phrase from random entropy
     *
     * @param entropy_bits Number of entropy bits (must be 128, 160, 192, 224, or 256)
     * @param mnemonic Output string with space-separated words
     * @return true on success, false on failure
     */
    static bool Generate(size_t entropy_bits, std::string& mnemonic);

    /**
     * Generate a new mnemonic phrase from provided entropy
     *
     * @param entropy Entropy bytes (length must be 16, 20, 24, 28, or 32 bytes)
     * @param entropy_len Length of entropy in bytes
     * @param mnemonic Output string with space-separated words
     * @return true on success, false on failure
     */
    static bool FromEntropy(const uint8_t* entropy, size_t entropy_len, std::string& mnemonic);

    /**
     * Validate a mnemonic phrase
     *
     * Checks:
     * - Word count is valid (12, 15, 18, 21, or 24)
     * - All words are in the BIP39 wordlist
     * - Checksum is correct
     *
     * @param mnemonic Space-separated mnemonic words
     * @return true if valid, false otherwise
     */
    static bool Validate(const std::string& mnemonic);

    /**
     * Convert mnemonic phrase to entropy
     *
     * Extracts the entropy bytes from a mnemonic phrase and verifies the checksum.
     *
     * @param mnemonic Space-separated mnemonic words
     * @param entropy Output buffer for entropy bytes
     * @return true on success, false if mnemonic is invalid
     */
    static bool ToEntropy(const std::string& mnemonic, std::vector<uint8_t>& entropy);

    /**
     * Convert mnemonic phrase to 64-byte seed
     *
     * Uses PBKDF2-SHA3-512 with:
     * - Password: mnemonic phrase (UTF-8, normalized)
     * - Salt: "dilithion-mnemonic" + passphrase (UTF-8)
     * - Iterations: 2048
     *
     * @param mnemonic Space-separated mnemonic words
     * @param passphrase Optional passphrase (empty string if none)
     * @param seed Output buffer for 64-byte seed
     * @return true on success, false if mnemonic is invalid
     */
    static bool ToSeed(const std::string& mnemonic, const std::string& passphrase,
                       uint8_t seed[64]);

    /**
     * Get the expected word count for a given entropy size
     *
     * @param entropy_bits Entropy size in bits
     * @return Expected word count, or 0 if entropy_bits is invalid
     */
    static size_t GetWordCount(size_t entropy_bits);

    /**
     * Get the expected entropy size for a given word count
     *
     * @param word_count Number of words in mnemonic
     * @return Expected entropy size in bits, or 0 if word_count is invalid
     */
    static size_t GetEntropyBits(size_t word_count);

private:
    /**
     * Split mnemonic string into words
     *
     * @param mnemonic Space-separated words
     * @param words Output vector of individual words
     */
    static void SplitWords(const std::string& mnemonic, std::vector<std::string>& words);

    /**
     * Find word index in BIP39 wordlist
     *
     * @param word Word to find
     * @return Index (0-2047) if found, -1 if not found
     */
    static int FindWordIndex(const std::string& word);

    /**
     * Compute checksum for entropy
     *
     * @param entropy Entropy bytes
     * @param entropy_len Entropy length in bytes
     * @param checksum_bits Number of checksum bits to compute
     * @return Checksum value (right-aligned in uint8_t)
     */
    static uint8_t ComputeChecksum(const uint8_t* entropy, size_t entropy_len,
                                    size_t checksum_bits);

    /**
     * Convert 11-bit indices to mnemonic words
     *
     * @param indices Vector of 11-bit word indices
     * @param mnemonic Output space-separated mnemonic string
     */
    static void IndicesToMnemonic(const std::vector<uint16_t>& indices, std::string& mnemonic);

    /**
     * Convert mnemonic words to 11-bit indices
     *
     * @param words Vector of mnemonic words
     * @param indices Output vector of 11-bit word indices
     * @return true on success, false if any word is not in wordlist
     */
    static bool MnemonicToIndices(const std::vector<std::string>& words,
                                   std::vector<uint16_t>& indices);
};

#endif // DILITHION_WALLET_MNEMONIC_H
