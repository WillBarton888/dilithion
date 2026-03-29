/**
 * Dilithium Crypto Module for Light Wallet
 *
 * This module provides cryptographic functions for the Dilithion light wallet:
 * - Dilithium3 key generation and signing (via WebAssembly)
 * - SHA3-256/512 hashing
 * - Address derivation
 * - HD wallet key derivation (BIP44-style)
 * - Encryption/decryption for local storage
 *
 * Copyright (c) 2025 The Dilithion Core developers
 * Distributed under the MIT software license
 */

// Module state
let wasmModule = null;
let wasmReady = false;
let sha3Ready = false;

// Dilithium3 key sizes (NIST Level 3)
const DILITHIUM3_PUBLICKEY_BYTES = 1952;
const DILITHIUM3_SECRETKEY_BYTES = 4032;
const DILITHIUM3_SIGNATURE_BYTES = 3309;

// Dilithion address version byte
const ADDRESS_VERSION = 0x1E;  // Results in 'D' prefix

// BIP44 coin type for Dilithion
const DILITHION_COIN_TYPE = 573;

/**
 * Initialize the crypto module
 * Loads WebAssembly modules for Dilithium and SHA3
 * @returns {Promise<boolean>} True if initialization successful
 */
async function init() {
    try {
        // Load SHA3 - use js-sha3 library (pure JS, no WASM needed)
        if (typeof sha3_256 === 'undefined') {
            console.log('[Crypto] Loading SHA3 library...');
            // Will be loaded via script tag in wallet.html
            // For now, mark as ready if function exists
        }
        sha3Ready = typeof sha3_256 !== 'undefined';

        // Load Dilithium WASM
        if (typeof DilithiumModule !== 'undefined') {
            console.log('[Crypto] Initializing Dilithium WASM...');
            wasmModule = await DilithiumModule();

            // Initialize the Dilithium module (creates OQS_SIG object)
            const initResult = wasmModule._dilithium_init();
            if (initResult !== 0) {
                console.error('[Crypto] Dilithium init failed with code:', initResult);
                wasmReady = false;
            } else {
                wasmReady = true;
                console.log('[Crypto] Dilithium module initialized successfully');
            }
        } else {
            console.warn('[Crypto] Dilithium WASM not loaded. Key generation and signing disabled.');
            wasmReady = false;
        }

        console.log('[Crypto] Init complete. SHA3:', sha3Ready, 'Dilithium:', wasmReady);
        return true;
    } catch (e) {
        console.error('[Crypto] Initialization error:', e);
        return false;
    }
}

/**
 * Check if the crypto module is ready for use
 * @returns {Object} Status of each component
 */
function getStatus() {
    return {
        ready: sha3Ready,  // Basic functions work with SHA3 only
        sha3: sha3Ready,
        dilithium: wasmReady,
        canSign: wasmReady,
        canGenerateKeys: wasmReady
    };
}

// ============================================================================
// SHA3 Hashing Functions
// ============================================================================

/**
 * Compute SHA3-256 hash
 * @param {Uint8Array|string} data - Input data
 * @returns {Uint8Array} 32-byte hash
 */
function sha3_256_hash(data) {
    if (!sha3Ready) {
        throw new Error('SHA3 library not loaded');
    }

    // Convert string to Uint8Array if needed
    let inputBytes;
    if (typeof data === 'string') {
        inputBytes = new TextEncoder().encode(data);
    } else if (data instanceof Uint8Array) {
        inputBytes = data;
    } else {
        inputBytes = new Uint8Array(data);
    }

    // Use js-sha3 library
    const hash = sha3_256.array(inputBytes);
    return new Uint8Array(hash);
}

/**
 * Compute SHA3-512 hash
 * @param {Uint8Array|string} data - Input data
 * @returns {Uint8Array} 64-byte hash
 */
function sha3_512_hash(data) {
    if (!sha3Ready) {
        throw new Error('SHA3 library not loaded');
    }

    let inputBytes;
    if (typeof data === 'string') {
        inputBytes = new TextEncoder().encode(data);
    } else if (data instanceof Uint8Array) {
        inputBytes = data;
    } else {
        inputBytes = new Uint8Array(data);
    }

    const hash = sha3_512.array(inputBytes);
    return new Uint8Array(hash);
}

// ============================================================================
// Base58 Encoding (Bitcoin-style with checksum)
// ============================================================================

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode bytes to Base58Check
 * @param {number} version - Version byte
 * @param {Uint8Array} payload - Data to encode
 * @returns {string} Base58Check encoded string
 */
function base58check_encode(version, payload) {
    // Version + payload
    const data = new Uint8Array(1 + payload.length);
    data[0] = version;
    data.set(payload, 1);

    // Double SHA3-256 for checksum
    const hash1 = sha3_256_hash(data);
    const hash2 = sha3_256_hash(hash1);
    const checksum = hash2.slice(0, 4);

    // Append checksum
    const full = new Uint8Array(data.length + 4);
    full.set(data);
    full.set(checksum, data.length);

    // Base58 encode
    return base58_encode(full);
}

/**
 * Decode Base58Check string
 * @param {string} encoded - Base58Check encoded string
 * @returns {Object} {version, payload} or throws on invalid
 */
function base58check_decode(encoded) {
    const decoded = base58_decode(encoded);
    if (decoded.length < 5) {
        throw new Error('Invalid Base58Check: too short');
    }

    // Split into parts
    const version = decoded[0];
    const payload = decoded.slice(1, -4);
    const checksum = decoded.slice(-4);

    // Verify checksum
    const data = decoded.slice(0, -4);
    const hash1 = sha3_256_hash(data);
    const hash2 = sha3_256_hash(hash1);
    const expectedChecksum = hash2.slice(0, 4);

    for (let i = 0; i < 4; i++) {
        if (checksum[i] !== expectedChecksum[i]) {
            throw new Error('Invalid Base58Check: checksum mismatch');
        }
    }

    return { version, payload };
}

/**
 * Encode bytes to Base58 (no checksum)
 * @param {Uint8Array} bytes - Input bytes
 * @returns {string} Base58 encoded string
 */
function base58_encode(bytes) {
    // Count leading zeros
    let zeros = 0;
    for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
        zeros++;
    }

    // Convert to big integer and encode
    const result = [];
    let num = BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    while (num > 0n) {
        const remainder = Number(num % 58n);
        result.unshift(BASE58_ALPHABET[remainder]);
        num = num / 58n;
    }

    // Add leading '1's for zero bytes
    for (let i = 0; i < zeros; i++) {
        result.unshift('1');
    }

    return result.join('');
}

/**
 * Decode Base58 string to bytes
 * @param {string} str - Base58 encoded string
 * @returns {Uint8Array} Decoded bytes
 */
function base58_decode(str) {
    // Count leading '1's
    let zeros = 0;
    for (let i = 0; i < str.length && str[i] === '1'; i++) {
        zeros++;
    }

    // Decode to big integer
    let num = 0n;
    for (let i = 0; i < str.length; i++) {
        const idx = BASE58_ALPHABET.indexOf(str[i]);
        if (idx === -1) {
            throw new Error('Invalid Base58 character: ' + str[i]);
        }
        num = num * 58n + BigInt(idx);
    }

    // Convert to bytes
    let hex = num.toString(16);
    if (hex.length % 2) hex = '0' + hex;

    const bytes = new Uint8Array(zeros + hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[zeros + i / 2] = parseInt(hex.substr(i, 2), 16);
    }

    return bytes;
}

// ============================================================================
// Address Functions
// ============================================================================

/**
 * Derive address from public key
 * Uses double SHA3-256, takes first 20 bytes, adds version prefix
 * @param {Uint8Array} publicKey - 1952-byte Dilithium3 public key
 * @returns {string} Dilithion address starting with 'D'
 */
function deriveAddress(publicKey) {
    if (!(publicKey instanceof Uint8Array)) {
        throw new Error('Public key must be Uint8Array');
    }
    if (publicKey.length !== DILITHIUM3_PUBLICKEY_BYTES) {
        throw new Error(`Invalid public key length: ${publicKey.length}, expected ${DILITHIUM3_PUBLICKEY_BYTES}`);
    }

    // Double SHA3-256
    const hash1 = sha3_256_hash(publicKey);
    const hash2 = sha3_256_hash(hash1);

    // Take first 20 bytes
    const addressBytes = hash2.slice(0, 20);

    // Base58Check encode with version byte
    return base58check_encode(ADDRESS_VERSION, addressBytes);
}

/**
 * Validate a Dilithion address
 * @param {string} address - Address to validate
 * @returns {boolean} True if valid
 */
function validateAddress(address) {
    try {
        if (!address || typeof address !== 'string') return false;
        if (!address.startsWith('D')) return false;

        const decoded = base58check_decode(address);
        if (decoded.version !== ADDRESS_VERSION) return false;
        if (decoded.payload.length !== 20) return false;

        return true;
    } catch (e) {
        return false;
    }
}

// ============================================================================
// Dilithium Key Generation and Signing (requires WASM)
// ============================================================================

/**
 * Generate a new Dilithium3 keypair
 * @returns {Promise<Object>} {publicKey: Uint8Array, privateKey: Uint8Array}
 */
async function generateKeypair() {
    if (!wasmReady) {
        throw new Error('Dilithium WASM not loaded. Cannot generate keys.');
    }

    console.log('[Crypto] Allocating memory for keypair...');

    // Allocate memory for keys
    const pkPtr = wasmModule._dilithium_malloc(DILITHIUM3_PUBLICKEY_BYTES);
    console.log('[Crypto] pkPtr:', pkPtr);
    const skPtr = wasmModule._dilithium_malloc(DILITHIUM3_SECRETKEY_BYTES);
    console.log('[Crypto] skPtr:', skPtr);

    if (pkPtr === 0 || skPtr === 0) {
        throw new Error('Memory allocation failed');
    }

    try {
        // Generate keypair
        console.log('[Crypto] Calling _dilithium_keypair...');
        const result = wasmModule._dilithium_keypair(pkPtr, skPtr);
        console.log('[Crypto] _dilithium_keypair returned:', result);
        if (result !== 0) {
            throw new Error('Key generation failed with code: ' + result);
        }

        // Copy keys from WASM memory
        const publicKey = new Uint8Array(
            wasmModule.HEAPU8.buffer,
            pkPtr,
            DILITHIUM3_PUBLICKEY_BYTES
        ).slice();  // Clone to own the data

        const privateKey = new Uint8Array(
            wasmModule.HEAPU8.buffer,
            skPtr,
            DILITHIUM3_SECRETKEY_BYTES
        ).slice();

        return { publicKey, privateKey };
    } finally {
        // Free WASM memory
        wasmModule._dilithium_free(pkPtr);
        wasmModule._dilithium_free(skPtr);
    }
}

/**
 * Sign a message with Dilithium3
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} privateKey - 4032-byte private key
 * @returns {Promise<Uint8Array>} Signature (up to 3309 bytes)
 */
async function sign(message, privateKey) {
    if (!wasmReady) {
        throw new Error('Dilithium WASM not loaded. Cannot sign.');
    }

    if (privateKey.length !== DILITHIUM3_SECRETKEY_BYTES) {
        throw new Error(`Invalid private key length: ${privateKey.length}`);
    }

    // Allocate memory
    const msgPtr = wasmModule._dilithium_malloc(message.length);
    const skPtr = wasmModule._dilithium_malloc(DILITHIUM3_SECRETKEY_BYTES);
    const sigPtr = wasmModule._dilithium_malloc(DILITHIUM3_SIGNATURE_BYTES);
    const sigLenPtr = wasmModule._dilithium_malloc(8);  // size_t

    try {
        // Copy data to WASM memory
        wasmModule.HEAPU8.set(message, msgPtr);
        wasmModule.HEAPU8.set(privateKey, skPtr);

        // Sign
        const result = wasmModule._dilithium_sign(
            sigPtr, sigLenPtr, msgPtr, message.length, skPtr
        );

        if (result !== 0) {
            throw new Error('Signing failed with code: ' + result);
        }

        // Get actual signature length
        const sigLen = wasmModule.HEAPU32[sigLenPtr / 4];

        // Copy signature from WASM memory
        const signature = new Uint8Array(
            wasmModule.HEAPU8.buffer,
            sigPtr,
            sigLen
        ).slice();

        return signature;
    } finally {
        wasmModule._dilithium_free(msgPtr);
        wasmModule._dilithium_free(skPtr);
        wasmModule._dilithium_free(sigPtr);
        wasmModule._dilithium_free(sigLenPtr);
    }
}

/**
 * Verify a Dilithium3 signature
 * @param {Uint8Array} signature - Signature to verify
 * @param {Uint8Array} message - Original message
 * @param {Uint8Array} publicKey - 1952-byte public key
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verify(signature, message, publicKey) {
    if (!wasmReady) {
        throw new Error('Dilithium WASM not loaded. Cannot verify.');
    }

    if (publicKey.length !== DILITHIUM3_PUBLICKEY_BYTES) {
        throw new Error(`Invalid public key length: ${publicKey.length}`);
    }

    // Allocate memory
    const sigPtr = wasmModule._dilithium_malloc(signature.length);
    const msgPtr = wasmModule._dilithium_malloc(message.length);
    const pkPtr = wasmModule._dilithium_malloc(DILITHIUM3_PUBLICKEY_BYTES);

    try {
        // Copy data to WASM memory
        wasmModule.HEAPU8.set(signature, sigPtr);
        wasmModule.HEAPU8.set(message, msgPtr);
        wasmModule.HEAPU8.set(publicKey, pkPtr);

        // Verify (liboqs API: message, message_len, sig, sig_len, pubkey)
        const result = wasmModule._dilithium_verify(
            msgPtr, message.length, sigPtr, signature.length, pkPtr
        );

        return result === 0;
    } finally {
        wasmModule._dilithium_free(sigPtr);
        wasmModule._dilithium_free(msgPtr);
        wasmModule._dilithium_free(pkPtr);
    }
}

// ============================================================================
// HD Wallet Functions (BIP44-style)
// ============================================================================

/**
 * Generate BIP39-style mnemonic (24 words)
 * @returns {Promise<string[]>} Array of 24 words
 */
async function generateMnemonic() {
    // Generate 256 bits of entropy using Web Crypto API
    const entropy = new Uint8Array(32);
    crypto.getRandomValues(entropy);

    // For now, use a simple word list encoding
    // In production, should use BIP39 word list
    const words = [];
    const wordList = await loadWordList();

    // Convert entropy to 24 words (11 bits per word)
    let bits = '';
    for (let i = 0; i < entropy.length; i++) {
        bits += entropy[i].toString(2).padStart(8, '0');
    }

    // Add checksum (first 8 bits of SHA3-256)
    const checksum = sha3_256_hash(entropy);
    bits += checksum[0].toString(2).padStart(8, '0');

    // Split into 24 x 11-bit segments
    for (let i = 0; i < 24; i++) {
        const segment = bits.substr(i * 11, 11);
        const index = parseInt(segment, 2);
        words.push(wordList[index]);
    }

    return words;
}

/**
 * Validate a mnemonic phrase
 * @param {string[]} words - Array of 24 words
 * @returns {Promise<boolean>} True if valid
 */
async function validateMnemonic(words) {
    if (!Array.isArray(words) || words.length !== 24) {
        return false;
    }

    const wordList = await loadWordList();

    // Check all words are in word list
    for (const word of words) {
        if (wordList.indexOf(word.toLowerCase()) === -1) {
            return false;
        }
    }

    // Verify checksum
    let bits = '';
    for (const word of words) {
        const index = wordList.indexOf(word.toLowerCase());
        bits += index.toString(2).padStart(11, '0');
    }

    // Extract entropy and checksum
    const entropyBits = bits.substr(0, 256);
    const checksumBits = bits.substr(256, 8);

    // Convert entropy to bytes
    const entropy = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        entropy[i] = parseInt(entropyBits.substr(i * 8, 8), 2);
    }

    // Verify checksum
    const hash = sha3_256_hash(entropy);
    const expectedChecksum = hash[0].toString(2).padStart(8, '0');

    return checksumBits === expectedChecksum;
}

/**
 * Convert mnemonic to seed
 * Uses PBKDF2 with SHA3-512 (similar to BIP39)
 * @param {string[]} mnemonic - Array of 24 words
 * @param {string} passphrase - Optional passphrase
 * @returns {Promise<Uint8Array>} 64-byte seed
 */
async function mnemonicToSeed(mnemonic, passphrase = '') {
    const words = mnemonic.join(' ');
    const salt = 'dilithion-mnemonic' + passphrase;

    // PBKDF2-SHA3-512 (Web Crypto doesn't support SHA3, so we implement it in JS)
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(words);
    const saltBytes = encoder.encode(salt);

    return pbkdf2_sha3_512(passwordBytes, saltBytes, 2048, 64);
}

/**
 * PBKDF2 using HMAC-SHA3-512
 * Matches the C++ node implementation in pbkdf2_sha3.cpp
 */
function pbkdf2_sha3_512(password, salt, iterations, keylen) {
    const hashLen = 64; // SHA3-512 output
    const numBlocks = Math.ceil(keylen / hashLen);
    const result = new Uint8Array(keylen);

    for (let blockIdx = 1; blockIdx <= numBlocks; blockIdx++) {
        // U1 = HMAC(password, salt || INT_32_BE(blockIdx))
        const saltBlock = new Uint8Array(salt.length + 4);
        saltBlock.set(salt);
        saltBlock[salt.length]     = (blockIdx >> 24) & 0xff;
        saltBlock[salt.length + 1] = (blockIdx >> 16) & 0xff;
        saltBlock[salt.length + 2] = (blockIdx >> 8) & 0xff;
        saltBlock[salt.length + 3] = blockIdx & 0xff;

        let u = hmacSha3_512(password, saltBlock);
        const block = new Uint8Array(u);

        for (let iter = 2; iter <= iterations; iter++) {
            u = hmacSha3_512(password, u);
            for (let j = 0; j < hashLen; j++) {
                block[j] ^= u[j];
            }
        }

        const offset = (blockIdx - 1) * hashLen;
        const bytesToCopy = Math.min(hashLen, keylen - offset);
        result.set(block.slice(0, bytesToCopy), offset);
    }

    return result;
}

/**
 * Derive child key from seed using BIP44 path
 * @param {Uint8Array} seed - 64-byte seed
 * @param {string} path - Derivation path (e.g., "m/44'/573'/0'/0/0")
 * @returns {Promise<Object>} {publicKey, privateKey, chainCode}
 */
async function deriveChildKey(seed, path) {
    if (!wasmReady) {
        throw new Error('Dilithium WASM not loaded. Cannot derive keys.');
    }

    // Parse path
    const segments = path.split('/').slice(1);  // Remove 'm'

    // Start with master key
    let current = await deriveMasterKey(seed);

    // Derive each level
    for (const segment of segments) {
        const hardened = segment.endsWith("'");
        const index = parseInt(segment.replace("'", ''));
        current = await deriveChildFromParent(current, index, hardened);
    }

    return current;
}

/**
 * Derive master key from seed
 * @param {Uint8Array} seed - 64-byte seed
 * @returns {Promise<Object>} {privateKey, chainCode}
 */
async function deriveMasterKey(seed) {
    // HMAC-SHA3-512 with key "Dilithion seed"
    const key = new TextEncoder().encode('Dilithion seed');

    // HMAC implementation (Web Crypto doesn't support SHA3)
    const blockSize = 72;  // SHA3-512 rate (1600 - 1024 = 576 bits = 72 bytes)

    // Pad key
    let keyPadded = new Uint8Array(blockSize);
    if (key.length > blockSize) {
        keyPadded = sha3_512_hash(key).slice(0, blockSize);
    } else {
        keyPadded.set(key);
    }

    // Inner padding
    const ipad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
        ipad[i] = keyPadded[i] ^ 0x36;
    }

    // Outer padding
    const opad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
        opad[i] = keyPadded[i] ^ 0x5c;
    }

    // HMAC = H(opad || H(ipad || message))
    const inner = new Uint8Array(blockSize + seed.length);
    inner.set(ipad);
    inner.set(seed, blockSize);
    const innerHash = sha3_512_hash(inner);

    const outer = new Uint8Array(blockSize + 64);
    outer.set(opad);
    outer.set(innerHash, blockSize);
    const result = sha3_512_hash(outer);

    // Split result: first 32 bytes = seed for key gen, last 32 bytes = chain code
    const keySeed = result.slice(0, 32);
    const chainCode = result.slice(32, 64);

    // Generate Dilithium keypair from seed
    const keypair = await generateKeypairFromSeed(keySeed);

    return {
        publicKey: keypair.publicKey,
        privateKey: keypair.privateKey,
        keySeed: keySeed,  // 32-byte seed used for child derivation (matches C++ hd_derivation.cpp)
        chainCode
    };
}

/**
 * Derive child key from parent
 * @param {Object} parent - {privateKey, chainCode}
 * @param {number} index - Child index
 * @param {boolean} hardened - Whether to use hardened derivation
 * @returns {Promise<Object>} {publicKey, privateKey, chainCode}
 */
async function deriveChildFromParent(parent, index, hardened) {
    // Build data for HMAC
    // Matches C++ hd_derivation.cpp: seed(32 bytes) || index(4 bytes big-endian)
    // Dilithion uses all-hardened derivation, so index always has bit 31 set
    const idx = hardened ? (index | 0x80000000) : index;
    const data = new Uint8Array(32 + 4);
    data.set(parent.keySeed);
    data[32] = (idx >> 24) & 0xff;
    data[33] = (idx >> 16) & 0xff;
    data[34] = (idx >> 8) & 0xff;
    data[35] = idx & 0xff;

    // HMAC-SHA3-512 with chain code
    const result = hmacSha3_512(parent.chainCode, data);

    // Split result
    const keySeed = result.slice(0, 32);
    const chainCode = result.slice(32, 64);

    // Generate keypair from seed
    const keypair = await generateKeypairFromSeed(keySeed);

    return {
        publicKey: keypair.publicKey,
        privateKey: keypair.privateKey,
        keySeed: keySeed,
        chainCode
    };
}

/**
 * Generate Dilithium keypair from a 32-byte seed (deterministic)
 * @param {Uint8Array} seed - 32-byte seed
 * @returns {Promise<Object>} {publicKey, privateKey}
 */
async function generateKeypairFromSeed(seed) {
    if (!wasmReady) {
        throw new Error('Dilithium WASM not loaded. Cannot generate keys.');
    }

    // Allocate memory
    const seedPtr = wasmModule._dilithium_malloc(32);
    const pkPtr = wasmModule._dilithium_malloc(DILITHIUM3_PUBLICKEY_BYTES);
    const skPtr = wasmModule._dilithium_malloc(DILITHIUM3_SECRETKEY_BYTES);

    try {
        // Copy seed to WASM memory
        wasmModule.HEAPU8.set(seed, seedPtr);

        // Generate keypair from seed (deterministic)
        const result = wasmModule._dilithium3_keypair_seed(pkPtr, skPtr, seedPtr);
        if (result !== 0) {
            throw new Error('Key generation from seed failed with code: ' + result);
        }

        // Copy keys from WASM memory
        const publicKey = new Uint8Array(
            wasmModule.HEAPU8.buffer,
            pkPtr,
            DILITHIUM3_PUBLICKEY_BYTES
        ).slice();

        const privateKey = new Uint8Array(
            wasmModule.HEAPU8.buffer,
            skPtr,
            DILITHIUM3_SECRETKEY_BYTES
        ).slice();

        return { publicKey, privateKey };
    } finally {
        wasmModule._dilithium_free(seedPtr);
        wasmModule._dilithium_free(pkPtr);
        wasmModule._dilithium_free(skPtr);
    }
}

/**
 * HMAC-SHA3-512
 * @param {Uint8Array} key - HMAC key
 * @param {Uint8Array} data - Data to hash
 * @returns {Uint8Array} 64-byte HMAC
 */
function hmacSha3_512(key, data) {
    const blockSize = 72;  // SHA3-512 rate (1600 - 1024 = 576 bits = 72 bytes)

    // Pad key
    let keyPadded = new Uint8Array(blockSize);
    if (key.length > blockSize) {
        keyPadded.set(sha3_512_hash(key).slice(0, blockSize));
    } else {
        keyPadded.set(key);
    }

    // Inner and outer padding
    const ipad = new Uint8Array(blockSize);
    const opad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
        ipad[i] = keyPadded[i] ^ 0x36;
        opad[i] = keyPadded[i] ^ 0x5c;
    }

    // HMAC = H(opad || H(ipad || message))
    const inner = new Uint8Array(blockSize + data.length);
    inner.set(ipad);
    inner.set(data, blockSize);
    const innerHash = sha3_512_hash(inner);

    const outer = new Uint8Array(blockSize + 64);
    outer.set(opad);
    outer.set(innerHash, blockSize);

    return sha3_512_hash(outer);
}

// ============================================================================
// Encryption Functions (for local wallet storage)
// ============================================================================

/**
 * Encrypt data with password using PBKDF2 + AES-256-GCM
 * @param {Uint8Array} data - Data to encrypt
 * @param {string} password - User password
 * @returns {Promise<Object>} {ciphertext, salt, iv} (all base64 encoded)
 */
async function encrypt(data, password) {
    // Generate random salt and IV
    const salt = new Uint8Array(16);
    const iv = new Uint8Array(12);  // AES-GCM uses 96-bit nonce
    crypto.getRandomValues(salt);
    crypto.getRandomValues(iv);

    // Derive key from password using PBKDF2
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );

    // Encrypt with AES-256-GCM
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
    );

    // Return base64-encoded values
    return {
        ciphertext: arrayToBase64(new Uint8Array(ciphertext)),
        salt: arrayToBase64(salt),
        iv: arrayToBase64(iv)
    };
}

/**
 * Decrypt data with password
 * @param {Object} encrypted - {ciphertext, salt, iv} (all base64)
 * @param {string} password - User password
 * @returns {Promise<Uint8Array>} Decrypted data
 */
async function decrypt(encrypted, password) {
    // Decode base64
    const ciphertext = base64ToArray(encrypted.ciphertext);
    const salt = base64ToArray(encrypted.salt);
    const iv = base64ToArray(encrypted.iv);

    // Derive key from password
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    // Decrypt
    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            ciphertext
        );
        return new Uint8Array(plaintext);
    } catch (e) {
        throw new Error('Decryption failed. Wrong password?');
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert Uint8Array to hex string
 * @param {Uint8Array} bytes - Input bytes
 * @returns {string} Hex string
 */
function toHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex - Hex string
 * @returns {Uint8Array} Bytes
 */
function fromHex(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error('Invalid hex string');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Convert Uint8Array to base64
 * @param {Uint8Array} bytes - Input bytes
 * @returns {string} Base64 string
 */
function arrayToBase64(bytes) {
    return btoa(String.fromCharCode.apply(null, bytes));
}

/**
 * Convert base64 to Uint8Array
 * @param {string} base64 - Base64 string
 * @returns {Uint8Array} Bytes
 */
function base64ToArray(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// BIP39 word list (English)
let wordListCache = null;

/**
 * Load BIP39 word list
 * @returns {Promise<string[]>} Array of 2048 words
 */
async function loadWordList() {
    if (wordListCache) {
        return wordListCache;
    }

    // Full BIP39 English word list (2048 words)
    wordListCache = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
        "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
        "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
        "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
        "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
        "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
        "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
        "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
        "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
        "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
        "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
        "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
        "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
        "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
        "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
        "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
        "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
        "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
        "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
        "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
        "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
        "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
        "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
        "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
        "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
        "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
        "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
        "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable",
        "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
        "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
        "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
        "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
        "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling",
        "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
        "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap",
        "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
        "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar",
        "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify",
        "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff",
        "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud",
        "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
        "code", "coffee", "coil", "coin", "collect", "color", "column", "combine",
        "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm",
        "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper",
        "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
        "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
        "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream",
        "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
        "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
        "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious",
        "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
        "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn",
        "day", "deal", "debate", "debris", "decade", "december", "decide", "decline",
        "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
        "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
        "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
        "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram",
        "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
        "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
        "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide",
        "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
        "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
        "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
        "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
        "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
        "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
        "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight",
        "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
        "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
        "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy",
        "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
        "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode",
        "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt",
        "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
        "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude",
        "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
        "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend",
        "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint",
        "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy",
        "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault",
        "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
        "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field",
        "figure", "file", "film", "filter", "final", "find", "fine", "finger",
        "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness",
        "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
        "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
        "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
        "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil",
        "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
        "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel",
        "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
        "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment",
        "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius",
        "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
        "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass",
        "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
        "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip",
        "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass",
        "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group",
        "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun",
        "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
        "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard",
        "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet",
        "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip",
        "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
        "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
        "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble",
        "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband",
        "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill",
        "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
        "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
        "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
        "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
        "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
        "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory",
        "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
        "job", "join", "joke", "journey", "joy", "judge", "juice", "jump",
        "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
        "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
        "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know",
        "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
        "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
        "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave",
        "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
        "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty",
        "library", "license", "life", "lift", "light", "like", "limb", "limit",
        "link", "lion", "liquid", "list", "little", "live", "lizard", "load",
        "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop",
        "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber",
        "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
        "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
        "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin",
        "marine", "market", "marriage", "mask", "mass", "master", "match", "material",
        "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure",
        "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory",
        "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
        "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
        "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
        "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
        "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
        "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
        "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
        "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
        "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
        "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
        "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
        "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice",
        "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey",
        "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
        "october", "odor", "off", "offer", "office", "often", "oil", "okay",
        "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
        "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
        "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
        "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
        "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page",
        "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
        "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
        "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut",
        "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper",
        "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
        "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
        "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
        "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge",
        "poem", "poet", "point", "polar", "pole", "police", "pond", "pony",
        "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery",
        "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
        "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
        "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
        "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
        "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
        "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
        "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
        "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail",
        "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid",
        "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real",
        "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
        "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
        "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
        "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
        "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
        "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
        "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
        "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
        "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
        "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
        "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
        "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
        "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
        "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
        "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
        "search", "season", "seat", "second", "secret", "section", "security", "seed",
        "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
        "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
        "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
        "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
        "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
        "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
        "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
        "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
        "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
        "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
        "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
        "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
        "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
        "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
        "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
        "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
        "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium",
        "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay",
        "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting",
        "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
        "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
        "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest",
        "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme",
        "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain",
        "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
        "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
        "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target",
        "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
        "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
        "theme", "then", "theory", "there", "they", "thing", "this", "thought",
        "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger",
        "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
        "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
        "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
        "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
        "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
        "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
        "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy",
        "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try",
        "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
        "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
        "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
        "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown",
        "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon",
        "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
        "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
        "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
        "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very",
        "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
        "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
        "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote",
        "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want",
        "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
        "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding",
        "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
        "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife",
        "wild", "will", "win", "window", "wine", "wing", "wink", "winner",
        "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
        "wonder", "wood", "wool", "word", "work", "world", "worry", "worth",
        "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
        "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"
    ];

    return wordListCache;
}

// ============================================================================
// Export module
// ============================================================================

const DilithiumCrypto = {
    // Module management
    init,
    getStatus,

    // Constants
    PUBLICKEY_BYTES: DILITHIUM3_PUBLICKEY_BYTES,
    SECRETKEY_BYTES: DILITHIUM3_SECRETKEY_BYTES,
    SIGNATURE_BYTES: DILITHIUM3_SIGNATURE_BYTES,
    ADDRESS_VERSION,
    COIN_TYPE: DILITHION_COIN_TYPE,

    // Hashing
    sha3_256: sha3_256_hash,
    sha3_512: sha3_512_hash,

    // Base58
    base58_encode,
    base58_decode,
    base58check_encode,
    base58check_decode,

    // Address functions
    deriveAddress,
    validateAddress,

    // Dilithium operations (require WASM)
    generateKeypair,
    sign,
    verify,

    // HD wallet
    generateMnemonic,
    validateMnemonic,
    mnemonicToSeed,
    deriveChildKey,

    // Encryption
    encrypt,
    decrypt,

    // Utilities
    toHex,
    fromHex,
    arrayToBase64,
    base64ToArray
};

// Export for both module and browser use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DilithiumCrypto;
} else if (typeof window !== 'undefined') {
    window.DilithiumCrypto = DilithiumCrypto;
}
