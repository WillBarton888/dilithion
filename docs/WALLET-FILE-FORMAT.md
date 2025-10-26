# Dilithion Wallet File Format Specification

**Version:** 1.0
**Date:** 2025-10-25

---

## Overview

The Dilithion wallet file stores:
- Encryption state (master key if encrypted)
- Key pairs (Dilithium3 public/private keys)
- Addresses (derived from public keys)
- Unspent transaction outputs (UTXOs)

The file format is binary for efficiency and uses a simple serialization scheme.

---

## File Structure

### Header (32 bytes)

| Field | Type | Size | Description |
|-------|------|------|-------------|
| Magic | char[8] | 8 bytes | "DILWLT01" - File identification |
| Version | uint32_t | 4 bytes | File format version (currently 1) |
| Flags | uint32_t | 4 bytes | Bit 0: Encrypted (1) or not (0) |
| Reserved | uint8_t[16] | 16 bytes | Reserved for future use (zeros) |

### Master Key Record (if encrypted)

Only present if `Flags & 0x01 == 1`

| Field | Type | Size | Description |
|-------|------|------|-------------|
| CryptedKeyLen | uint32_t | 4 bytes | Length of encrypted master key |
| vchCryptedKey | uint8_t[] | Variable | Encrypted master key data |
| vchSalt | uint8_t[32] | 32 bytes | PBKDF2 salt |
| vchIV | uint8_t[16] | 16 bytes | IV for master key encryption |
| nDerivationMethod | uint32_t | 4 bytes | Key derivation method (0 = PBKDF2-SHA3) |
| nDeriveIterations | uint32_t | 4 bytes | PBKDF2 iteration count |

### Keys Section

| Field | Type | Size | Description |
|-------|------|------|-------------|
| NumKeys | uint32_t | 4 bytes | Number of key records |

**For each key (encrypted wallet):**

| Field | Type | Size | Description |
|-------|------|------|-------------|
| AddressData | uint8_t[21] | 21 bytes | Address (1 version + 20 hash) |
| vchPubKey | uint8_t[1952] | 1952 bytes | Dilithium3 public key |
| CryptedKeyLen | uint32_t | 4 bytes | Length of encrypted private key |
| vchCryptedKey | uint8_t[] | Variable | Encrypted private key |
| vchIV | uint8_t[16] | 16 bytes | IV for this key encryption |

**For each key (unencrypted wallet):**

| Field | Type | Size | Description |
|-------|------|------|-------------|
| AddressData | uint8_t[21] | 21 bytes | Address (1 version + 20 hash) |
| vchPubKey | uint8_t[1952] | 1952 bytes | Dilithium3 public key |
| vchPrivKey | uint8_t[4032] | 4032 bytes | Dilithium3 private key |

### Default Address

| Field | Type | Size | Description |
|-------|------|------|-------------|
| HasDefault | uint8_t | 1 byte | 1 if default address set, 0 otherwise |
| AddressData | uint8_t[21] | 21 bytes | Default address (only if HasDefault = 1) |

### Transactions Section

| Field | Type | Size | Description |
|-------|------|------|-------------|
| NumTxs | uint32_t | 4 bytes | Number of transaction records |

**For each transaction:**

| Field | Type | Size | Description |
|-------|------|------|-------------|
| txid | uint8_t[32] | 32 bytes | Transaction ID |
| vout | uint32_t | 4 bytes | Output index |
| nValue | int64_t | 8 bytes | Value in satoshis |
| AddressData | uint8_t[21] | 21 bytes | Receiving address |
| fSpent | uint8_t | 1 byte | 1 if spent, 0 if unspent |
| nHeight | uint32_t | 4 bytes | Block height |

---

## Security Considerations

1. **Private Key Protection**: Unencrypted wallets store private keys in plaintext. File permissions should be set to user-only (0600).

2. **Encryption**: When encrypted, only the master key is derived from the user's passphrase. All private keys are encrypted with the master key.

3. **No Passphrase Storage**: The passphrase is NEVER stored in the file. It must be provided to unlock the wallet.

4. **Memory Wiping**: Sensitive data (master key, private keys) should be wiped from memory after use.

---

## File Location

Default: `~/.dilithion/wallet.dat`

---

## Future Enhancements

- Compression (gzip)
- Checksum/integrity verification (SHA3-256)
- Incremental saves (journaling)
- Multi-wallet support
- HD wallet support (BIP32-style derivation)

---

## Example File Sizes

- **Empty encrypted wallet**: ~100 bytes (header + master key)
- **1 key (encrypted)**: ~2.1 KB
- **1 key (unencrypted)**: ~6.1 KB
- **100 keys (encrypted)**: ~210 KB
- **100 keys + 100 UTXOs**: ~217 KB
