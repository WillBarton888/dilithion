# Dilithium RPC User Guide

**Post-Quantum Signature System for Bitcoin**

## Table of Contents

1. [Introduction](#introduction)
2. [Why Dilithium?](#why-dilithium)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [RPC Commands](#rpc-commands)
6. [Common Workflows](#common-workflows)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Introduction

This guide explains how to use the Dilithium post-quantum signature system through Bitcoin's RPC interface. Dilithium is a NIST-standardized (FIPS 204) lattice-based digital signature scheme designed to resist attacks from quantum computers.

### What You'll Learn

- How to generate Dilithium keypairs
- How to sign messages with Dilithium signatures
- How to verify Dilithium signatures
- Best practices for quantum-resistant cryptography

---

## Why Dilithium?

### The Quantum Threat

Quantum computers pose a significant threat to current cryptographic systems:

- **ECDSA Vulnerable**: Bitcoin's current ECDSA signatures can be broken by sufficiently powerful quantum computers using Shor's algorithm
- **Timeline**: Experts estimate quantum computers capable of breaking ECDSA could exist within 10-20 years
- **Irreversible**: Once broken, funds protected by compromised keys cannot be recovered

### Dilithium Solution

Dilithium provides quantum resistance through:

- **NIST Standardized**: Selected by NIST for post-quantum standardization (FIPS 204)
- **Lattice-Based**: Uses mathematical lattice problems that are hard even for quantum computers
- **Security Level 2**: Provides 128-bit quantum security (equivalent to AES-128)
- **Proven**: Extensively analyzed by cryptographers worldwide

### Key Specifications

| Property | Value |
|----------|-------|
| Public Key Size | 1,312 bytes |
| Private Key Size | 2,560 bytes |
| Signature Size | 2,421 bytes (including hash type) |
| Security Level | NIST Level 2 (128-bit quantum security) |
| Algorithm | CRYSTALS-Dilithium Round 3 |

---

## Installation

### Prerequisites

- Bitcoin Core with Dilithium support compiled
- bitcoind running (regtest, testnet, or mainnet)
- bitcoin-cli installed

### Starting bitcoind

```bash
# Regtest (for testing)
bitcoind -regtest -daemon

# Testnet
bitcoind -testnet -daemon

# Mainnet (production)
bitcoind -daemon
```

### Verify Installation

Check that Dilithium RPC commands are available:

```bash
bitcoin-cli help | grep dilithium
```

You should see:
```
generatedilithiumkeypair
signmessagedilithium
verifymessagedilithium
```

---

## Quick Start

### 1. Generate a Keypair

```bash
bitcoin-cli generatedilithiumkeypair
```

**Output:**
```json
{
  "privkey": "8cbf503e8a421a6e...",  # 2560 bytes (5120 hex chars)
  "pubkey": "8cbf503e8a421a6e...",   # 1312 bytes (2624 hex chars)
  "privkey_size": 2560,
  "pubkey_size": 1312
}
```

### 2. Sign a Message

```bash
bitcoin-cli signmessagedilithium "<privkey>" "Hello, quantum-resistant world!"
```

**Output:**
```json
{
  "signature": "68cbf9dde3144855...",  # 2421 bytes
  "signature_size": 2421,
  "message_hash": "a1107a9e4a5ebc78..."
}
```

### 3. Verify the Signature

```bash
bitcoin-cli verifymessagedilithium "<pubkey>" "<signature>" "Hello, quantum-resistant world!"
```

**Output:**
```json
{
  "valid": true,
  "message_hash": "a1107a9e4a5ebc78...",
  "signature_size": 2421,
  "pubkey_size": 1312
}
```

---

## RPC Commands

### `generatedilithiumkeypair`

Generate a new Dilithium key pair.

**Syntax:**
```bash
generatedilithiumkeypair
```

**Parameters:** None

**Returns:**
```json
{
  "privkey": string,        # Hex-encoded private key (2560 bytes)
  "pubkey": string,         # Hex-encoded public key (1312 bytes)
  "privkey_size": number,   # Size in bytes (always 2560)
  "pubkey_size": number     # Size in bytes (always 1312)
}
```

**Example:**
```bash
bitcoin-cli generatedilithiumkeypair
```

**Security Note:** Store the private key securely. Anyone with access to the private key can sign messages on your behalf.

---

### `signmessagedilithium`

Sign a message with a Dilithium private key.

**Syntax:**
```bash
signmessagedilithium "privkey" "message"
```

**Parameters:**
1. `privkey` (string, required) - Hex-encoded Dilithium private key (2560 bytes)
2. `message` (string, required) - Message to sign (any text)

**Returns:**
```json
{
  "signature": string,      # Hex-encoded signature (2421 bytes)
  "signature_size": number, # Size in bytes (always 2421)
  "message_hash": string    # SHA256 hash of the message
}
```

**Example:**
```bash
# Store keys in variables for convenience
PRIVKEY=$(bitcoin-cli generatedilithiumkeypair | jq -r '.privkey')

# Sign a message
bitcoin-cli signmessagedilithium "$PRIVKEY" "I own this address"
```

**Errors:**
- `Invalid private key size`: Private key must be exactly 2560 bytes (5120 hex characters)
- `Signing failed`: Internal error during signature generation

---

### `verifymessagedilithium`

Verify a Dilithium signature on a message.

**Syntax:**
```bash
verifymessagedilithium "pubkey" "signature" "message"
```

**Parameters:**
1. `pubkey` (string, required) - Hex-encoded Dilithium public key (1312 bytes)
2. `signature` (string, required) - Hex-encoded signature (2421 bytes)
3. `message` (string, required) - Original message that was signed

**Returns:**
```json
{
  "valid": boolean,         # true if signature is valid
  "message_hash": string,   # SHA256 hash of the message
  "signature_size": number, # Size of signature in bytes
  "pubkey_size": number     # Size of public key in bytes
}
```

**Example:**
```bash
# Verify a signature
bitcoin-cli verifymessagedilithium "$PUBKEY" "$SIGNATURE" "I own this address"
```

**Important:** The message must match exactly (including case and whitespace) for verification to succeed.

---

### `importdilithiumkey`

Import a Dilithium private key into the keystore for persistent storage.

**Syntax:**
```bash
importdilithiumkey "privkey" ( "label" )
```

**Parameters:**
1. `privkey` (string, required) - Hex-encoded Dilithium private key (2560 bytes)
2. `label` (string, optional) - Label for the key (for easy identification)

**Returns:**
```json
{
  "keyid": string,          # Generated key identifier (16 hex characters)
  "pubkey": string,         # Hex-encoded public key
  "label": string,          # Key label (empty if not provided)
  "imported": boolean       # Always true on success
}
```

**Example:**
```bash
# Generate a key
KEYS=$(bitcoin-cli generatedilithiumkeypair)
PRIVKEY=$(echo "$KEYS" | jq -r '.privkey')

# Import with label
bitcoin-cli importdilithiumkey "$PRIVKEY" "my-signing-key"

# Import without label
bitcoin-cli importdilithiumkey "$PRIVKEY"
```

**Errors:**
- `Invalid private key size`: Private key must be exactly 2560 bytes
- `Invalid private key`: Private key format is invalid
- `Key already exists`: This key is already in the keystore

---

### `listdilithiumkeys`

List all Dilithium keys stored in the keystore.

**Syntax:**
```bash
listdilithiumkeys
```

**Parameters:** None

**Returns:**
```json
[
  {
    "keyid": string,          # Key identifier
    "pubkey": string,         # Hex-encoded public key
    "label": string,          # Key label
    "created": number,        # Creation timestamp (Unix epoch)
    "last_used": number,      # Last used timestamp (Unix epoch)
    "usage_count": number     # Number of times key has been used
  },
  ...
]
```

**Example:**
```bash
# List all keys
bitcoin-cli listdilithiumkeys

# Find a specific key by label
bitcoin-cli listdilithiumkeys | jq '.[] | select(.label == "my-signing-key")'
```

---

### `getdilithiumkeyinfo`

Get detailed information about a specific Dilithium key.

**Syntax:**
```bash
getdilithiumkeyinfo "keyid"
```

**Parameters:**
1. `keyid` (string, required) - Key identifier (from importdilithiumkey or listdilithiumkeys)

**Returns:**
```json
{
  "keyid": string,          # Key identifier
  "pubkey": string,         # Hex-encoded public key
  "label": string,          # Key label
  "created": number,        # Creation timestamp (Unix epoch)
  "last_used": number,      # Last used timestamp (Unix epoch)
  "usage_count": number     # Number of times key has been used
}
```

**Example:**
```bash
# Get info for a specific key
bitcoin-cli getdilithiumkeyinfo "5df6e0e2761359d3"
```

**Errors:**
- `Key not found`: No key exists with this identifier

---

## Common Workflows

### Workflow 1: Prove Address Ownership

```bash
#!/bin/bash

# Generate keypair
KEYS=$(bitcoin-cli generatedilithiumkeypair)
PRIVKEY=$(echo "$KEYS" | jq -r '.privkey')
PUBKEY=$(echo "$KEYS" | jq -r '.pubkey')

# Sign ownership proof
MESSAGE="I own address xyz at $(date)"
SIG=$(bitcoin-cli signmessagedilithium "$PRIVKEY" "$MESSAGE" | jq -r '.signature')

# Share pubkey, signature, and message publicly
echo "Public Key: $PUBKEY"
echo "Signature: $SIG"
echo "Message: $MESSAGE"

# Anyone can verify
bitcoin-cli verifymessagedilithium "$PUBKEY" "$SIG" "$MESSAGE"
```

### Workflow 2: Secure Document Signing

```bash
#!/bin/bash

# Read document
DOCUMENT=$(cat important_document.txt)

# Sign with your private key
SIG=$(bitcoin-cli signmessagedilithium "$MY_PRIVKEY" "$DOCUMENT" | jq -r '.signature')

# Save signature
echo "$SIG" > document.sig

# Later, verify the document
bitcoin-cli verifymessagedilithium "$MY_PUBKEY" "$(cat document.sig)" "$DOCUMENT"
```

### Workflow 3: Multi-Party Verification

```bash
#!/bin/bash

# Alice generates keypair
ALICE_KEYS=$(bitcoin-cli generatedilithiumkeypair)
ALICE_PUBKEY=$(echo "$ALICE_KEYS" | jq -r '.pubkey')
ALICE_PRIVKEY=$(echo "$ALICE_KEYS" | jq -r '.privkey')

# Bob generates keypair
BOB_KEYS=$(bitcoin-cli generatedilithiumkeypair)
BOB_PUBKEY=$(echo "$BOB_KEYS" | jq -r '.pubkey')
BOB_PRIVKEY=$(echo "$BOB_KEYS" | jq -r '.privkey')

# Both sign the same contract
CONTRACT="We agree to terms dated $(date)"

ALICE_SIG=$(bitcoin-cli signmessagedilithium "$ALICE_PRIVKEY" "$CONTRACT" | jq -r '.signature')
BOB_SIG=$(bitcoin-cli signmessagedilithium "$BOB_PRIVKEY" "$CONTRACT" | jq -r '.signature')

# Verify both signatures
bitcoin-cli verifymessagedilithium "$ALICE_PUBKEY" "$ALICE_SIG" "$CONTRACT"
bitcoin-cli verifymessagedilithium "$BOB_PUBKEY" "$BOB_SIG" "$CONTRACT"
```

---

## Best Practices

### Key Management

1. **Never Share Private Keys**
   - Private keys must be kept secret
   - Use secure storage (hardware wallet, encrypted file, key management system)
   - Consider using environment variables instead of command-line arguments

2. **Backup Keys Securely**
   ```bash
   # Encrypt before backing up
   bitcoin-cli generatedilithiumkeypair | gpg --encrypt > dilithium_keys.gpg
   ```

3. **Rotate Keys Periodically**
   - Generate new keypairs for different purposes
   - Don't reuse keys across different contexts

### Signature Security

1. **Include Timestamps**
   ```bash
   MESSAGE="Action: transfer | Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
   ```

2. **Include Context**
   ```bash
   MESSAGE="Purpose: Proof of ownership | Address: xyz | Nonce: $RANDOM"
   ```

3. **Verify Before Acting**
   - Always verify signatures before trusting signed data
   - Check that the message matches expectations

### Performance Considerations

1. **Signature Size**
   - Dilithium signatures are 2,421 bytes (vs ~70 bytes for ECDSA)
   - Consider bandwidth/storage implications for high-volume applications

2. **CPU Usage**
   - Signing: ~1-2ms per signature
   - Verification: ~0.5-1ms per verification
   - Plan for computational requirements at scale

---

## Troubleshooting

### Error: "Invalid private key size"

**Problem:** Private key is not exactly 2560 bytes

**Solution:**
```bash
# Verify key length (should be 5120 hex characters)
echo "$PRIVKEY" | wc -c
# Should output: 5120

# If using jq, ensure no extra whitespace
PRIVKEY=$(bitcoin-cli generatedilithiumkeypair | jq -r '.privkey' | tr -d '\n')
```

### Error: "Signature verification failed"

**Problem:** Signature is invalid or message doesn't match

**Checklist:**
1. ✓ Message is exactly the same (case-sensitive)
2. ✓ No extra whitespace or newlines
3. ✓ Using correct public key
4. ✓ Signature not corrupted

**Debug:**
```bash
# Compare message hashes
SIGN_HASH=$(bitcoin-cli signmessagedilithium "$PRIVKEY" "$MSG" | jq -r '.message_hash')
VERIFY_HASH=$(bitcoin-cli verifymessagedilithium "$PUBKEY" "$SIG" "$MSG" | jq -r '.message_hash')

# Hashes should match
test "$SIGN_HASH" = "$VERIFY_HASH" && echo "Messages match" || echo "Messages differ"
```

### Error: "Connection refused"

**Problem:** bitcoind is not running

**Solution:**
```bash
# Check if bitcoind is running
bitcoin-cli getblockchaininfo

# If not, start it
bitcoind -regtest -daemon

# Wait for startup
sleep 3
```

### Performance Issues

**Problem:** Signatures taking too long

**Possible Causes:**
- High system load
- Insufficient CPU resources
- Memory constraints

**Solutions:**
1. Check system resources: `top` or `htop`
2. Ensure bitcoind has adequate resources
3. Consider batching operations
4. Use faster hardware for production

---

## Additional Resources

- **NIST FIPS 204**: Official Dilithium standard
- **CRYSTALS-Dilithium**: https://pq-crystals.org/dilithium/
- **Bitcoin Core Documentation**: https://bitcoincore.org/
- **Quantum Computing Timeline**: NIST Post-Quantum Cryptography project

---

## Support

For issues or questions:

1. Check this documentation
2. Review error messages carefully
3. Consult the API reference (dilithium-rpc-api.md)
4. Report bugs to the development team

---

**Last Updated:** October 2025
**Version:** 1.0
**License:** MIT
