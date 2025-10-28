# Dilithion Changelog

All notable changes to the Dilithion cryptocurrency project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Phase 4 - Security Hardening (October 28, 2025)

#### Critical Security Fixes

**FIXED: Unchecked std::stoi() Exceptions Causing DoS Crashes**
- **Impact**: CRITICAL - Malformed CLI arguments or RPC parameters could crash the node
- **Locations**: 6 instances across CLI and RPC parameter parsing
- **Files**: `src/node/dilithion-node.cpp`, `src/rpc/server.cpp`

**CLI Argument Parsing** (`dilithion-node.cpp`)
- `--rpcport=<value>`: Now validates port range (1-65535) with try-catch
  - Invalid format: "Error: Invalid RPC port format (not a number)"
  - Out of range: "Error: Invalid RPC port (must be 1-65535)"
- `--port=<value>`: Now validates P2P port range with try-catch
  - Invalid format: "Error: Invalid P2P port format (not a number)"
  - Out of range: "Error: Invalid P2P port (must be 1-65535)"
- `--threads=<value>`: Now validates thread count (1-256) with try-catch
  - Invalid format: "Error: Invalid thread count format (not a number)"
  - Out of range: "Error: Invalid thread count (must be 1-256)"

**Peer Address Parsing** (`dilithion-node.cpp`)
- `--connect=<ip:port>`: Now validates port in peer address with try-catch
  - Invalid format: "Invalid port format in address (expected ip:port)"
  - Out of range: "Invalid port number in address (must be 1-65535)"
- `--addnode=<ip:port>`: Same validation as --connect

**RPC Parameter Parsing** (`server.cpp`)
- `getblockhash` height parameter: Now validates with try-catch
  - Invalid format: "Invalid height parameter format (not a number)"
  - Out of range: "Height parameter out of range"
  - Negative values: "Invalid height parameter (must be non-negative)"

**Attack Vector Eliminated**:
```bash
# Before Phase 4 (CRASH):
./dilithion-node --rpcport=INVALID  # → Uncaught exception, node crash

# After Phase 4 (GRACEFUL):
./dilithion-node --rpcport=INVALID  # → Error message, clean exit
```

#### Code Quality Improvements

**REMOVED: Debug Output from Production Code**
- **Impact**: HIGH - Cleaner production logs, reduced log spam
- **Files**: `src/node/dilithion-node.cpp`
- **Changes**: Removed 18 instances of `[DEBUG]` output
  - Removed verbose coinbase creation debug (3 lines)
  - Removed verbose coinbase verification debug (5 lines)
  - Removed verbose wallet crediting debug (7 lines)
  - Removed verbose transaction processing debug (3 lines)
- **Production Logging**: Retained clean `[Wallet]`, `[Mining]`, `[Blockchain]` prefixed logs

**Before Phase 4**:
```
[DEBUG] Coinbase creation:
[DEBUG]   Miner pubkey hash size: 20 bytes
[DEBUG]   scriptPubKey size: 25 bytes
[DEBUG] Coinbase verification:
[DEBUG]   scriptPubKey size: 25 bytes
...18 verbose debug lines...
```

**After Phase 4**:
```
[Wallet] Coinbase credited: 50.00000000 DIL
[Wallet] Total Balance: 50.00000000 DIL (5000000000 ions)
```

**ADDED: Consensus Parameter Constants** (`src/consensus/params.h`)
- **Impact**: HIGH - Improved maintainability, eliminated magic numbers
- **New Header**: Comprehensive consensus parameters header
- **Categories**:
  - Block Reward Parameters (subsidy, halving interval, maturity)
  - Network Protocol Limits (max inv size, max request size, max block size)
  - Port Range Validation (min/max port, default ports)
  - Mining Parameters (threads, block time, difficulty adjustment)
  - Chain Security (max reorg depth, max headers, max blocks in transit)
  - P2P Network (connection limits, timeouts)
  - Mempool Parameters (size limits, fees, tx limits)
  - Script and Transaction Limits (max sigops, max script size)
  - Cryptographic Constants (Dilithium3 sizes, SHA3 sizes)
  - Time Constants (max future block time, median time span)

**REPLACED: Magic Numbers with Named Constants**
- **Files**: `src/node/dilithion-node.cpp`

**Block Subsidy Calculation**:
```cpp
// Before:
int64_t nSubsidy = 50 * COIN;
int nHalvings = nHeight / 210000;
if (nHalvings >= 64) {
    nSubsidy = 0;
}

// After:
int64_t nSubsidy = Consensus::INITIAL_BLOCK_SUBSIDY;
int nHalvings = nHeight / Consensus::SUBSIDY_HALVING_INTERVAL;
if (nHalvings >= Consensus::SUBSIDY_HALVING_BITS) {
    nSubsidy = 0;
}
```

**Port Validation**:
```cpp
// Before:
if (port <= 0 || port > 65535) {

// After:
if (port < Consensus::MIN_PORT || port > Consensus::MAX_PORT) {
```

**Thread Validation**:
```cpp
// Before:
if (threads <= 0 || threads > 256) {

// After:
if (threads < Consensus::MIN_MINING_THREADS || threads > Consensus::MAX_MINING_THREADS) {
```

#### Testing

**Input Validation Tests**:
- All CLI arguments tested with invalid formats (non-numeric strings)
- All CLI arguments tested with out-of-range values (negative, too large)
- All CLI arguments tested with edge cases (0, MAX_INT, empty strings)
- All CLI arguments tested with valid inputs (confirmed no regression)
- RPC methods tested with malformed parameters
- Peer addresses tested with invalid port formats

**Compilation**:
- Zero compilation errors
- All binaries build successfully (dilithion-node: 937K)
- All existing tests pass (no regressions)

**Manual Testing**:
```bash
# Invalid format handling:
./dilithion-node --rpcport=INVALID  # ✓ Graceful error
./dilithion-node --port=ABC         # ✓ Graceful error
./dilithion-node --threads=XYZ      # ✓ Graceful error

# Out of range handling:
./dilithion-node --rpcport=999999   # ✓ Rejected with error
./dilithion-node --threads=0        # ✓ Rejected with error
./dilithion-node --threads=1000     # ✓ Rejected with error

# Valid inputs (no regression):
./dilithion-node --rpcport=8445     # ✓ Works normally
./dilithion-node --port=8444        # ✓ Works normally
./dilithion-node --threads=4        # ✓ Works normally
```

---

### Phase 3 - Testnet Readiness (October 28, 2025)

#### Added
- **Manual Peer Setup Documentation** (`docs/MANUAL-PEER-SETUP.md`)
  - Complete guide for `--addnode` and `--connect` usage
  - Network topology recommendations (star, mesh)
  - Troubleshooting guide for connectivity issues
  - Security best practices
  - 3-node testnet example setup

- **Transaction Hex Serialization** (`src/util/strencodings.h`, `src/util/strencodings.cpp`)
  - `HexStr()` - Convert byte arrays to hex strings
  - `ParseHex()` - Parse hex strings to byte vectors
  - `IsHex()` - Validate hex string format
  - `HexDigit()` - Convert hex character to value

- **RPC Method Implementations**
  - `signrawtransaction` - Fully functional (deserialize → sign → serialize)
  - `sendrawtransaction` - Fully functional (deserialize → validate → broadcast)
  - `startmining` - Production-ready with block template creation

#### Changed
- Updated help text for `signrawtransaction` and `sendrawtransaction`
- Removed "not fully implemented" warnings from RPC methods

---

### Phase 2 - Critical Security Fixes (October 28, 2025)

#### Security

**FIXED: VULN-002 - Wallet Unlock Timeout Race Condition**
- **Severity**: CRITICAL
- **Impact**: Unauthorized transaction signing after wallet timeout
- **Files**: `src/wallet/wallet.h`, `src/wallet/wallet.cpp`
- **Fix**: Added atomic `IsUnlockValid()` helper method
- **Details**: Prevents race condition between timeout check and signing operation

**FIXED: VULN-003 - Missing Signature Message Validation**
- **Severity**: CRITICAL
- **Impact**: Signature replay attacks, transaction malleability
- **Files**: `src/consensus/tx_validation.cpp`, `src/wallet/wallet.cpp`
- **Fix**: Enhanced signature message to include transaction version
- **BREAKING CHANGE**: Signature message now 40 bytes (was 36 bytes)
  - Format: tx_hash (32) + input_index (4) + tx_version (4)
  - All nodes must upgrade for consensus compatibility

**FIXED: SHA3 Streaming API Critical Bug**
- **Severity**: CRITICAL
- **Impact**: Runtime crashes from unimplemented streaming API
- **Files**: `src/crypto/sha3.h`, `src/crypto/sha3.cpp`
- **Fix**: Removed dangerous `CSHA3_256`/`CSHA3_512` classes
- **Changes**: Simplified to production-ready one-shot functions only

---

### Phase 1 - Initial Security Fixes (October 27-28, 2025)

#### Security

**FIXED: VULN-001 - Integer Overflow in GetBalance()**
- **Severity**: CRITICAL
- **Impact**: Wallet balance corruption, potential fund loss
- **Files**: `src/wallet/wallet.cpp`
- **Fix**: Added overflow detection before balance addition

**FIXED: VULN-006 - Missing Base58 Length Limits**
- **Severity**: HIGH
- **Impact**: DoS via unbounded Base58 string allocation
- **Files**: `src/wallet/wallet.cpp`
- **Fix**: Added `MAX_BASE58_LEN = 1024` byte limit

**FIXED: VULN-007 - Mempool Double-Spend Detection Missing**
- **Severity**: HIGH
- **Impact**: Double-spend attacks via mempool manipulation
- **Files**: `src/node/mempool.h`, `src/node/mempool.cpp`
- **Fix**: Added `mapSpentOutpoints` tracking and conflict checks

**FIXED: VULN-008 - No Chain Reorganization Depth Limit**
- **Severity**: HIGH
- **Impact**: DoS via deep reorg attacks
- **Files**: `src/consensus/chain.cpp`
- **Fix**: Added `MAX_REORG_DEPTH = 100` blocks limit

---

## Production Readiness Status

### ✅ READY FOR TESTNET LAUNCH
- All CRITICAL security vulnerabilities fixed
- All HIGH priority security issues addressed
- All input validation hardened with exception handling
- Production-quality logging and error messages
- Comprehensive consensus parameters
- Clean, maintainable codebase
- Zero compilation errors
- Full test coverage

### 📋 Pending for v1.1
- Transaction blockchain indexing (gettransaction currently mempool-only)
- DNS seed node infrastructure
- Difficulty calculation display
- Peer info integration
- Performance optimizations
- Additional monitoring tools

---

## Contributors

- **AI-Assisted Development**: Claude Code (Anthropic)
- **Project Lead**: Will Barton
- **Security Audits**: Comprehensive AI-driven security analysis

---

## License

MIT License - See LICENSE file for details
