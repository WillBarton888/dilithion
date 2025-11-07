# Dilithion Mainnet - Pre-Launch Security Checklist

**Document Version:** 1.0.0
**Date:** November 7, 2025
**Mainnet Launch:** January 1, 2026 00:00:00 UTC
**Purpose:** Final security verification before mainnet deployment

---

## Checklist Overview

This checklist must be completed and verified before mainnet launch on January 1, 2026. All CRITICAL and HIGH priority items are mandatory. MEDIUM priority items are strongly recommended.

**Checklist Status:** 🟡 IN PROGRESS

---

## Legend

- ✅ **COMPLETE** - Verified and documented
- 🟡 **IN PROGRESS** - Work underway
- ⏳ **PENDING** - Not yet started
- ⚠️ **BLOCKED** - External dependency required
- ❌ **FAILED** - Does not meet requirements

**Priority Levels:**
- 🔴 **CRITICAL** - Must complete before launch (blockers)
- 🟠 **HIGH** - Strongly recommended before launch
- 🟡 **MEDIUM** - Recommended (can be completed post-launch)
- 🟢 **LOW** - Nice to have (post-launch)

---

## 1. Cryptography Security

### 1.1 Post-Quantum Cryptography

- [ ] 🔴 **CRITICAL:** CRYSTALS-Dilithium3 implementation verified
  - Reference: NIST FIPS 204
  - Source: `depends/dilithium/ref/`
  - Status: ⏳ PENDING VERIFICATION
  - Verification: Compare with official NIST test vectors

- [ ] 🔴 **CRITICAL:** SHA-3 implementation verified
  - Reference: NIST FIPS 202
  - Source: `src/crypto/sha3.cpp`
  - Status: ⏳ PENDING VERIFICATION
  - Verification: Test against known vectors

- [ ] 🟠 **HIGH:** Signature verification working correctly
  - Test: Sign and verify 1000 transactions
  - Test: Reject invalid signatures
  - Status: ⏳ PENDING TEST

- [ ] 🟡 **MEDIUM:** Constant-time operations verified
  - Tool: timing analysis or static analysis
  - Status: ⏳ PENDING ANALYSIS

### 1.2 Random Number Generation

- [ ] 🔴 **CRITICAL:** System RNG accessible
  - Linux: `/dev/urandom` readable
  - Windows: `CryptGenRandom` available
  - Status: ⏳ PENDING TEST ON ALL PLATFORMS

- [ ] 🟡 **MEDIUM:** RNG fallback mechanism
  - Reference: MEDIUM-001 from security audit
  - Status: ⏳ NOT IMPLEMENTED (post-launch)

### 1.3 Wallet Encryption

- [ ] 🔴 **CRITICAL:** AES-256-CBC encryption working
  - Test: Encrypt and decrypt wallet
  - Test: Wrong passphrase rejected
  - Status: ⏳ PENDING TEST

- [ ] 🟠 **HIGH:** Passphrase strength validation
  - Minimum: 8 characters
  - Test: Weak passphrases detected
  - Status: ⏳ PENDING VERIFICATION

- [ ] 🟡 **MEDIUM:** Enhanced passphrase requirements
  - Complexity: uppercase, lowercase, numbers, symbols
  - Status: ⏳ NOT IMPLEMENTED (post-launch enhancement)

---

## 2. Consensus Security

### 2.1 Proof-of-Work

- [ ] 🔴 **CRITICAL:** RandomX initialization successful
  - Test: Mine blocks on testnet
  - Test: Verify RandomX dataset generation
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Block validation working
  - Test: Accept valid blocks
  - Test: Reject invalid blocks (bad PoW, bad merkle, etc.)
  - Status: ⏳ PENDING TEST

- [ ] 🟠 **HIGH:** Difficulty adjustment tested
  - Test: 2016-block adjustment cycle
  - Test: Handles edge cases (slow/fast blocks)
  - Status: ⏳ PENDING TEST

### 2.2 Block Validation

- [ ] 🔴 **CRITICAL:** Timestamp validation working
  - Test: Reject blocks with timestamps in past
  - Test: Reject blocks >2 hours in future
  - Test: Median-of-11 validation
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Merkle root validation
  - Test: Correct merkle root calculation
  - Test: Reject blocks with wrong merkle root
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Block size limits enforced
  - Maximum: 4 MB
  - Test: Reject oversized blocks
  - Status: ⏳ PENDING TEST

### 2.3 Transaction Validation

- [ ] 🔴 **CRITICAL:** Signature validation
  - Test: Valid Dilithium3 signatures accepted
  - Test: Invalid signatures rejected
  - Reference: VULN-003 fix verified
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Double-spend prevention
  - Test: Reject transactions spending same UTXO
  - Reference: VULN-007 fix verified
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Balance validation
  - Test: Inputs ≥ Outputs + Fee
  - Test: No negative values
  - Test: No integer overflow (VULN-001 fix)
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Coinbase maturity enforced
  - Maturity: 100 blocks
  - Test: Reject spending immature coinbase
  - Status: ⏳ PENDING TEST

---

## 3. Network Security

### 3.1 Seed Nodes (CRITICAL PRIORITY)

- [ ] 🔴 **CRITICAL:** Mainnet seed nodes configured
  - Required: 5-10 seed nodes
  - Geographic diversity: Multiple continents
  - Organizational diversity: Multiple operators
  - Status: ⚠️ BLOCKED (awaiting seed node setup)
  - **ACTION REQUIRED BEFORE LAUNCH**

- [ ] 🔴 **CRITICAL:** DNS seeds registered
  - Required: seed.dilithion.org, seed1.dilithion.org, seed2.dilithion.org
  - Status: ⚠️ BLOCKED (awaiting DNS registration)
  - **ACTION REQUIRED BEFORE LAUNCH**

- [ ] 🔴 **CRITICAL:** Seed node connectivity tested
  - Test: New node can bootstrap from seed nodes
  - Test: All seed nodes reachable
  - Status: ⏳ PENDING (depends on seed node setup)

- [ ] 🟠 **HIGH:** Seed node security hardened
  - Firewall configured
  - Only P2P port (8444) exposed
  - RPC not exposed to internet
  - Status: ⏳ PENDING

### 3.2 P2P Protocol

- [ ] 🔴 **CRITICAL:** Network magic bytes configured
  - Mainnet: 0xD1711710
  - Testnet: 0xDAB5BFFA
  - Test: Mainnet/testnet isolation
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Message validation working
  - Test: Checksum validation
  - Test: Size limits enforced (32MB max)
  - Test: Malformed messages rejected
  - Status: ⏳ PENDING TEST

- [ ] 🟠 **HIGH:** Connection limits enforced
  - Maximum connections: 125 (default)
  - Per-IP limits: 8 connections
  - Test: Additional connections rejected
  - Status: ⏳ PENDING TEST

- [ ] 🟠 **HIGH:** Peer banning functional
  - Test: Misbehaving peers banned
  - Test: Ban duration enforced (24 hours default)
  - Status: ⏳ PENDING TEST

- [ ] 🟡 **MEDIUM:** Subnet diversity limits
  - Reference: MEDIUM-003 from security audit
  - Status: ⏳ NOT IMPLEMENTED (post-launch)

### 3.3 Eclipse Attack Resistance

- [ ] 🔴 **CRITICAL:** Multiple seed sources
  - DNS seeds: 3-5 domains
  - Hard-coded IPs: 5-10 nodes
  - Status: ⚠️ BLOCKED (see 3.1)

- [ ] 🟠 **HIGH:** Peer diversity monitored
  - Inbound/outbound mix maintained
  - IP range diversity
  - Status: ⏳ PENDING IMPLEMENTATION

---

## 4. Application Security

### 4.1 RPC Security

- [ ] 🔴 **CRITICAL:** RPC bound to localhost
  - Default: 127.0.0.1:8332
  - Test: External connections rejected
  - Status: ⏳ PENDING TEST

- [ ] 🟠 **HIGH:** RPC authentication configured
  - Username/password set
  - Test: Unauthenticated requests rejected
  - Status: ⏳ PENDING CONFIGURATION

- [ ] 🟠 **HIGH:** RPC rate limiting functional
  - Prevents brute-force attacks
  - Status: ⏳ PENDING TEST

- [ ] 🟡 **MEDIUM:** RPC methods reviewed
  - Only necessary methods enabled
  - Dangerous methods (stop, invalidateblock) protected
  - Status: ⏳ PENDING REVIEW

### 4.2 Memory Safety

- [ ] 🔴 **CRITICAL:** Fuzzing results verified
  - 374M+ executions completed
  - Zero crashes confirmed
  - All 11 fuzzers passing
  - Status: ✅ COMPLETE (verified in security audit)

- [ ] 🟠 **HIGH:** Static analysis clean
  - Tool: cppcheck
  - No critical warnings
  - Status: ⏳ PENDING ANALYSIS

- [ ] 🟡 **MEDIUM:** Memory leak analysis
  - Tool: valgrind
  - No significant leaks
  - Status: ⏳ PENDING ANALYSIS

### 4.3 Input Validation

- [ ] 🔴 **CRITICAL:** All parsers fuzz-tested
  - Block parser: ✅ COMPLETE
  - Transaction parser: ✅ COMPLETE
  - Network message parser: ✅ COMPLETE
  - Address parser: ✅ COMPLETE
  - CompactSize parser: ✅ COMPLETE

- [ ] 🔴 **CRITICAL:** Base58 length limits enforced
  - Reference: VULN-006 fix verified
  - Status: ⏳ PENDING TEST

---

## 5. Storage Security

### 5.1 Blockchain Database

- [ ] 🔴 **CRITICAL:** LevelDB checksums enabled
  - Detects corruption
  - Status: ⏳ PENDING VERIFICATION

- [ ] 🟠 **HIGH:** Database backup tested
  - Test: Backup and restore blockchain
  - Test: Backup doesn't corrupt running node
  - Status: ⏳ PENDING TEST

- [ ] 🟡 **MEDIUM:** Database recovery tested
  - Test: Recover from corruption
  - Test: Reindex functionality
  - Status: ⏳ PENDING TEST

### 5.2 Wallet Storage

- [ ] 🔴 **CRITICAL:** Wallet file permissions enforced
  - Permissions: 600 (owner read/write only)
  - Test: Correct permissions on creation
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Wallet backup/restore tested
  - Test: Backup encrypted wallet
  - Test: Restore wallet and verify balance
  - Status: ⏳ PENDING TEST

- [ ] 🟠 **HIGH:** Wallet encryption detection working
  - Script: `scripts/backup-wallet-2025-11-07.sh`
  - Status: ⏳ PENDING TEST

---

## 6. Deployment Infrastructure Security

### 6.1 Systemd Service

- [ ] 🟠 **HIGH:** Systemd security hardening verified
  - `NoNewPrivileges=yes`: ✅ CONFIGURED
  - `PrivateTmp=yes`: ✅ CONFIGURED
  - `ReadWritePaths` restricted: ✅ CONFIGURED
  - Resource limits set: ✅ CONFIGURED
  - Status: ⏳ PENDING DEPLOYMENT TEST

- [ ] 🟡 **MEDIUM:** SELinux/AppArmor profile
  - Optional additional hardening
  - Status: ⏳ NOT IMPLEMENTED (optional)

### 6.2 Docker Security

- [ ] 🟠 **HIGH:** Docker image security verified
  - Non-root user (UID 1000): ✅ CONFIGURED
  - Minimal runtime dependencies: ✅ CONFIGURED
  - No secrets in image: ✅ VERIFIED
  - Health checks configured: ✅ CONFIGURED
  - Status: ⏳ PENDING DEPLOYMENT TEST

- [ ] 🟡 **MEDIUM:** Docker image signed
  - Optional: Sign images with Docker Content Trust
  - Status: ⏳ NOT IMPLEMENTED (optional)

### 6.3 Installation Security

- [ ] 🟠 **HIGH:** Binary checksum verification
  - SHA256 checksums provided
  - Installation script verifies checksums
  - Status: ⏳ DOCUMENTED BUT NOT IMPLEMENTED

- [ ] 🟠 **HIGH:** Binary signature verification
  - GPG signatures for releases
  - Installation script verifies signatures
  - Status: ⚠️ NOT IMPLEMENTED (see 6.4)

### 6.4 Supply Chain Security

- [ ] 🟠 **HIGH:** Reproducible builds documented
  - Build instructions complete
  - Deterministic build possible
  - Status: ✅ COMPLETE (Makefile documented)

- [ ] 🟠 **HIGH:** Official release signing
  - GPG key published
  - All releases signed
  - Status: ⚠️ BLOCKED (GPG key needed)
  - **ACTION: Generate and publish GPG signing key**

- [ ] 🟡 **MEDIUM:** Dependency audit
  - RandomX: ✅ VERIFIED (well-known library)
  - Dilithium: ✅ VERIFIED (NIST standard implementation)
  - LevelDB: ✅ VERIFIED (Google library)
  - Status: ✅ COMPLETE

---

## 7. Monitoring & Alerting Security

### 7.1 Monitoring Configuration

- [ ] 🟠 **HIGH:** Prometheus authentication enabled
  - Basic auth or OAuth configured
  - Status: ⏳ PENDING CONFIGURATION

- [ ] 🟠 **HIGH:** Grafana authentication enabled
  - Admin password changed from default
  - User accounts configured
  - Status: ⏳ PENDING CONFIGURATION

- [ ] 🟠 **HIGH:** Monitoring ports firewalled
  - Prometheus (9090): localhost only or firewall
  - Grafana (3000): localhost only or firewall
  - Node exporter (9100): localhost only
  - Status: ⏳ PENDING CONFIGURATION

- [ ] 🟡 **MEDIUM:** TLS for monitoring
  - Reverse proxy with TLS
  - Self-signed or Let's Encrypt certificates
  - Status: ⏳ NOT CONFIGURED (optional)

### 7.2 Alert Configuration

- [ ] 🟠 **HIGH:** Alert channels tested
  - Email: ⏳ PENDING TEST
  - Slack: ⏳ PENDING TEST (if enabled)
  - Discord: ⏳ PENDING TEST (if enabled)
  - Telegram: ⏳ PENDING TEST (if enabled)
  - Status: ⏳ PENDING

- [ ] 🟠 **HIGH:** Alert rate limiting verified
  - 5-minute cooldown tested
  - No alert spam during testing
  - Status: ⏳ PENDING TEST

- [ ] 🟡 **MEDIUM:** Alert log rotation configured
  - Prevent disk filling
  - Status: ⏳ PENDING CONFIGURATION

---

## 8. Documentation Security

### 8.1 User Documentation

- [ ] 🟠 **HIGH:** Security warnings prominent
  - Wallet encryption importance: ✅ DOCUMENTED
  - Backup importance: ✅ DOCUMENTED
  - Phishing warnings: ✅ DOCUMENTED
  - Private key security: ✅ DOCUMENTED
  - Status: ✅ COMPLETE

- [ ] 🟠 **HIGH:** Official communication channels documented
  - Website: dilithion.org (or similar)
  - GitHub: Official repository
  - Discord/Telegram: Official channels
  - Status: ⏳ PENDING (channels need to be established)

- [ ] 🟡 **MEDIUM:** Security best practices guide
  - Cold storage setup: ✅ DOCUMENTED
  - Multi-signature (future): ⏳ N/A
  - Hardware wallet support (future): ⏳ N/A
  - Status: ✅ COMPLETE (current features)

---

## 9. Testing & Verification

### 9.1 Unit Tests

- [ ] 🔴 **CRITICAL:** All tests passing
  - Test count: 251/251
  - Status: ✅ COMPLETE

- [ ] 🟠 **HIGH:** Critical paths covered
  - Consensus validation: ✅ COVERED
  - Transaction validation: ✅ COVERED
  - UTXO operations: ✅ COVERED
  - Wallet operations: ✅ COVERED
  - Status: ✅ COMPLETE

### 9.2 Integration Tests

- [ ] 🔴 **CRITICAL:** End-to-end transaction test
  - Create transaction → Sign → Broadcast → Mine → Confirm
  - Status: ⏳ PENDING TEST

- [ ] 🔴 **CRITICAL:** Mining integration test
  - Start mining → Find block → Validate → Propagate
  - Status: ⏳ PENDING TEST

- [ ] 🟠 **HIGH:** Multi-node synchronization test
  - 2+ nodes sync blockchain
  - Block propagation tested
  - Status: ⏳ PENDING TEST

### 9.3 Testnet Verification

- [ ] 🔴 **CRITICAL:** Testnet operational
  - Testnet running at: 170.64.203.134:18444
  - Status: ✅ OPERATIONAL

- [ ] 🟠 **HIGH:** Testnet stress tested
  - High transaction volume
  - Multiple miners
  - Network splits and recovery
  - Status: ⏳ PENDING TEST

- [ ] 🟡 **MEDIUM:** Testnet security incidents
  - Simulated attacks tested
  - Recovery procedures verified
  - Status: ⏳ PENDING TEST

---

## 10. Pre-Launch Final Checks

### 10.1 Critical Path (T-14 Days)

- [ ] 🔴 **CRITICAL:** All previous CRITICAL items complete
  - Review items marked 🔴 above
  - Status: ⏳ IN PROGRESS

- [ ] 🔴 **CRITICAL:** Seed nodes operational
  - All 5-10 seed nodes running
  - DNS seeds resolving
  - Status: ⚠️ BLOCKED

- [ ] 🔴 **CRITICAL:** Genesis block parameters finalized
  - Genesis time: 1767225600 (Jan 1, 2026 00:00:00 UTC)
  - Genesis message: ✅ FINALIZED
  - Genesis difficulty: ✅ FINALIZED (0x1e00ffff)
  - Status: ✅ COMPLETE

- [ ] 🔴 **CRITICAL:** Binaries built and tested
  - All platforms: Linux, Windows, macOS
  - Checksums generated
  - Status: ⏳ PENDING

### 10.2 High Priority (T-7 Days)

- [ ] 🟠 **HIGH:** All HIGH priority items complete
  - Review items marked 🟠 above
  - Status: ⏳ IN PROGRESS

- [ ] 🟠 **HIGH:** Security audit recommendations addressed
  - CRITICAL-001: Seed nodes (see 3.1)
  - MEDIUM-001: RNG fallback (post-launch)
  - MEDIUM-002: Difficulty float (evaluated, acceptable risk)
  - MEDIUM-003: Subnet diversity (post-launch)
  - Status: 🟡 MOSTLY COMPLETE

- [ ] 🟠 **HIGH:** Monitoring fully operational
  - Prometheus collecting metrics
  - Grafana dashboards displaying
  - Alerts firing correctly
  - Status: ⏳ PENDING DEPLOYMENT

- [ ] 🟠 **HIGH:** Community communications prepared
  - Launch announcement
  - Security best practices guide
  - Support channels established
  - Status: ⏳ PENDING

### 10.3 Final Verification (T-1 Day)

- [ ] 🔴 **CRITICAL:** All blocking issues resolved
  - No open critical bugs
  - No known security vulnerabilities
  - Status: ⏳ PENDING

- [ ] 🔴 **CRITICAL:** Launch team ready
  - Incident response team identified
  - Communication plan established
  - Rollback plan prepared
  - Status: ⏳ PENDING

- [ ] 🔴 **CRITICAL:** Backup plan verified
  - Emergency contacts available
  - Seed node backups ready
  - Database backups tested
  - Status: ⏳ PENDING

---

## 11. Launch Day (T-0)

### 11.1 Pre-Launch

- [ ] 🔴 **CRITICAL:** Final security scan
  - Run: `scripts/security-scan-2025-11-07.sh`
  - All checks passing
  - Status: ⏳ PENDING

- [ ] 🔴 **CRITICAL:** All seed nodes running
  - Health check passing on all nodes
  - Connectivity verified
  - Status: ⏳ PENDING

- [ ] 🔴 **CRITICAL:** Monitoring active
  - All metrics collecting
  - All alerts configured
  - Status: ⏳ PENDING

### 11.2 Launch (00:00:00 UTC)

- [ ] 🔴 **CRITICAL:** Genesis block mined
  - Block 0 created at genesis time
  - Network starts at Jan 1, 2026 00:00:00 UTC
  - Status: ⏳ PENDING LAUNCH

- [ ] 🔴 **CRITICAL:** Network operational
  - Seed nodes accepting connections
  - Blocks being mined
  - Transactions being processed
  - Status: ⏳ PENDING LAUNCH

### 11.3 Post-Launch (T+1 Hour)

- [ ] 🔴 **CRITICAL:** Network health check
  - Multiple blocks mined
  - Nodes synchronizing
  - No critical alerts
  - Status: ⏳ PENDING LAUNCH

- [ ] 🟠 **HIGH:** Community announcement
  - Launch announcement posted
  - Official channels active
  - Support team responsive
  - Status: ⏳ PENDING LAUNCH

---

## Summary Status

### By Priority

| Priority | Total | Complete | In Progress | Pending | Blocked |
|----------|-------|----------|-------------|---------|---------|
| 🔴 CRITICAL | 45 | 8 (18%) | 2 (4%) | 30 (67%) | 5 (11%) |
| 🟠 HIGH | 37 | 4 (11%) | 0 (0%) | 31 (84%) | 2 (5%) |
| 🟡 MEDIUM | 18 | 1 (6%) | 0 (0%) | 17 (94%) | 0 (0%) |
| 🟢 LOW | 0 | 0 | 0 | 0 | 0 |
| **TOTAL** | **100** | **13 (13%)** | **2 (2%)** | **78 (78%)** | **7 (7%)** |

### Critical Blockers

1. **Seed Nodes** - Must be configured before launch
2. **DNS Seeds** - Must be registered before launch
3. **Binary Signatures** - GPG key needed for release signing

### Recommendation

**Current Status:** 🟡 NOT READY FOR LAUNCH

**Estimated Completion:** 2-3 weeks (assuming seed node setup)

**Next Steps:**
1. Set up mainnet seed nodes (5-10 nodes)
2. Register DNS seeds
3. Generate and publish GPG signing key
4. Complete testing and verification
5. Run final security scan
6. Complete deployment checklist

---

**Document Maintained By:** Security Team
**Last Updated:** November 7, 2025
**Next Review:** Weekly until launch

---

*Use this checklist in conjunction with DEPLOYMENT-CHECKLIST-2025-11-07.md* ✓
