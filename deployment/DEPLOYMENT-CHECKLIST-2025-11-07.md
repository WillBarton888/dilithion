# Dilithion Mainnet - Final Deployment Checklist

**Document Version:** 1.0.0
**Date:** November 7, 2025
**Mainnet Launch:** January 1, 2026 00:00:00 UTC (Epoch: 1767225600)
**Purpose:** Final operational checklist for mainnet deployment

---

## Overview

This checklist covers the operational aspects of mainnet deployment. It complements the [SECURITY-CHECKLIST-2025-11-07.md](../docs/SECURITY-CHECKLIST-2025-11-07.md) which focuses on security verification.

**All items must be completed before mainnet launch on January 1, 2026.**

---

## Pre-Deployment Timeline

- **T-14 days (Dec 18, 2025):** Critical infrastructure setup complete
- **T-7 days (Dec 25, 2025):** Testing and verification complete
- **T-3 days (Dec 29, 2025):** Final security audit complete
- **T-1 day (Dec 31, 2025):** Launch team briefing and final checks
- **T-0 (Jan 1, 2026 00:00:00 UTC):** Mainnet Launch

---

## 1. Infrastructure Preparation

### 1.1 Seed Nodes

- [ ] 🔴 **T-14:** Provision 5-10 seed nodes
  - **Geographic distribution:** North America, Europe, Asia, South America, Australia
  - **Operating system:** Ubuntu 22.04 LTS or newer
  - **Hardware:**
    - CPU: 2+ cores
    - RAM: 2GB minimum, 4GB recommended
    - Disk: 50GB SSD minimum
    - Network: 100 Mbps+ connection, static IP
  - **Status:** ⚠️ IN PROGRESS

- [ ] 🔴 **T-14:** Install Dilithion node on seed nodes
  - Use: `scripts/install-mainnet-2025-11-07.sh`
  - Verify: `dilithion-node --version`
  - Configure: Auto-start with systemd
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-14:** Configure seed node security
  - Firewall: Allow 8444 (P2P), block 8332 (RPC)
  - SSH: Key-based authentication only, no password
  - Updates: Configure automatic security updates
  - Monitoring: Install and configure monitoring agents
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-10:** Register DNS seed domains
  - **Domains to register:**
    - seed.dilithion.org
    - seed1.dilithion.org
    - seed2.dilithion.org
    - seed3.dilithion.org (optional)
    - seed4.dilithion.org (optional)
  - **DNS type:** A records pointing to seed node IPs
  - **TTL:** 300 seconds (5 minutes) for quick updates
  - **Status:** ⚠️ BLOCKED (domain registration needed)

- [ ] 🔴 **T-7:** Update chainparams.cpp with seed nodes
  ```cpp
  // src/core/chainparams.cpp - Mainnet()
  dns_seeds = {
      "seed.dilithion.org",
      "seed1.dilithion.org",
      "seed2.dilithion.org",
  };

  AddSeedNode("IP_ADDRESS_1", 8444);
  AddSeedNode("IP_ADDRESS_2", 8444);
  AddSeedNode("IP_ADDRESS_3", 8444);
  AddSeedNode("IP_ADDRESS_4", 8444);
  AddSeedNode("IP_ADDRESS_5", 8444);
  // ... (add all seed node IPs)
  ```
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-7:** Rebuild and test with seed nodes
  - Build: `make clean && make -j$(nproc)`
  - Test: New node can bootstrap from seeds
  - **Status:** ⏳ PENDING

### 1.2 Monitoring Infrastructure

- [ ] 🟠 **T-10:** Deploy Prometheus server
  - Location: Monitoring server (separate from seed nodes)
  - Configuration: `monitoring/prometheus-2025-11-07.yml`
  - Storage: 30-day retention minimum
  - Authentication: Enable basic auth or OAuth
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-10:** Deploy Grafana server
  - Location: Same as Prometheus or separate
  - Configuration: Import dashboard from `monitoring/grafana-dashboard-2025-11-07.json`
  - Authentication: Change default admin password
  - Create user accounts for team members
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-7:** Configure monitoring for seed nodes
  - Install node_exporter on each seed node
  - Install process-exporter for dilithion-node process
  - Verify metrics collection in Prometheus
  - Verify dashboard displays in Grafana
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-7:** Configure alerting
  - Run: `scripts/alert-handler-2025-11-07.sh --setup`
  - Configure: Email, Slack, Discord, or Telegram
  - Test: `scripts/alert-handler-2025-11-07.sh --test`
  - Set up cron: `*/5 * * * * /path/to/alert-handler-2025-11-07.sh --check`
  - **Status:** ⏳ PENDING

### 1.3 Website & Communication

- [ ] 🟠 **T-10:** Official website live
  - Domain: dilithion.org (or similar)
  - SSL certificate: Let's Encrypt or commercial
  - Content:
    - Project overview
    - Whitepaper
    - Download links
    - Documentation links
    - Community channels
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-10:** Documentation published
  - Host: GitHub Pages, website, or both
  - Content:
    - MAINNET-NODE-SETUP-2025-11-07.md
    - MAINNET-MINING-GUIDE-2025-11-07.md
    - MAINNET-WALLET-GUIDE-2025-11-07.md
    - TROUBLESHOOTING-2025-11-07.md
    - SECURITY-BEST-PRACTICES
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-10:** Community channels established
  - **Discord server:** Created and moderated
  - **Telegram group:** Created and moderated
  - **Reddit:** r/Dilithion created
  - **Twitter/X:** @DilithionCoin (or similar)
  - **GitHub:** Discussions enabled
  - **Status:** ⏳ PENDING

- [ ] 🟡 **T-7:** GitHub release prepared
  - Tag: v1.0.0-mainnet
  - Release notes: Comprehensive changelog
  - Binaries: Linux (x86_64), Windows (x64), macOS (Intel + ARM)
  - Checksums: SHA256 for all binaries
  - Signatures: GPG signatures (if implemented)
  - **Status:** ⏳ PENDING

---

## 2. Binary Preparation

### 2.1 Build Process

- [ ] 🔴 **T-7:** Final code freeze
  - No more code changes except critical fixes
  - All tests passing (251/251)
  - All fuzzers passing (11/11, zero crashes)
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-7:** Build release binaries
  - **Linux (x86_64):**
    - Ubuntu 20.04 (compatibility)
    - `make clean && make -j$(nproc) CXXFLAGS="-O3 -march=x86-64"`
  - **Windows (x64):**
    - MSYS2/MinGW-w64
    - Cross-compile or native build
  - **macOS (Intel):**
    - macOS 10.15+ compatible
    - `make clean && make -j$(sysctl -n hw.ncpu)`
  - **macOS (ARM):**
    - Apple Silicon (M1/M2/M3)
    - Native ARM64 build
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-7:** Generate checksums
  - Linux: `sha256sum dilithion-node > dilithion-node-linux-x86_64-v1.0.0.sha256`
  - Windows: `sha256sum dilithion-node.exe > dilithion-node-windows-x64-v1.0.0.sha256`
  - macOS Intel: `shasum -a 256 dilithion-node > dilithion-node-macos-intel-v1.0.0.sha256`
  - macOS ARM: `shasum -a 256 dilithion-node > dilithion-node-macos-arm64-v1.0.0.sha256`
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-7:** Sign binaries with GPG
  - Generate GPG key if not exists
  - Sign each binary: `gpg --detach-sign --armor dilithion-node`
  - Publish public key to key servers
  - Document key fingerprint on website
  - **Status:** ⚠️ BLOCKED (GPG key setup needed)

- [ ] 🟡 **T-7:** Test binaries on clean systems
  - Test each platform on fresh VM/container
  - Verify: `--version`, `--help`, start node, sync blocks
  - **Status:** ⏳ PENDING

### 2.2 Distribution

- [ ] 🔴 **T-5:** Upload binaries to GitHub releases
  - Release: v1.0.0-mainnet
  - Files: All binaries, checksums, signatures
  - **Status:** ⏳ PENDING

- [ ] 🟡 **T-5:** Create installers (optional)
  - Windows: NSIS installer
  - macOS: DMG package
  - Linux: .deb, .rpm packages
  - **Status:** ⏳ OPTIONAL

- [ ] 🟡 **T-5:** Mirror binaries to CDN
  - Reduce load on GitHub
  - Faster downloads worldwide
  - **Status:** ⏳ OPTIONAL

---

## 3. Testing & Verification

### 3.1 Testnet Final Testing

- [ ] 🔴 **T-10:** Testnet stress test
  - High transaction volume
  - Multiple miners
  - Network splits and recovery
  - Duration: 48+ hours
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-10:** Upgrade test (testnet)
  - Simulate mainnet upgrade path
  - Test: `scripts/update-node-2025-11-07.sh`
  - Verify: Node continues operating after update
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-7:** Performance benchmarks
  - Transaction throughput: Target 10-20 tx/sec
  - Block propagation time: <5 seconds
  - Sync time: Document time to sync from genesis
  - Memory usage: <2GB for non-mining, <4GB for mining
  - **Status:** ⏳ PENDING

### 3.2 Mainnet Preparation Testing

- [ ] 🔴 **T-5:** Genesis block generation test
  - Test time: Genesis time must be exactly 1767225600 (Jan 1, 2026 00:00:00 UTC)
  - Test nonce: Verify genesis block can be mined
  - Test validation: Ensure genesis block validates correctly
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-5:** Multi-platform sync test
  - Linux node ↔ Windows node ↔ macOS node
  - Verify: All nodes see same chain
  - Verify: Block propagation works cross-platform
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-5:** Wallet functionality test
  - Create wallet
  - Encrypt wallet
  - Generate address
  - Create and sign transaction
  - Broadcast transaction
  - Receive confirmation
  - Backup and restore wallet
  - **Status:** ⏳ PENDING

### 3.3 Security Verification

- [ ] 🔴 **T-3:** Run final security scan
  - Execute: `scripts/security-scan-2025-11-07.sh --report`
  - Verify: Zero critical issues
  - Address: All high-priority issues
  - Document: Scan results
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-3:** Review security checklist
  - Document: `docs/SECURITY-CHECKLIST-2025-11-07.md`
  - Verify: All CRITICAL items complete
  - Verify: All HIGH items complete or documented exceptions
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-3:** External security review (if available)
  - Independent security researcher review
  - Bug bounty program announcement
  - **Status:** ⏳ OPTIONAL

---

## 4. Launch Team Preparation

### 4.1 Team Roles

- [ ] 🔴 **T-7:** Assign launch roles
  - **Launch Coordinator:** Overall responsibility
  - **Infrastructure Lead:** Seed nodes, monitoring
  - **Communications Lead:** Announcements, community
  - **Security Lead:** Security monitoring, incident response
  - **Support Lead:** User support, troubleshooting
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-3:** Launch team briefing
  - Review launch timeline
  - Review incident response procedures
  - Review communication protocols
  - Verify all team members have access to systems
  - **Status:** ⏳ PENDING

### 4.2 Procedures & Documentation

- [ ] 🔴 **T-7:** Incident response plan
  - 51% attack response
  - Network split response
  - Critical bug discovery response
  - Eclipse attack response
  - Contact tree for escalation
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-7:** Communication templates
  - Launch announcement
  - Known issues announcement
  - Emergency notice template
  - Update announcement template
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-3:** Support documentation
  - Common issues and solutions
  - Troubleshooting flowcharts
  - FAQ document
  - Support ticket templates
  - **Status:** ⏳ PENDING

### 4.3 Contact Information

- [ ] 🔴 **T-3:** Emergency contacts updated
  - All team members' contact information
  - Escalation procedures
  - 24/7 coverage schedule (first week)
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-3:** External contacts identified
  - Exchanges (for coordination if needed)
  - Block explorers (for listing)
  - Media contacts (for announcements)
  - **Status:** ⏳ PENDING

---

## 5. Launch Day Preparations

### 5.1 T-1 Day (December 31, 2025)

- [ ] 🔴 **T-1:** All seed nodes operational
  - Health check: All 5-10 seed nodes running
  - Connectivity: All seed nodes reachable
  - Synchronization: All seed nodes on same (empty) chain
  - Resources: CPU, memory, disk space adequate
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-1:** Monitoring fully operational
  - Prometheus: Collecting metrics from all seed nodes
  - Grafana: Dashboards displaying correctly
  - Alerts: All alert channels tested and working
  - Health checks: Running every 5 minutes
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-1:** Binaries verified and ready
  - All binaries uploaded to GitHub releases
  - Checksums verified
  - Signatures verified (if applicable)
  - Download links tested
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-1:** Website and documentation live
  - Website accessible
  - Documentation complete and accessible
  - Download links working
  - Community channels active
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-1:** Launch team ready
  - All team members briefed
  - All team members have system access
  - Communication channels open
  - 24/7 coverage scheduled
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-1:** Announcements prepared
  - Launch announcement drafted
  - Social media posts scheduled
  - Email newsletter drafted (if applicable)
  - **Status:** ⏳ PENDING

### 5.2 T-0 (Launch - January 1, 2026 00:00:00 UTC)

- [ ] 🔴 **00:00 UTC:** Genesis block creation
  - Ensure system clocks synchronized (NTP)
  - Start seed nodes at exactly 00:00:00 UTC
  - Verify genesis block hash matches expectations
  - **Expected Genesis Hash:** TBD (after mining)
  - **Status:** ⏳ LAUNCH DAY

- [ ] 🔴 **00:05 UTC:** Network verification
  - Seed nodes connected to each other
  - Genesis block propagated
  - No errors in logs
  - Monitoring shows healthy status
  - **Status:** ⏳ LAUNCH DAY

- [ ] 🔴 **00:10 UTC:** Public announcement
  - Post launch announcement to all channels
  - Update website with "LIVE" status
  - Share download links
  - Announce on social media
  - **Status:** ⏳ LAUNCH DAY

- [ ] 🟠 **00:15 UTC:** First block mined
  - Monitor for first mined block (block 1)
  - Expected time: ~9 hours with genesis difficulty
  - Verify block propagates correctly
  - **Status:** ⏳ LAUNCH DAY

---

## 6. Post-Launch Monitoring

### 6.1 First Hour (T+1 Hour)

- [ ] 🔴 **T+1h:** Network health check
  - All seed nodes operational
  - Peer connections established
  - No critical alerts
  - Monitoring dashboards healthy
  - **Status:** ⏳ POST-LAUNCH

- [ ] 🟠 **T+1h:** Community activity check
  - Monitor social media for issues
  - Respond to early adopter questions
  - Watch for problem reports
  - **Status:** ⏳ POST-LAUNCH

### 6.2 First Day (T+24 Hours)

- [ ] 🔴 **T+24h:** First block verification
  - First block should be mined (if difficulty correct)
  - Verify block propagation
  - Verify nodes sync correctly
  - **Status:** ⏳ POST-LAUNCH

- [ ] 🟠 **T+24h:** Mining distribution check
  - Monitor: Is mining decentralized?
  - Monitor: Multiple miners participating?
  - Monitor: Reasonable hashrate distribution?
  - **Status:** ⏳ POST-LAUNCH

- [ ] 🟠 **T+24h:** User feedback review
  - Compile common issues
  - Update FAQ based on feedback
  - Address any critical bugs
  - **Status:** ⏳ POST-LAUNCH

### 6.3 First Week (T+7 Days)

- [ ] 🟠 **T+7d:** Network statistics
  - Total nodes: Target 50+ nodes
  - Hash rate: Sufficient for security
  - Block time: Averaging 4 minutes
  - Difficulty adjustment: Working correctly
  - **Status:** ⏳ POST-LAUNCH

- [ ] 🟠 **T+7d:** Security review
  - No attacks detected
  - No critical vulnerabilities discovered
  - No consensus issues
  - **Status:** ⏳ POST-LAUNCH

- [ ] 🟠 **T+7d:** Community growth
  - Active community in Discord/Telegram
  - Documentation being used
  - Support requests being handled
  - **Status:** ⏳ POST-LAUNCH

- [ ] 🟡 **T+7d:** Exchange outreach (if desired)
  - Prepare exchange listing materials
  - Contact exchanges for potential listing
  - **Status:** ⏳ OPTIONAL

### 6.4 First Month (T+30 Days)

- [ ] 🟡 **T+30d:** First difficulty adjustment
  - Verify: Difficulty adjustment works correctly
  - Occurs at block 2016
  - **Status:** ⏳ POST-LAUNCH

- [ ] 🟡 **T+30d:** Post-launch retrospective
  - What went well?
  - What could be improved?
  - Lessons learned
  - Plan improvements
  - **Status:** ⏳ POST-LAUNCH

---

## 7. Rollback Plan

### 7.1 Emergency Rollback Scenarios

- [ ] 🔴 **T-3:** Document rollback scenarios
  - Critical security vulnerability discovered
  - Consensus bug causing chain split
  - Genesis block parameter error
  - Network unable to mine blocks
  - **Status:** ⏳ PENDING

- [ ] 🔴 **T-3:** Rollback communication plan
  - How to announce delay/rollback
  - How to communicate with early adopters
  - How to coordinate new launch date
  - **Status:** ⏳ PENDING

### 7.2 Emergency Procedures

- [ ] 🟠 **T-3:** Emergency shutdown procedure
  - How to safely stop seed nodes
  - How to prevent further block production
  - How to communicate emergency
  - **Status:** ⏳ PENDING

- [ ] 🟠 **T-3:** Emergency patch procedure
  - How to quickly deploy critical fixes
  - How to coordinate with community
  - How to maintain trust
  - **Status:** ⏳ PENDING

---

## Summary Status

### Completion Tracking

| Phase | Total | Complete | In Progress | Pending | Blocked |
|-------|-------|----------|-------------|---------|---------|
| 1. Infrastructure | 11 | 0 | 2 | 8 | 1 |
| 2. Binary Prep | 8 | 0 | 0 | 7 | 1 |
| 3. Testing | 10 | 0 | 0 | 10 | 0 |
| 4. Team Prep | 10 | 0 | 0 | 10 | 0 |
| 5. Launch Day | 9 | 0 | 0 | 9 | 0 |
| 6. Post-Launch | 10 | 0 | 0 | 10 | 0 |
| 7. Rollback Plan | 4 | 0 | 0 | 4 | 0 |
| **TOTAL** | **62** | **0 (0%)** | **2 (3%)** | **58 (94%)** | **2 (3%)** |

### Critical Path Items

1. **Seed Nodes** - Must be set up and configured (T-14)
2. **DNS Seeds** - Must be registered (T-10)
3. **Code Update** - Seed nodes added to chainparams.cpp (T-7)
4. **Binary Build** - Release binaries built and tested (T-7)
5. **Security Scan** - Final security verification (T-3)
6. **Team Ready** - Launch team briefed and ready (T-1)
7. **Launch** - Genesis block creation at 00:00:00 UTC (T-0)

### Current Status

**Overall:** 🔴 **NOT READY FOR LAUNCH**

**Blocking Issues:**
1. Seed nodes not yet provisioned
2. DNS seeds not yet registered
3. GPG signing key not yet generated

**Estimated Time to Ready:** 2-3 weeks (with seed node setup)

---

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Launch Coordinator | _______________ | __________ | _____ |
| Infrastructure Lead | _______________ | __________ | _____ |
| Security Lead | _______________ | __________ | _____ |
| Communications Lead | _______________ | __________ | _____ |

**Final Approval:**

- [ ] All CRITICAL items complete
- [ ] Security checklist reviewed and approved
- [ ] Incident response plan in place
- [ ] Team ready for 24/7 coverage (first week)
- [ ] GO / NO-GO decision: _______________

---

**Document Maintained By:** Launch Coordinator
**Last Updated:** November 7, 2025
**Next Review:** Daily until launch

---

*This checklist must be reviewed and updated daily during the countdown to launch* ✓

---

**Related Documents:**
- [SECURITY-CHECKLIST-2025-11-07.md](../docs/SECURITY-CHECKLIST-2025-11-07.md) - Security verification
- [SECURITY-AUDIT-2025-11-07.md](../SECURITY-AUDIT-2025-11-07.md) - Security audit report
- [THREAT-MODEL-2025-11-07.md](../docs/THREAT-MODEL-2025-11-07.md) - Threat analysis
- [PRODUCTION-DEPLOYMENT-PLAN.md](../PRODUCTION-DEPLOYMENT-PLAN.md) - Overall deployment plan

---

*Dilithion Mainnet - Launch with Confidence* 🚀
