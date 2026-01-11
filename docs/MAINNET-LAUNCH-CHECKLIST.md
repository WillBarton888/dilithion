# Dilithion Mainnet Launch Checklist

**Target Launch Date:** TBD
**Last Updated:** 2026-01-11
**Current Status:** ~75% Ready (2 Critical Blockers)

---

## PHASE 1: CRITICAL BLOCKERS (Week 1)

### 1.1 Seed Node Infrastructure
**Status:** NOT STARTED | **Blocker:** YES | **Effort:** 1-2 days

- [ ] Provision 5-10 VPS servers globally:
  - [ ] North America (2 nodes): NYC, LA or Toronto
  - [ ] Europe (2 nodes): London, Frankfurt or Amsterdam
  - [ ] Asia (2 nodes): Singapore, Tokyo or Hong Kong
  - [ ] South America (1 node): São Paulo
  - [ ] Oceania (1 node): Sydney
- [ ] Configure each server:
  - [ ] Ubuntu 22.04 LTS
  - [ ] 4GB RAM minimum
  - [ ] 100GB SSD minimum
  - [ ] Static IP address
- [ ] Install Dilithion on each seed node
- [ ] Create systemd service for auto-restart:
  ```
  /etc/systemd/system/dilithion.service
  ```
- [ ] Configure firewall (UFW):
  - [ ] Allow port 8444 (P2P mainnet)
  - [ ] Allow port 8445 (RPC - localhost only)
- [ ] Update `src/net/peers.cpp` InitializeSeedNodes() with mainnet IPs
- [ ] Register DNS records:
  - [ ] seed1.dilithion.org
  - [ ] seed2.dilithion.org
  - [ ] seed3.dilithion.org
  - [ ] (etc.)
- [ ] Configure DNS seeds in `src/net/dns.cpp`
- [ ] Test seed node connectivity from multiple locations
- [ ] Set up monitoring/alerting for each seed node

### 1.2 Extended Stability Testing
**Status:** IN PROGRESS | **Blocker:** YES | **Effort:** 7-14 days

- [ ] **Mining Test (1000+ blocks)**
  - [ ] Mine continuously for 7+ days
  - [ ] Verify block times average ~240 seconds
  - [ ] Check difficulty adjustments every 2016 blocks
  - [ ] Confirm no orphan rate > 1%

- [ ] **Transaction Test (1000+ transactions)**
  - [ ] Send transactions between multiple wallets
  - [ ] Verify mempool propagation
  - [ ] Test transaction confirmation times
  - [ ] Check fee estimation accuracy

- [ ] **Stability Test (24+ hours)**
  - [ ] Zero crashes over 24 hours
  - [ ] Memory usage stable (no leaks)
  - [ ] CPU usage reasonable under load
  - [ ] Disk usage growth as expected

- [ ] **Network Resilience Tests**
  - [ ] Peer disconnect/reconnect
  - [ ] Network partition simulation
  - [ ] Seed node failure recovery
  - [ ] IBD from scratch (new node sync)

- [ ] **Database Recovery Tests**
  - [ ] Graceful shutdown recovery
  - [ ] Hard kill (SIGKILL) recovery
  - [ ] Corrupt database detection
  - [ ] -reindex functionality

---

## PHASE 2: HIGH PRIORITY (Week 2)

### 2.1 Security Fixes
**Status:** 56% Complete | **Effort:** 2-3 days

- [ ] Review remaining 8 HIGH priority security issues
- [ ] Fix identified vulnerabilities:
  - [ ] Network protocol edge cases
  - [ ] Memory management in hot paths
  - [ ] Input validation in consensus code
- [ ] Re-run security audit after fixes
- [ ] Document security mitigations

### 2.2 Test Suite Completion
**Status:** 87% CI Passing | **Effort:** 1-2 days

- [ ] Fix remaining C++ test failures (1/14 failing)
- [ ] Fix Python functional test mock data issues (4/17 failing)
- [ ] Achieve 100% CI pass rate
- [ ] Run full test suite on all platforms:
  - [ ] Linux
  - [ ] macOS
  - [ ] Windows
- [ ] Verify fuzzing harnesses all pass

### 2.3 Code Cleanup
**Status:** Not Started | **Effort:** 1 day

- [ ] Remove testnet-only code from mainnet build
- [ ] Update version strings to mainnet
- [ ] Review and remove debug logging
- [ ] Ensure no hardcoded testnet values
- [ ] Update chainparams for mainnet:
  - [ ] Genesis block hash
  - [ ] Network magic bytes
  - [ ] Default ports (8444/8445)

---

## PHASE 3: DOCUMENTATION (Week 2-3)

### 3.1 Operational Documentation
**Status:** Partial | **Effort:** 1-2 days

- [ ] Create `docs/operations/SEED-NODE-SETUP.md`
- [ ] Create `docs/operations/MONITORING.md`
- [ ] Create `docs/operations/BACKUP-RECOVERY.md`
- [ ] Create `docs/operations/INCIDENT-RESPONSE.md`
- [ ] Document database backup procedures
- [ ] Document wallet backup procedures

### 3.2 User Documentation Updates
**Status:** Good | **Effort:** 0.5 days

- [ ] Update USER-GUIDE.md for mainnet
- [ ] Update MINING-GUIDE.md for mainnet
- [ ] Update API-DOCUMENTATION.md
- [ ] Create FAQ document
- [ ] Update README.md with mainnet info

### 3.3 Emergency Procedures
**Status:** Not Started | **Effort:** 1 day

- [ ] Document chain halt procedure
- [ ] Document emergency patch deployment
- [ ] Document rollback procedure
- [ ] Create communication templates:
  - [ ] Security advisory template
  - [ ] Network issue template
  - [ ] Planned maintenance template
- [ ] Establish communication channels:
  - [ ] Discord/Telegram for community
  - [ ] Email list for critical updates

---

## PHASE 4: PRE-LAUNCH VALIDATION (Week 3)

### 4.1 Final Testing
**Status:** Not Started | **Effort:** 2-3 days

- [ ] Complete 7-day stability test with zero issues
- [ ] Verify all seed nodes operational
- [ ] Test IBD from genesis on fresh node
- [ ] Test wallet creation and recovery
- [ ] Test mining on multiple platforms
- [ ] Verify block explorer integration (if applicable)

### 4.2 Genesis Block Preparation
**Status:** Not Started | **Effort:** 0.5 days

- [ ] Generate mainnet genesis block
- [ ] Verify genesis block hash
- [ ] Update chainparams with genesis data
- [ ] Document genesis block creation process
- [ ] Backup genesis generation parameters

### 4.3 Release Preparation
**Status:** Not Started | **Effort:** 1 day

- [ ] Create mainnet release tag (v2.0.0)
- [ ] Build release binaries:
  - [ ] Linux x64
  - [ ] macOS x64/ARM64
  - [ ] Windows x64
- [ ] Create bootstrap file from testnet (optional)
- [ ] Write release notes
- [ ] Prepare announcement blog post

---

## PHASE 5: LAUNCH DAY

### 5.1 Pre-Launch (T-24 hours)
- [ ] Final seed node health check
- [ ] Verify all binaries downloadable
- [ ] Test download links
- [ ] Prepare monitoring dashboards
- [ ] Alert team members

### 5.2 Launch (T-0)
- [ ] Start seed nodes with mainnet genesis
- [ ] Verify peer connectivity
- [ ] Announce launch on all channels
- [ ] Monitor for issues
- [ ] First block mined

### 5.3 Post-Launch (T+24 hours)
- [ ] Verify network stability
- [ ] Check block propagation
- [ ] Monitor peer count growth
- [ ] Address any reported issues
- [ ] Publish "Launch Success" update

---

## PHASE 6: POST-LAUNCH (Week 1-4)

### 6.1 Immediate (Week 1)
- [ ] 24/7 monitoring for first week
- [ ] Rapid response to any issues
- [ ] Daily status updates
- [ ] Community support active

### 6.2 Stabilization (Week 2-4)
- [ ] Reduce monitoring intensity
- [ ] Address non-critical bugs
- [ ] Gather user feedback
- [ ] Plan v2.1 improvements

### 6.3 Future Enhancements (Backlog)
- [ ] Multi-signature wallet support
- [ ] Hardware wallet integration
- [ ] Mobile wallet development
- [ ] Block explorer improvements
- [ ] Mining pool software
- [ ] Exchange integration support

---

## TRACKING

### Progress Summary

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: Critical Blockers | 🔴 Not Started | 0% |
| Phase 2: High Priority | 🟡 Partial | 50% |
| Phase 3: Documentation | 🟡 Partial | 40% |
| Phase 4: Pre-Launch | ⚪ Not Started | 0% |
| Phase 5: Launch Day | ⚪ Not Started | 0% |
| Phase 6: Post-Launch | ⚪ Not Started | 0% |

### Timeline

```
Week 1: Phase 1 (Critical Blockers)
        - Deploy seed nodes
        - Start extended testing

Week 2: Phase 2 (High Priority) + Phase 3 (Documentation)
        - Security fixes
        - Test suite completion
        - Operational docs

Week 3: Phase 4 (Pre-Launch Validation)
        - Final testing
        - Genesis preparation
        - Release preparation

Week 4: Phase 5 (Launch) + Phase 6 (Post-Launch)
        - MAINNET LAUNCH
        - Monitoring & support
```

### Contacts

| Role | Name | Contact |
|------|------|---------|
| Lead Developer | | |
| DevOps | | |
| Security | | |
| Community | | |

---

## NOTES

- This checklist should be reviewed daily during launch preparation
- Any blockers should be escalated immediately
- All changes should go through code review
- Keep backups of all critical data
- Document everything

---

*Last reviewed: 2026-01-11*
