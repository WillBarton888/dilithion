# Dilithion Mainnet Tasks - Detailed Breakdown
**Date:** December 2025  
**Purpose:** Actionable task list for mainnet deployment  
**Target Launch:** January 1, 2026 00:00:00 UTC

---

## 📋 Task Organization

Tasks are organized by:
- **Priority:** CRITICAL → HIGH → MEDIUM → LOW
- **Estimated Time:** Per task (hours/days)
- **Dependencies:** What must be done first
- **Status:** ✅ Complete | ⏳ In Progress | ⬜ Pending

---

## 🔴 CRITICAL TASKS (Must Complete Before Mainnet)

### Task Group 1: Seed Node Infrastructure
**Total Time:** 1-2 days  
**Blocking:** YES

#### Task 1.1: Provision Seed Node Servers
**Time:** 2-4 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Create account with cloud provider (DigitalOcean/AWS/Linode)
- [ ] Provision 5-10 VPS instances:
  - [ ] Seed 1: North America (NYC/SF) - 2GB RAM, 2 cores, 50GB SSD
  - [ ] Seed 2: Europe (London/Frankfurt) - 2GB RAM, 2 cores, 50GB SSD
  - [ ] Seed 3: Asia (Singapore/Tokyo) - 2GB RAM, 2 cores, 50GB SSD
  - [ ] Seed 4: South America (São Paulo) - Optional
  - [ ] Seed 5: Australia (Sydney) - Optional
- [ ] Record all IP addresses in spreadsheet
- [ ] Verify static IPs (no dynamic IPs)

**Deliverable:** List of 5-10 seed node IPs with locations

---

#### Task 1.2: Install Dilithion on Seed Nodes
**Time:** 1-2 hours per node (5-10 hours total)  
**Status:** ⬜ PENDING  
**Dependencies:** Task 1.1

**Actions (repeat for each node):**
- [ ] SSH into node: `ssh root@<IP>`
- [ ] Update system: `apt update && apt upgrade -y`
- [ ] Install dependencies: `apt install -y build-essential git cmake libleveldb-dev libssl-dev`
- [ ] Clone repository: `git clone https://github.com/WillBarton888/dilithion.git`
- [ ] Build RandomX: `cd depends/randomx && mkdir build && cd build && cmake .. && make -j$(nproc)`
- [ ] Build Dilithium: `cd ../../dilithium/ref && make -j$(nproc)`
- [ ] Build node: `cd ../../.. && make dilithion-node`
- [ ] Verify build: `./dilithion-node --version`
- [ ] Test run: `./dilithion-node --testnet` (verify it starts)

**Deliverable:** All seed nodes have working `dilithion-node` binary

**Note:** Script exists: `scripts/install-mainnet-2025-11-07.sh` - can automate this

---

#### Task 1.3: Configure Systemd Service
**Time:** 30 minutes per node (2.5-5 hours total)  
**Status:** ⬜ PENDING  
**Dependencies:** Task 1.2

**Actions (repeat for each node):**
- [ ] Copy service file: `cp deployment/systemd/dilithion-2025-11-07.service /etc/systemd/system/dilithion.service`
- [ ] Edit service file:
  - [ ] Set correct `WorkingDirectory`
  - [ ] Set correct `ExecStart` path
  - [ ] Configure `--datadir` path
  - [ ] Set `--port=8444` (mainnet P2P port)
  - [ ] Set `--rpcport=8332` (mainnet RPC port)
- [ ] Reload systemd: `systemctl daemon-reload`
- [ ] Enable service: `systemctl enable dilithion`
- [ ] Start service: `systemctl start dilithion`
- [ ] Check status: `systemctl status dilithion`
- [ ] Verify logs: `journalctl -u dilithion -n 50`

**Deliverable:** All seed nodes running as systemd service

**Note:** Service file exists: `deployment/systemd/dilithion-2025-11-07.service`

---

#### Task 1.4: Configure Firewall
**Time:** 15 minutes per node (1.25-2.5 hours total)  
**Status:** ⬜ PENDING  
**Dependencies:** Task 1.3

**Actions (repeat for each node):**
- [ ] Allow SSH: `ufw allow 22/tcp`
- [ ] Allow P2P port: `ufw allow 8444/tcp`
- [ ] Block RPC from external: `ufw deny 8332/tcp` (or allow only from monitoring IP)
- [ ] Enable firewall: `ufw --force enable`
- [ ] Verify rules: `ufw status`
- [ ] Test P2P port: `nc -zv <IP> 8444` (from another machine)

**Deliverable:** All seed nodes have proper firewall rules

---

#### Task 1.5: Update Code with Seed Node IPs
**Time:** 30 minutes  
**Status:** ⬜ PENDING  
**Dependencies:** Task 1.1

**Actions:**
- [ ] Open `src/net/peers.cpp`
- [ ] Find `InitializeSeedNodes()` function (around line 422)
- [ ] Replace testnet IPs with mainnet seed node IPs:
  ```cpp
  // MAINNET SEED NODE #1: NYC
  NetProtocol::CAddress seed_nyc;
  seed_nyc.services = NetProtocol::NODE_NETWORK;
  seed_nyc.SetIPv4(0xXXXXXXXX);  // Replace with actual IP
  seed_nyc.port = 8444;  // Mainnet port
  seed_nyc.time = GetTime();
  seed_nodes.push_back(seed_nyc);
  // Repeat for all seed nodes
  ```
- [ ] Update DNS seeds (if DNS configured):
  ```cpp
  dns_seeds = {
      "seed.dilithion.com",
      "seed1.dilithion.com",
      "seed2.dilithion.com",
  };
  ```
- [ ] Commit changes: `git commit -m "Add mainnet seed nodes"`
- [ ] Push to repository

**Deliverable:** Code updated with mainnet seed node IPs

---

#### Task 1.6: Configure DNS Records (Optional but Recommended)
**Time:** 1 hour  
**Status:** ⬜ PENDING  
**Dependencies:** Task 1.1, Domain ownership

**Actions:**
- [ ] Log into domain registrar (e.g., Webcentral)
- [ ] Navigate to DNS management for `dilithion.com` (or `.org`)
- [ ] Add A records:
  - [ ] `seed.dilithion.com` → Seed 1 IP
  - [ ] `seed1.dilithion.com` → Seed 1 IP
  - [ ] `seed2.dilithion.com` → Seed 2 IP
  - [ ] `seed3.dilithion.com` → Seed 3 IP
- [ ] Set TTL: 300 seconds (5 minutes)
- [ ] Wait 5-10 minutes
- [ ] Verify DNS: `nslookup seed.dilithion.com`
- [ ] Test from node: `dig seed.dilithion.com`

**Deliverable:** DNS records pointing to seed nodes

---

#### Task 1.7: Set Up Monitoring (Basic)
**Time:** 2-3 hours  
**Status:** ⬜ PENDING  
**Dependencies:** Task 1.3

**Actions:**
- [ ] Choose monitoring solution (Prometheus + Grafana, or simple health checks)
- [ ] Install monitoring agent on each seed node (or use SSH-based checks)
- [ ] Configure health check script:
  ```bash
  #!/bin/bash
  # Check if dilithion-node is running
  systemctl is-active dilithion || exit 1
  # Check if port 8444 is listening
  netstat -tuln | grep 8444 || exit 1
  # Check RPC (optional)
  curl -s http://localhost:8332 -X POST -d '{"jsonrpc":"2.0","method":"getblockcount","id":1}' || exit 1
  ```
- [ ] Set up alerting (email/Slack) for downtime
- [ ] Test alerting by stopping service

**Deliverable:** Basic monitoring and alerting for seed nodes

---

### Task Group 2: Extended Testnet Stability Testing
**Total Time:** 7-14 days (continuous, parallel with other work)  
**Blocking:** YES

#### Task 2.1: Set Up Multi-Node Testnet
**Time:** 2-3 hours  
**Status:** ⏳ IN PROGRESS (partially done)  
**Dependencies:** None

**Actions:**
- [ ] Deploy 5+ nodes on different machines/VPS
- [ ] Configure nodes to connect to each other
- [ ] Start all nodes simultaneously
- [ ] Verify all nodes connect and sync
- [ ] Document node IPs and configuration

**Deliverable:** 5+ node testnet network running

**Current Status:** 3 nodes running (NYC, London, Singapore)

---

#### Task 2.2: 24-Hour Continuous Operation Test
**Time:** 24 hours (monitoring)  
**Status:** ⬜ PENDING  
**Dependencies:** Task 2.1

**Actions:**
- [ ] Start all nodes
- [ ] Monitor for 24 hours:
  - [ ] Check every 2 hours: Are all nodes running?
  - [ ] Check every 2 hours: Are all nodes at same height?
  - [ ] Check logs for errors/crashes
  - [ ] Monitor memory usage (check for leaks)
  - [ ] Monitor CPU usage
- [ ] Document any issues found
- [ ] Fix any crashes/hangs found

**Deliverable:** 24-hour stability report

**Success Criteria:**
- Zero crashes
- All nodes maintain consensus
- Memory usage stable (no leaks)
- CPU usage reasonable

---

#### Task 2.3: 1000+ Block Mining Test
**Time:** 2-3 days (mining time)  
**Status:** ⬜ PENDING  
**Dependencies:** Task 2.1

**Actions:**
- [ ] Enable mining on one node
- [ ] Mine 1000+ blocks
- [ ] Monitor:
  - [ ] Block propagation time
  - [ ] All nodes receive all blocks
  - [ ] Consensus maintained
  - [ ] No orphan blocks
- [ ] Document results

**Deliverable:** 1000+ block mining test report

**Success Criteria:**
- 100% block propagation success
- All nodes at same height
- Zero orphan blocks

---

#### Task 2.4: 1000+ Transaction Test
**Time:** 1-2 days  
**Status:** ⬜ PENDING  
**Dependencies:** Task 2.1

**Actions:**
- [ ] Create script to send 1000+ transactions
- [ ] Send transactions across network
- [ ] Monitor:
  - [ ] Mempool size
  - [ ] Transaction propagation
  - [ ] UTXO set growth
  - [ ] Memory usage
- [ ] Verify all transactions confirmed
- [ ] Document results

**Deliverable:** 1000+ transaction test report

**Success Criteria:**
- All transactions confirmed
- Mempool doesn't overflow
- UTXO set correct

---

#### Task 2.5: Network Partition Recovery Test
**Time:** 2-3 hours  
**Status:** ⬜ PENDING  
**Dependencies:** Task 2.1

**Actions:**
- [ ] Split network into two partitions (block firewall)
- [ ] Mine blocks in each partition
- [ ] Reconnect partitions
- [ ] Verify:
  - [ ] Longer chain wins
  - [ ] Shorter chain reorganizes
  - [ ] Consensus restored
- [ ] Document results

**Deliverable:** Network partition recovery test report

---

#### Task 2.6: Peer Disconnect/Reconnect Test
**Time:** 1-2 hours  
**Status:** ⬜ PENDING  
**Dependencies:** Task 2.1

**Actions:**
- [ ] Disconnect a peer (stop node or block firewall)
- [ ] Mine blocks on remaining nodes
- [ ] Reconnect peer
- [ ] Verify:
  - [ ] Peer syncs missing blocks
  - [ ] Consensus restored
  - [ ] No errors in logs
- [ ] Repeat with multiple peers
- [ ] Document results

**Deliverable:** Peer reconnect test report

---

#### Task 2.7: Database Corruption Recovery Test
**Time:** 1-2 hours  
**Status:** ⬜ PENDING  
**Dependencies:** Task 2.1

**Actions:**
- [ ] Stop a node
- [ ] Corrupt database (delete some files or modify data)
- [ ] Start node with `-reindex` flag
- [ ] Verify:
  - [ ] Node rebuilds index
  - [ ] Node syncs with network
  - [ ] Consensus restored
- [ ] Test `-rescan` flag
- [ ] Document results

**Deliverable:** Database recovery test report

---

## 🟡 HIGH PRIORITY TASKS (Recommended Before Mainnet)

### Task Group 3: Remaining Security Fixes
**Total Time:** 2-3 days  
**Blocking:** RECOMMENDED

#### Task 3.1: Review Remaining HIGH Priority Issues
**Time:** 2-3 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Read `audit/SECURITY-FIXES-STATUS-2025-11-11.md`
- [ ] List all 8 remaining HIGH priority issues
- [ ] Prioritize by severity/exploitability
- [ ] Create fix plan for each issue
- [ ] Estimate time per fix

**Deliverable:** Prioritized list of HIGH priority security fixes

---

#### Task 3.2: Fix HIGH Priority Issues (8 issues)
**Time:** 1-2 days  
**Status:** ⬜ PENDING  
**Dependencies:** Task 3.1

**Actions (repeat for each issue):**
- [ ] Read issue description
- [ ] Locate code in codebase
- [ ] Implement fix
- [ ] Write/update unit test
- [ ] Test fix
- [ ] Commit with descriptive message
- [ ] Document fix

**Deliverable:** All 8 HIGH priority issues fixed

**Files Likely Affected:**
- `src/consensus/pow.cpp`
- `src/consensus/chain.cpp`
- `src/consensus/validation.cpp`
- `src/consensus/tx_validation.cpp`

---

#### Task 3.3: Fix Critical MEDIUM Priority Issues
**Time:** 1 day  
**Status:** ⬜ PENDING  
**Dependencies:** Task 3.2

**Actions:**
- [ ] Review 11 MEDIUM priority issues
- [ ] Identify which are exploitable (vs. code quality)
- [ ] Fix exploitable MEDIUM issues (estimate 5-7 issues)
- [ ] Test fixes
- [ ] Document fixes

**Deliverable:** Critical MEDIUM priority issues fixed

---

### Task Group 4: Test Suite Completion
**Total Time:** 1-2 days  
**Blocking:** RECOMMENDED

#### Task 4.1: Fix Python Functional Test Failures
**Time:** 4-6 hours  
**Status:** ✅ MOSTLY DONE (mock data improved)  
**Dependencies:** None

**Actions:**
- [ ] Run Python functional tests: `cd test/functional && python3 test_runner.py`
- [ ] Identify failing tests (should be 4/17)
- [ ] For each failing test:
  - [ ] Read test code
  - [ ] Understand what it's testing
  - [ ] Improve `TestNode` mock data if needed
  - [ ] Or mark test as requiring real node (if appropriate)
- [ ] Re-run tests
- [ ] Document any tests that can't be fixed (require real node)

**Deliverable:** All Python functional tests passing (or documented as requiring real node)

**Note:** Mock data already improved in `test/functional/test_framework/test_framework.py`

---

#### Task 4.2: Fix Wallet Test Failures
**Time:** 2-4 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Run wallet tests: `./test_wallet` (or equivalent)
- [ ] Identify 2 failing tests
- [ ] Read test code to understand failures
- [ ] Fix fee calculation edge cases
- [ ] Fix script validation edge cases
- [ ] Re-run tests
- [ ] Document fixes

**Deliverable:** All wallet tests passing

---

#### Task 4.3: Verify CI Stability
**Time:** 1-2 hours  
**Status:** ⬜ PENDING  
**Dependencies:** Tasks 4.1, 4.2

**Actions:**
- [ ] Push changes to GitHub
- [ ] Monitor CI runs
- [ ] Verify all 15 jobs pass (or acceptable failures documented)
- [ ] Fix any CI failures
- [ ] Document CI status

**Deliverable:** CI stable with 13-15/15 jobs passing

---

## 🟢 MEDIUM PRIORITY TASKS (Not Blocking)

### Task Group 5: Performance Optimization
**Total Time:** 2-3 days  
**Blocking:** NO

#### Task 5.1: Add Performance Benchmarks
**Time:** 4-6 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Create `src/bench/` directory
- [ ] Add benchmark for IBD (block download speed)
- [ ] Add benchmark for mining (hash rate)
- [ ] Add benchmark for transaction validation
- [ ] Add benchmark for UTXO lookups
- [ ] Run benchmarks and document baseline

**Deliverable:** Performance benchmark suite

---

#### Task 5.2: Profile Critical Paths
**Time:** 4-6 hours  
**Status:** ⬜ PENDING  
**Dependencies:** Task 5.1

**Actions:**
- [ ] Profile IBD with `perf` or `gprof`
- [ ] Profile mining with `perf`
- [ ] Profile transaction validation
- [ ] Identify bottlenecks
- [ ] Document findings

**Deliverable:** Performance profiling report

---

#### Task 5.3: Optimize Identified Bottlenecks
**Time:** 1-2 days  
**Status:** ⬜ PENDING  
**Dependencies:** Task 5.2

**Actions:**
- [ ] Optimize top 3 bottlenecks
- [ ] Measure improvement
- [ ] Verify correctness
- [ ] Document optimizations

**Deliverable:** Performance improvements implemented

**Note:** Some optimizations already done (mining hot loop, per-thread RandomX VMs)

---

### Task Group 6: User Experience Improvements
**Total Time:** 1-2 days  
**Blocking:** NO

#### Task 6.1: Improve Error Messages
**Time:** 4-6 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Review common error messages
- [ ] Make messages user-friendly
- [ ] Add recovery guidance
- [ ] Test error scenarios
- [ ] Document improvements

**Deliverable:** Improved error messages

**Note:** `CErrorFormatter` already exists - use it more consistently

---

#### Task 6.2: Improve Help Text
**Time:** 2-3 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Review `--help` output
- [ ] Add descriptions for all options
- [ ] Add examples
- [ ] Test help output
- [ ] Document improvements

**Deliverable:** Improved help text

---

### Task Group 7: Network Resilience Enhancements
**Total Time:** 2-3 days  
**Blocking:** NO

#### Task 7.1: Enhanced Peer Discovery
**Time:** 1 day  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Review current peer discovery
- [ ] Add additional discovery methods (if needed)
- [ ] Test peer discovery
- [ ] Document improvements

**Deliverable:** Enhanced peer discovery

**Note:** `CPeerDiscovery` already exists - may be sufficient

---

#### Task 7.2: Connection Pool Improvements
**Time:** 1 day  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Review connection management
- [ ] Optimize connection pool
- [ ] Test with many peers
- [ ] Document improvements

**Deliverable:** Improved connection pool

**Note:** `CAsyncBroadcaster` already exists - async broadcasting implemented

---

## 🔵 LOW PRIORITY TASKS (Optional)

### Task Group 8: Documentation
**Total Time:** Ongoing  
**Blocking:** NO

#### Task 8.1: Expand API Documentation
**Time:** 4-6 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Review `docs/developer/API-DOCUMENTATION.md`
- [ ] Add missing RPC methods
- [ ] Add examples
- [ ] Add error codes
- [ ] Document WebSocket API
- [ ] Document TLS/SSL setup

**Deliverable:** Complete API documentation

---

#### Task 8.2: Add Architecture Diagrams
**Time:** 2-3 hours  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Create system architecture diagram
- [ ] Create network protocol diagram
- [ ] Create database schema diagram
- [ ] Add to `docs/ARCHITECTURE.md`

**Deliverable:** Architecture diagrams

---

### Task Group 9: Optional Enhancements
**Total Time:** 1-2 hours  
**Blocking:** NO

#### Task 9.1: Set Up Coverity Account
**Time:** 30 minutes  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Create account at https://scan.coverity.com/
- [ ] Create project "dilithion"
- [ ] Get token
- [ ] Add `COVERITY_TOKEN` secret to GitHub
- [ ] Add `COVERITY_EMAIL` secret to GitHub
- [ ] Push to main branch to trigger scan

**Deliverable:** Coverity scans running

---

#### Task 9.2: Submit OSS-Fuzz PR
**Time:** 1 hour  
**Status:** ⬜ PENDING  
**Dependencies:** None

**Actions:**
- [ ] Fork google/oss-fuzz
- [ ] Copy `projects/dilithion/` files (already created)
- [ ] Create PR
- [ ] Monitor PR status

**Deliverable:** OSS-Fuzz submission

---

## 📊 Task Summary

### By Priority

| Priority | Task Groups | Total Tasks | Estimated Time |
|----------|-------------|-------------|----------------|
| 🔴 CRITICAL | 2 groups | 13 tasks | 7-14 days + testing |
| 🟡 HIGH | 2 groups | 6 tasks | 3-5 days |
| 🟢 MEDIUM | 3 groups | 8 tasks | 5-8 days |
| 🔵 LOW | 2 groups | 4 tasks | 1-2 days |

### By Status

- ✅ **Complete:** 1 task (Python test mocks improved)
- ⏳ **In Progress:** 1 task (Multi-node testnet)
- ⬜ **Pending:** 30 tasks

### Critical Path

1. **Week 1:** Tasks 1.1-1.7 (Seed nodes) + Task 2.1-2.7 (Testing in parallel)
2. **Week 2:** Tasks 3.1-3.3 (Security fixes) + Tasks 4.1-4.3 (Test suite)
3. **Week 3:** Tasks 5.1-5.3 (Performance) + Tasks 6.1-6.2 (UX)
4. **Week 4:** Tasks 7.1-7.2 (Network) + Final validation

---

## 🎯 Quick Start Guide

### If You Have 1 Day:
Focus on **Task Group 1** (Seed Nodes):
- Task 1.1: Provision servers (2-4 hours)
- Task 1.2: Install Dilithion (5-10 hours)
- Task 1.3: Configure systemd (2.5-5 hours)

### If You Have 1 Week:
Focus on **Critical Tasks**:
- Complete Task Group 1 (Seed Nodes)
- Start Task Group 2 (Testing) - runs in parallel
- Complete Task Group 3 (Security Fixes)

### If You Have 2 Weeks:
Complete all **CRITICAL** and **HIGH** priority tasks:
- Task Groups 1-4 (Seed nodes, Testing, Security, Tests)

### If You Have 4 Weeks:
Complete everything including **MEDIUM** priority:
- All task groups 1-7

---

## 📝 Notes

- **Parallel Work:** Testing (Group 2) can run in parallel with other tasks
- **Dependencies:** Most tasks are independent - can work on multiple simultaneously
- **Time Estimates:** Conservative - actual time may be less
- **Testing:** Extended testing (7-14 days) must run continuously - start early

---

**Last Updated:** December 2025  
**Next Review:** After Task Group 1 completion

