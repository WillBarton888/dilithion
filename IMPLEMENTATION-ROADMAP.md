# Dilithion Implementation Roadmap

## Current Status
- **All known bugs resolved** (BUG #26-85)
- **Testnet running healthy** on 4 nodes (3 Linux servers + Windows local)
- **Mining working** at ~1900 H/s
- **Network syncing** properly

---

## Phase 1: Critical Stability (Priority: HIGH)

### 1.1 Thread Safety & Error Handling
**Goal**: Prevent silent crashes and improve diagnostics

| Task | Source | Files |
|------|--------|-------|
| Add RAII wrapper for mining threads | Original code | src/mining/randomx_miner.cpp |
| Wrap thread lambdas in try/catch | Bitcoin Core pattern | src/node/dilithion-node.cpp |
| Add AssertLockHeld() assertions | Bitcoin Core net_processing.cpp | src/p2p/*.cpp |

**Estimated effort**: 1 day

### 1.2 Global State Cleanup
**Goal**: Prevent future static initialization bugs (like BUG #85)

| Task | Source | Files |
|------|--------|-------|
| Create NodeContext struct | Bitcoin Core src/node/context.h | src/core/node_context.h |
| Move g_* pointers into NodeContext | Original | src/core/globals.cpp |
| Add explicit Init/Shutdown functions | Bitcoin Core | src/init.cpp (new) |

**Estimated effort**: 2 days

---

## Phase 2: Logging & Diagnostics (Priority: HIGH)

### 2.1 Port Bitcoin Core Logging
**Goal**: Replace std::cout/cerr with proper logging

| Task | Source | Files |
|------|--------|-------|
| Port logging.h/cpp | Bitcoin Core src/logging.* | src/util/logging.h, logging.cpp |
| Add log categories (NET, MEMPOOL, WALLET, etc) | Bitcoin Core | src/util/logging.h |
| Replace std::cout calls | Search/replace | All .cpp files |
| Add log rotation | Bitcoin Core | src/util/logging.cpp |

**Estimated effort**: 2 days

### 2.2 Crash Diagnostics
**Goal**: Better crash reports

| Task | Source | Files |
|------|--------|-------|
| Add top-level exception handler | Bitcoin Core | src/node/dilithion-node.cpp |
| Add stack trace logging (debug builds) | Original | src/util/stacktrace.cpp |

**Estimated effort**: 1 day

---

## Phase 3: P2P Security (Priority: CRITICAL)

### 3.1 Peer Misbehavior & DoS Protection
**Goal**: Prevent eclipse attacks and resource exhaustion

| Task | Source | Files |
|------|--------|-------|
| Port PeerManager with ban scores | Bitcoin Core src/net_processing.cpp | src/p2p/peer_manager.h/cpp |
| Add per-peer resource limits | Bitcoin Core | src/p2p/net.cpp |
| Implement eviction logic | Bitcoin Core | src/p2p/net.cpp |
| Port addrman (address manager) | Bitcoin Core src/addrman.* | src/p2p/addrman.h/cpp |
| Add feeler connections | Bitcoin Core | src/p2p/net.cpp |

**Estimated effort**: 5 days

### 3.2 Message Protocol Hardening
**Goal**: Strict protocol validation

| Task | Source | Files |
|------|--------|-------|
| Add message size limits | Bitcoin Core | src/p2p/protocol.h |
| Add checksum verification | Bitcoin Core | src/p2p/net.cpp |
| Protocol version negotiation | Bitcoin Core | src/p2p/net.cpp |
| Feature flags system | Bitcoin Core | src/p2p/protocol.h |

**Estimated effort**: 2 days

---

## Phase 4: Consensus & Validation (Priority: HIGH)

### 4.1 Modularize Validation
**Goal**: Separate validation into dedicated modules

| Task | Source | Files |
|------|--------|-------|
| Create validation.cpp | Bitcoin Core src/validation.cpp | src/consensus/validation.cpp |
| Create chainstate.cpp | Bitcoin Core src/chainstate.cpp | src/consensus/chainstate.cpp |
| Add invariant checks and asserts | Bitcoin Core | Throughout |

**Estimated effort**: 3 days

### 4.2 Database Hardening
**Goal**: Prevent corruption and enable recovery

| Task | Source | Files |
|------|--------|-------|
| Harden LevelDB error paths | Bitcoin Core | src/db/leveldb.cpp |
| Add fsync verification | Bitcoin Core | src/db/leveldb.cpp |
| Implement -reindex, -rescan | Bitcoin Core | src/init.cpp |
| Add corruption recovery tools | Bitcoin Core | src/db/recovery.cpp |

**Estimated effort**: 3 days

---

## Phase 5: IBD Coordinator (Priority: MEDIUM)

### 5.1 Encapsulate IBD Logic
**Goal**: Clean up dilithion-node.cpp main loop

| Task | Source | Files |
|------|--------|-------|
| Create CIBDCoordinator class | Original (based on Bitcoin Core) | src/node/ibd_coordinator.h/cpp |
| Move headers/block fetcher logic | From dilithion-node.cpp | src/node/ibd_coordinator.cpp |
| Add state machine for IBD phases | Original | src/node/ibd_coordinator.cpp |

**Estimated effort**: 3 days

---

## Phase 6: RPC & Wallet Separation (Priority: MEDIUM)

### 6.1 Wallet Separation
**Goal**: Allow node-only deployments

| Task | Source | Files |
|------|--------|-------|
| Add --disablewallet flag | Bitcoin Core | src/init.cpp |
| Abstract wallet into service | Bitcoin Core | src/wallet/wallet_service.h/cpp |
| Define wallet RPC surface | Bitcoin Core | src/wallet/rpc.cpp |

**Estimated effort**: 2 days

### 6.2 RPC Refactoring
**Goal**: Separate RPC parsing from business logic

| Task | Source | Files |
|------|--------|-------|
| Create RPCArg parser helpers | Bitcoin Core src/rpc/util.* | src/rpc/util.h/cpp |
| Simplify RPC handlers | Bitcoin Core pattern | src/rpc/server.cpp |
| Add RPC authentication (cookie/TLS) | Bitcoin Core | src/rpc/server.cpp |

**Estimated effort**: 2 days

---

## Phase 7: Mining Decoupling (Priority: MEDIUM)

### 7.1 External Miner Support
**Goal**: Treat built-in mining as auxiliary

| Task | Source | Files |
|------|--------|-------|
| Clean getblocktemplate RPC | Bitcoin Core | src/rpc/mining.cpp |
| Add submitblock improvements | Bitcoin Core | src/rpc/mining.cpp |
| Decouple mining threads from main node | Original | src/mining/randomx_miner.cpp |

**Estimated effort**: 2 days

---

## Phase 8: Testing Infrastructure (Priority: MEDIUM)

### 8.1 Unit Test Coverage
**Goal**: Cover consensus-critical code

| Task | Priority | Files |
|------|----------|-------|
| Headers validation tests | HIGH | src/test/headers_tests.cpp |
| Block fetcher scoring tests | MEDIUM | src/test/block_fetcher_tests.cpp |
| RandomX state machine tests | MEDIUM | src/test/randomx_tests.cpp |
| Protocol message fuzz tests | HIGH | src/test/fuzz/*.cpp |

**Estimated effort**: 3 days

### 8.2 Functional Test Framework
**Goal**: End-to-end regression testing

| Task | Source | Files |
|------|--------|-------|
| Port pytest-based framework | Bitcoin Core test/functional/ | test/functional/*.py |
| IBD simulation tests | Original | test/functional/ibd_test.py |
| Fork handling tests | Original | test/functional/fork_test.py |
| Mempool behavior tests | Bitcoin Core | test/functional/mempool_test.py |

**Estimated effort**: 3 days

### 8.3 CI/CD Pipeline
**Goal**: Automated quality gates

| Task | Files |
|------|-------|
| GitHub Actions workflow | .github/workflows/ci.yml |
| clang-format enforcement | src/.clang-format |
| clang-tidy in CI | .clang-tidy |
| ASan/UBSan builds | .github/workflows/sanitizers.yml |
| Continuous fuzzing (OSS-Fuzz) | fuzz/ |

**Estimated effort**: 2 days

---

## Phase 9: Security Hardening (Priority: HIGH)

### 9.1 Static Analysis & Fuzzing
**Goal**: Find vulnerabilities before attackers

| Task | Source | Files |
|------|--------|-------|
| Expand fuzz targets (protocol, script) | Bitcoin Core | src/test/fuzz/*.cpp |
| Integrate OSS-Fuzz | Google OSS-Fuzz | .clusterfuzzlite/ |
| Enable Coverity scans | Coverity | CI config |

**Estimated effort**: 2 days

### 9.2 Build Hardening
**Goal**: Secure release binaries

| Task | Source | Files |
|------|--------|-------|
| Enable stack canaries | GCC/Clang flags | Makefile |
| Enable FORTIFY_SOURCE | GCC flags | Makefile |
| Use hardened malloc | jemalloc/tcmalloc | Makefile |

**Estimated effort**: 1 day

### 9.3 Cryptography Audit
**Goal**: Validate PQ implementation

| Task | Notes |
|------|-------|
| Commission third-party audit | External |
| Document threat model for Dilithium | SECURITY.md |
| Add property-based tests for crypto | src/test/dilithium_tests.cpp |
| Review constant-time implementation | Code review |

**Estimated effort**: External engagement

---

## Phase 10: Configuration & Infrastructure (Priority: LOW)

### 10.1 Configuration System
**Goal**: Better UX for operators

| Task | Source | Files |
|------|--------|-------|
| Support dilithion.conf file | Bitcoin Core | src/util/config.cpp |
| Environment variable overrides | Original | src/util/config.cpp |
| Runtime reload for non-critical settings | Bitcoin Core | src/util/config.cpp |

**Estimated effort**: 1 day

### 10.2 Metrics & Monitoring
**Goal**: Operational visibility

| Task | Source | Files |
|------|--------|-------|
| JSON structured logging option | Original | src/util/logging.cpp |
| Prometheus metrics endpoint | Original | src/metrics/prometheus.cpp |

**Estimated effort**: 2 days

---

## Phase 11: Release Engineering (Priority: MEDIUM)

### 11.1 Reproducible Builds
**Goal**: Verifiable release integrity

| Task | Source | Files |
|------|--------|-------|
| Docker-based deterministic builds | Bitcoin Core contrib/guix/ | docker/build/ |
| PGP-signed release tags | Process | RELEASE.md |
| Binary signatures | Process | RELEASE.md |
| Release checklist | Bitcoin Core | RELEASE.md |

**Estimated effort**: 2 days

---

## Phase 12: Governance & Documentation (Priority: LOW)

### 12.1 DIPs (Dilithion Improvement Proposals)
**Goal**: Formal protocol change process

| Task | Source | Files |
|------|--------|-------|
| Create DIP template | Bitcoin BIPs | dips/DIP-0001.md |
| Document consensus rules | Original | dips/DIP-0002.md |

**Estimated effort**: 1 day

### 12.2 Documentation
**Goal**: Clear standards and guides

| Task | Status |
|------|--------|
| Archive old bug reports | DONE (archive/bugs/) |
| Archive session notes | DONE (archive/sessions/) |
| Create CONTRIBUTING.md style guide | Pending |
| Create HISTORY.md changelog | Pending |

---

## Priority Summary

| Priority | Phases | Total Effort |
|----------|--------|--------------|
| CRITICAL | 3 (P2P Security) | 7 days |
| HIGH | 1, 2, 4, 9 | 12 days |
| MEDIUM | 5, 6, 7, 8, 11 | 16 days |
| LOW | 10, 12 | 4 days |

**Total estimated effort**: ~39 days

---

## Immediate Next Steps

1. **Test wallet transactions** - Coins maturing now
2. **Start Phase 1.1** - Thread safety improvements
3. **Start Phase 3.1** - P2P security (most critical gap)

---

## Archive Structure

```
archive/
├── bugs/           # All BUG-*.md files (BUG #26-85)
├── sessions/       # SESSION-*.md, STATUS-*.md, MORNING-*.md
└── debug/          # Debug output files
```

---

## Version History

| Date | Version | Notes |
|------|---------|-------|
| 2025-12-01 | v1.0.18 | BUG #84, #85 fixes deployed |
| 2025-11-29 | v1.0.17 | Chain sync fixes |
| 2025-11-24 | v1.0.16 | P2P stability improvements |
