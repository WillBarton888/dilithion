# Bitcoin Core Functional Test Framework Analysis

## Research Report for Dilithion

Date: November 3, 2025

---

## EXECUTIVE SUMMARY

Bitcoin Core's functional test framework is a production-grade testing system with:

- 270+ tests organized by category
- Python 3 implementation
- Parallel execution support (default 4 workers)
- Metaclass-enforced test structure
- RPC testing via JSON-RPC 2.0
- P2P protocol testing with full network simulation
- Comprehensive utilities for assertions and test data

---

## 1. ARCHITECTURE OVERVIEW

### Key Files

**Core Framework:**
- test_framework.py: BitcoinTestFramework base class
- test_node.py: TestNode for bitcoind instance management
- p2p.py: P2P protocol simulation (40+ message types)
- authproxy.py: RPC communication (JSON-RPC 2.0)
- util.py: Assertion functions and utilities
- blocktools.py: Block and transaction creation
- wallet.py: MiniWallet for lightweight testing

**Orchestration:**
- test_runner.py: Main test orchestrator
- create_cache.py: Pre-generate shared test data
- combine_logs.py: Log aggregation

### Design Principles

1. **Metaclass Enforcement** - Validates test structure
2. **Isolation** - Each test: unique ports, isolated directories
3. **Parallelization** - ThreadPoolExecutor with configurable workers
4. **Determinism** - Controlled time, seeded randomness
5. **Automatic Cleanup** - Resource cleanup with optional debugging

---

## 2. KEY BASE CLASSES

### BitcoinTestFramework

Core test orchestrator:

- set_test_params(): Define num_nodes, configuration
- setup_chain(): Initialize blockchain
- setup_network(): Establish node connections
- run_test(): Main test logic (OVERRIDE THIS)
- main(): Orchestrates lifecycle

Key methods:
- add_nodes(), start_nodes(), stop_nodes()
- connect_nodes(), disconnect_nodes()
- sync_blocks(), sync_mempools()
- generate(), generateblock()
- wait_until(), assert_equal(), assert_raises_rpc_error()

### TestNode

Manages bitcoind instance:

- start(): Launch bitcoind process
- stop_node(): Gracefully terminate
- wait_for_rpc_connection(): Poll RPC endpoint
- add_p2p_connection(): Accept inbound P2P connection
- add_outbound_p2p_connection(): Establish outbound connection

### P2PInterface

Simulates network peer:

- send_message(): Send P2P message
- on_block(), on_tx(), on_inv(): Message callbacks
- wait_for_block(), wait_for_tx(): Wait predicates
- Support for 40+ message types
- V1 and V2 protocol support

---

## 3. TEST EXECUTION FLOW

### Lifecycle

1. Parse arguments
2. Validate resources
3. Load test scripts
4. Filter tests
5. Create cache (if parallel)
6. Execute tests in parallel
   - Each: setup -> run -> cleanup
7. Aggregate results
8. Report status

### Single Test Phases

**Phase 1: Setup**
- set_test_params()
- setup_chain()
- setup_network()
- setup_nodes()

**Phase 2: Execution**
- run_test()

**Phase 3: Cleanup**
- stop_nodes()
- Dump logs (on failure)
- Delete temp directory

---

## 4. RPC TESTING PATTERNS

### Pattern 1: Basic RPC Testing

```python
class MyRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        
    def run_test(self):
        info = self.nodes[0].getblockchaininfo()
        assert_equal(info['blocks'] > 0, True)
        
        assert_raises_rpc_error(
            -8, "error message",
            self.nodes[0].getblock,
            "invalid"
        )
```

### Pattern 2: Wallet Testing

- Generate blocks
- Send transactions
- Verify balance
- Test UTXO locking (lockunspent)
- Test fee calculation

### Pattern 3: MiniWallet

Lightweight wallet alternative (no wallet.dat):

```python
wallet = MiniWallet(self.nodes[0])
utxo = wallet.get_utxo()
tx = wallet.send_to(...)
```

---

## 5. P2P TESTING PATTERNS

### Pattern 1: Connection and Messages

Custom P2PInterface with callbacks:

```python
class TestP2PConn(P2PInterface):
    def on_block(self, msg):
        self.received_blocks.append(msg)

peer = TestP2PConn()
self.nodes[0].add_p2p_connection(peer)
```

### Pattern 2: Ban and Disconnect

Test peer management:
- setban(), listbanned(), clearbanned()
- disconnectnode()
- Persistence across restart

### Pattern 3: Protocol Messages

Test BIP152 compact blocks:
- sendcmpct negotiation
- Compact block reception
- Block reconstruction

---

## 6. ADAPTATION FOR DILITHION

### Required Changes

1. **DilithionTestFramework** (extend BitcoinTestFramework)
   - binary = "dilithiond"
   - block_time = 4 * 60
   - Custom generate()

2. **DilithionTestNode** (adapt TestNode)
   - Dilithium-specific config
   - Custom port ranges
   - Custom data directories

3. **blocktools.py** (modify)
   - Dilithium PoW
   - Coinbase reward schedule
   - Timestamp constraints

4. **util.py** (extend)
   - Dilithium assertions
   - Fee calculation
   - Helper functions

### Implementation Steps

1. Copy test_runner.py from Bitcoin Core
2. Copy test_framework/ directory
3. Create DilithionTestFramework class
4. Adapt TestNode for Dilithium
5. Modify blocktools.py
6. Create first RPC test
7. Create first P2P test
8. Integrate with test_runner
9. Document framework
10. Create examples

---

## 7. KEY ASSERTION FUNCTIONS

- assert_equal(a, b): Equality with diff output
- assert_not_equal(a, b): Inequality
- assert_greater_than(a, b): Comparison
- assert_raises_rpc_error(code, msg, fn, *args): RPC error
- assert_is_hex_string(value): Format check
- assert_is_hash_string(value): Hash format
- wait_until(predicate, timeout): Polling

---

## 8. FILES TO REUSE FROM BITCOIN CORE

**Completely Reusable:**
- authproxy.py (JSON-RPC 2.0)
- test_runner.py (orchestration)
- combine_logs.py (log aggregation)

**Requires Adaptation:**
- test_framework.py (create subclass)
- test_node.py (config)
- blocktools.py (consensus)
- util.py (extend)

---

## CONCLUSION

Bitcoin Core's functional test framework is production-grade and ideal for Dilithion. The key approach:

1. Inherit from BitcoinTestFramework
2. Extend with Dilithium-specific parameters
3. Adapt consensus/mining logic
4. Reuse proven testing patterns
5. Maintain alignment with Bitcoin Core best practices

This provides Dilithion with a professional test framework while maintaining independence for Dilithium-specific features.

---

**Document Version:** 1.0 | November 3, 2025
