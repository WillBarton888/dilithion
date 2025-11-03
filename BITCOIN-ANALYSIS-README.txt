BITCOIN-FUNCTIONAL-TEST-ANALYSIS.md

This document analyzes Bitcoin Core's functional testing framework based on research
of the bitcoin/bitcoin repository on GitHub. 

RESEARCH COMPLETED - KEY FINDINGS:

1. FRAMEWORK STRUCTURE
   - Location: test/functional/test_framework/
   - Base class: BitcoinTestFramework with metaclass enforcement
   - Test count: 200+ tests across 70+ files
   - Languages: Python 3 with type hints

2. CORE COMPONENTS
   - BitcoinTestFramework: Base class for all tests
   - TestNode: Wraps bitcoind process with RPC/P2P interface
   - P2PInterface: Implements Bitcoin P2P protocol
   - Message classes: Protocol message serialization
   - Block tools: Test data generation (create_block, create_coinbase)
   - Utility helpers: Assertions and synchronization primitives

3. KEY TEST CATEGORIES
   - RPC Interface Tests: JSON-RPC protocol compliance
   - Feature Tests: Consensus rules (70+ files)
   - Mempool Tests: Transaction pool behavior (25+ files)
   - P2P Tests: Network protocol validation
   - Mining Tests: Block template generation
   - Interface Tests: CLI, REST, ZMQ, IPC

4. BEST PRACTICES IDENTIFIED
   - Naming: <category>_test.py convention
   - Structure: params → helpers → run_test()
   - PEP-8 with type hints and f-strings
   - Minimize node count and restart cycles
   - Use MiniWallet for deterministic transactions
   - Employ p2p_lock for thread-safe P2P testing
   - Use assert_* functions for validation
   - wait_until() for polling conditions

5. KEY PATTERNS RESEARCHED
   - Custom P2PInterface subclassing for message handling
   - Block construction with merkle root validation
   - Transaction fee validation and RBF rules
   - Service flag validation and peer disconnection
   - Mempool acceptance testing without submission

6. FRAMEWORK UTILITIES
   - assert_equal, assert_approx, assert_raises_rpc_error
   - wait_until, ensure_for
   - create_block, create_coinbase, add_witness_commitment
   - MiniWallet for deterministic tx generation
   - Parallel test execution support (4+ workers)

DOCUMENT GENERATION SUMMARY:
Full markdown document created with:
- Executive summary and key statistics
- Directory structure overview
- Detailed framework class documentation
- Best practices checklist (40+ items)
- 5 annotated test examples
- Complete test template starter code
- Test execution commands and options
- Key files reference table

All research gathered from WebFetch analysis of bitcoin/bitcoin repository.
