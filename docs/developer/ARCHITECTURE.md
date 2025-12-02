# Dilithion Architecture Documentation

## System Overview

Dilithion is a post-quantum cryptocurrency node implementation that uses CRYSTALS-Dilithium3 for signatures and RandomX for proof-of-work. The architecture follows Bitcoin Core patterns for modularity, security, and maintainability.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Dilithion Node                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Consensus  │  │   Network    │  │    Wallet    │      │
│  │   Engine     │  │   Layer      │  │   Manager   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                 │                   │              │
│         └─────────────────┼───────────────────┘              │
│                           │                                 │
│                  ┌────────▼────────┐                        │
│                  │  NodeContext    │                        │
│                  │  (Global State)  │                        │
│                  └────────┬────────┘                        │
│                           │                                 │
│  ┌────────────────────────┼────────────────────────┐        │
│  │                        │                        │        │
│  ┌──────────┐    ┌────────▼────────┐    ┌──────────┐      │
│  │Database  │    │   Mempool       │    │  Mining  │      │
│  │(LevelDB) │    │   Manager       │    │ Controller│      │
│  └──────────┘    └─────────────────┘    └──────────┘      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. NodeContext

Centralized state management for all node components.

**Location:** `src/core/node_context.h`, `src/core/node_context.cpp`

**Components:**
- `block_fetcher`: Manages block download during IBD
- `headers_manager`: Manages block header synchronization
- `peer_manager`: Manages P2P peer connections
- `chainstate`: Blockchain state and UTXO set
- `mempool`: Transaction mempool
- `mining_controller`: Mining operations

**Lifecycle:**
1. `NodeContext::Init()`: Initializes all components
2. Runtime: Components interact via NodeContext
3. `NodeContext::Shutdown()`: Clean shutdown of all components

### 2. Consensus Engine

**Location:** `src/consensus/`

**Components:**
- Block validation
- Transaction validation
- UTXO set management
- Chain state management

**Key Features:**
- Post-quantum signature verification (Dilithium3)
- SHA-3/Keccak-256 hashing
- Block and transaction validation rules

### 3. Network Layer

**Location:** `src/net/`

**Components:**

#### 3.1. Connection Management (`CConnectionManager`)
- Outbound connection initiation
- Inbound connection acceptance
- Handshake management
- Message sending/receiving
- Connection quality tracking
- Network partition detection

#### 3.2. Peer Management (`CPeerManager`)
- Peer lifecycle management
- Peer state tracking
- Connection limits
- Peer discovery integration

#### 3.3. Message Processing (`CNetMessageProcessor`)
- Message deserialization
- Message validation
- Message routing to handlers
- Rate limiting
- DoS protection

#### 3.4. Address Management (`CAddrMan`)
- Peer address storage
- Address selection for connections
- Eclipse attack protection
- Address quality scoring

#### 3.5. Peer Discovery (`CPeerDiscovery`)
- DNS seed resolution
- Hardcoded seed nodes
- Address manager integration
- Connection quality metrics

#### 3.6. Connection Quality (`CConnectionQualityTracker`)
- Bytes sent/received tracking
- Message rate tracking
- Error tracking
- Quality score calculation
- Automatic peer disconnection

#### 3.7. Partition Detection (`CPartitionDetector`)
- Connection failure tracking
- Message inactivity detection
- Network isolation detection
- Partition severity calculation

### 4. Database Layer

**Location:** `src/db/`, `src/node/blockchain_storage.cpp`

**Components:**
- LevelDB integration
- Block storage
- UTXO set storage
- Error classification and recovery
- Database hardening

**Features:**
- Error classification (CORRUPTION, IO_ERROR)
- Fsync verification
- Recovery mechanisms (`--reindex`, `--rescan`)

### 5. Mining

**Location:** `src/miner/`

**Components:**
- RandomX integration
- Block template creation
- Transaction selection
- Merkle root calculation
- Mining thread management

**Features:**
- CPU-friendly PoW (RandomX)
- Configurable thread count
- Benchmarking integration

### 6. RPC Server

**Location:** `src/rpc/`

**Components:**
- JSON-RPC 2.0 server
- Method routing
- Parameter validation
- Error formatting
- Rate limiting

**Features:**
- Structured error responses
- Enhanced error messages with recovery steps
- Rate limiting
- Thread-safe request handling

### 7. Initial Block Download (IBD)

**Location:** `src/node/ibd_coordinator.cpp`

**Components:**
- State machine for IBD
- Header synchronization
- Block fetching coordination
- Peer management during IBD
- Exponential backoff

**States:**
1. `IDLE`: Not in IBD
2. `SYNCING_HEADERS`: Synchronizing block headers
3. `FETCHING_BLOCKS`: Downloading blocks
4. `COMPLETE`: IBD complete

## Data Flow

### Block Propagation

```
Peer → ReceiveMessages() → ProcessMessage() → ProcessBlockMessage()
  → ValidateBlock() → AddToChain() → UpdateUTXO() → AnnounceToPeers()
```

### Transaction Propagation

```
Peer → ReceiveMessages() → ProcessMessage() → ProcessTxMessage()
  → ValidateTransaction() → AddToMempool() → RelayToPeers()
```

### Mining Flow

```
MiningController → CreateBlockTemplate() → SelectTransactions()
  → CreateCoinbase() → BuildMerkleRoot() → RandomX Hash
  → Valid Block? → Broadcast Block
```

## Threading Model

### Main Thread
- Node initialization
- Main event loop
- Shutdown coordination

### P2P Threads
- Connection management
- Message sending/receiving
- Peer discovery

### RPC Threads
- Request handling
- Response generation
- Cleanup operations

### Mining Threads
- RandomX hashing
- Block template creation

## Security Features

### 1. DoS Protection
- Rate limiting for messages (INV, ADDR)
- Message size limits
- Misbehavior scoring
- Peer stalling detection

### 2. Network Security
- Address manager for eclipse protection
- Feeler connections for peer discovery
- Connection quality tracking
- Network partition detection

### 3. Data Integrity
- Checksum verification
- Database error classification
- Fsync verification
- Recovery mechanisms

### 4. Cryptography
- Post-quantum signatures (Dilithium3)
- SHA-3/Keccak-256 hashing
- Constant-time verification
- Property-based testing

## Configuration System

**Location:** `src/util/config.cpp`

**Priority Order:**
1. Command-line arguments
2. Environment variables
3. Configuration file (`dilithion.conf`)
4. Default values

**Configuration Options:**
- `testnet`: Enable testnet mode
- `mine`: Enable mining
- `threads`: Mining thread count
- `addnode`: Add peer addresses
- `rpcport`: RPC server port
- `port`: P2P network port
- `datadir`: Data directory
- `reindex`: Rebuild block index
- `rescan`: Rescan blockchain

## Logging System

**Location:** `src/util/logging.h`, `src/util/logging.cpp`

**Features:**
- Structured logging with categories
- Log levels (DEBUG, INFO, WARN, ERROR)
- File and console output
- Log rotation
- Thread-safe

**Categories:**
- `ALL`: All categories
- `NET`: Network operations
- `CONSENSUS`: Consensus operations
- `MINING`: Mining operations
- `RPC`: RPC operations

## Error Handling

**Location:** `src/util/error_format.h`, `src/util/error_format.cpp`

**Features:**
- Structured error messages
- User-friendly formatting
- Technical logging format
- Recovery guidance
- Error severity levels

## Testing Infrastructure

**Location:** `src/test/`

**Components:**
- Unit tests (Boost.Test)
- Fuzz tests (libFuzzer)
- Property-based tests
- Integration tests

**CI/CD:**
- GitHub Actions
- Sanitizers (ASan, UBSan, TSan)
- Static analysis (clang-tidy, cppcheck)
- Code coverage

## Build System

**Location:** `Makefile`

**Features:**
- Cross-platform support (Windows, Linux, macOS)
- Dependency management
- Sanitizer support
- Fuzzing support
- Benchmarking support

## Future Enhancements

1. **Modularization**: Further separation of concerns
2. **Performance**: Profile and optimize hot paths
3. **Security**: External security audit
4. **Documentation**: Expand API and architecture docs
5. **Testing**: Increase test coverage
6. **Release Process**: Formal release process with reproducible builds

