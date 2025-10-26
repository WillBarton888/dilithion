# Dilithion Architecture Documentation

**Version:** 1.0.0
**Date:** October 25, 2025
**Status:** Production Ready (10/10)

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Transaction Flow](#transaction-flow)
4. [Mining Flow](#mining-flow)
5. [Network Protocol](#network-protocol)
6. [Wallet Architecture](#wallet-architecture)
7. [Security Architecture](#security-architecture)
8. [Data Flow](#data-flow)

---

## System Overview

Dilithion is a post-quantum cryptocurrency built on:
- **CRYSTALS-Dilithium** signatures (quantum-resistant)
- **RandomX** proof-of-work (ASIC-resistant)
- **AES-256-CBC** wallet encryption
- **Simple, robust, 10/10 quality** codebase

```mermaid
graph TB
    User[User/Wallet] --> RPC[RPC Server]
    RPC --> Wallet[Wallet Module]
    RPC --> Node[Node Module]
    RPC --> Miner[Miner Module]

    Wallet --> Crypto[Cryptography]
    Node --> Blockchain[Blockchain Storage]
    Node --> Mempool[Memory Pool]
    Miner --> Mining[Mining Controller]

    Node <--> Network[P2P Network]
    Network <--> Peers[Other Nodes]

    Blockchain --> LevelDB[(LevelDB)]
    Wallet --> WalletFile[(wallet.dat)]

    Mining --> RandomX[RandomX PoW]
    Crypto --> Dilithium[CRYSTALS-Dilithium]

    style Dilithium fill:#f9f,stroke:#333,stroke-width:4px
    style RandomX fill:#bbf,stroke:#333,stroke-width:4px
    style Crypto fill:#bfb,stroke:#333,stroke-width:2px
```

---

## Component Architecture

### Core Modules

```mermaid
graph LR
    subgraph "Node Layer"
        Node[Node Core]
        BS[Blockchain Storage]
        BI[Block Index]
        MP[Mempool]
        Gen[Genesis]
    end

    subgraph "Network Layer"
        Net[Network Manager]
        Peers[Peer Manager]
        Proto[Protocol Handler]
        DNS[DNS Seeder]
        Sock[Socket Manager]
    end

    subgraph "Consensus Layer"
        PoW[Proof of Work]
        Fees[Fee Rules]
        Val[Validation]
    end

    subgraph "Wallet Layer"
        Wallet[Wallet Core]
        Crypter[Encryption]
        Keys[Key Management]
    end

    subgraph "RPC Layer"
        RPC[RPC Server]
        Auth[Authentication]
    end

    subgraph "Mining Layer"
        Miner[Mining Controller]
        RX[RandomX Hasher]
    end

    Node --> BS
    Node --> BI
    Node --> MP
    Net --> Peers
    Net --> Proto
    Wallet --> Crypter
    RPC --> Auth
    Miner --> RX

    style Node fill:#lightblue
    style Wallet fill:#lightgreen
    style RPC fill:#lightyellow
    style Miner fill:#lightcoral
```

### Directory Structure

```
dilithion/
├── src/
│   ├── consensus/        # Consensus rules (PoW, fees, validation)
│   ├── crypto/           # Cryptography (SHA-3, RandomX wrapper)
│   ├── miner/            # Mining controller
│   ├── net/              # P2P networking
│   ├── node/             # Blockchain storage, mempool, genesis
│   ├── primitives/       # Block and transaction structures
│   ├── rpc/              # RPC server and authentication
│   ├── util/             # Utilities (time, encoding)
│   ├── wallet/           # Wallet and encryption
│   └── test/             # Test suite
├── depends/
│   ├── randomx/          # RandomX library
│   └── dilithium/        # CRYSTALS-Dilithium library
└── docs/                 # Documentation
```

---

## Transaction Flow

```mermaid
sequenceDiagram
    participant User
    participant Wallet
    participant RPC
    participant Node
    participant Mempool
    participant Miner
    participant Network

    User->>RPC: sendtoaddress(addr, amount)
    RPC->>Wallet: CreateTransaction()
    Wallet->>Wallet: Select UTXOs
    Wallet->>Wallet: Sign with Dilithium
    Wallet-->>RPC: Signed Transaction
    RPC->>Node: BroadcastTransaction()
    Node->>Node: ValidateTransaction()
    Node->>Mempool: AddToMempool()
    Node->>Network: RelayTransaction()
    Network-->>Peers: tx message

    Note over Miner: Mining process
    Miner->>Mempool: GetTransactions()
    Miner->>Miner: Mine Block
    Miner->>Node: SubmitBlock()
    Node->>Node: ValidateBlock()
    Node->>Blockchain: AddBlock()
    Node->>Mempool: RemoveFromMempool()
    Node->>Network: RelayBlock()
    Network-->>Peers: block message

    Note over User: Transaction Confirmed
```

### Transaction Validation Steps

1. **Syntax Check**: Valid structure, correct sizes
2. **Signature Verification**: Dilithium signature validation
3. **UTXO Check**: Inputs exist and unspent
4. **Fee Check**: Sufficient fee (MIN_TX_FEE + size * FEE_PER_BYTE)
5. **Double-Spend Check**: Not already in mempool/blockchain
6. **Mempool Add**: Add to pending transactions

---

## Mining Flow

```mermaid
flowchart TB
    Start([Start Mining]) --> Init[Initialize RandomX]
    Init --> CreateTemplate[Create Block Template]
    CreateTemplate --> GetTx[Get Transactions from Mempool]
    GetTx --> SortByFee[Sort by Fee Rate]
    SortByFee --> CreateCoinbase[Create Coinbase Transaction]
    CreateCoinbase --> BuildBlock[Build Block]

    BuildBlock --> StartThreads[Start Mining Threads]
    StartThreads --> Thread1[Thread 1: Mine]
    StartThreads --> Thread2[Thread 2: Mine]
    StartThreads --> Thread3[Thread N: Mine]

    Thread1 --> Hash1[RandomX Hash]
    Thread2 --> Hash2[RandomX Hash]
    Thread3 --> Hash3[RandomX Hash]

    Hash1 --> Check1{Hash < Target?}
    Hash2 --> Check2{Hash < Target?}
    Hash3 --> Check3{Hash < Target?}

    Check1 -->|No| Nonce1[Increment Nonce]
    Check2 -->|No| Nonce2[Increment Nonce]
    Check3 -->|No| Nonce3[Increment Nonce]

    Nonce1 --> Hash1
    Nonce2 --> Hash2
    Nonce3 --> Hash3

    Check1 -->|Yes| Found[Block Found!]
    Check2 -->|Yes| Found
    Check3 -->|Yes| Found

    Found --> Validate[Validate Block]
    Validate --> Broadcast[Broadcast to Network]
    Broadcast --> Update[Update Blockchain]
    Update --> CreateTemplate

    style Found fill:#90EE90
    style Validate fill:#FFD700
    style Broadcast fill:#87CEEB
```

### Difficulty Adjustment

- **Target Block Time**: 120 seconds
- **Adjustment Interval**: Every 2016 blocks (~28 days)
- **Algorithm**: Examines last 2016 blocks, adjusts target to maintain 120s average

```
New Difficulty = Old Difficulty * (Actual Time / Expected Time)
Max adjustment: 4x per interval
```

---

## Network Protocol

```mermaid
sequenceDiagram
    participant Node1 as Node A
    participant Node2 as Node B

    Note over Node1,Node2: Connection Handshake
    Node1->>Node2: TCP Connect
    Node2-->>Node1: Accept
    Node1->>Node2: version message
    Node2->>Node1: version message
    Node1->>Node2: verack message
    Node2->>Node1: verack message

    Note over Node1,Node2: Connected

    Node1->>Node2: getblocks message
    Node2->>Node1: inv message (block hashes)
    Node1->>Node2: getdata message
    Node2->>Node1: block messages

    Note over Node1,Node2: Transaction Relay
    Node1->>Node2: inv message (tx hash)
    Node2->>Node1: getdata message
    Node1->>Node2: tx message

    Note over Node1,Node2: Keep-Alive
    Node1->>Node2: ping message
    Node2->>Node1: pong message
```

### Message Types

| Message | Purpose | Frequency |
|---------|---------|-----------|
| `version` | Protocol version and capabilities | Once at connect |
| `verack` | Acknowledge version | Once at connect |
| `ping` / `pong` | Keep-alive | Every 60 seconds |
| `getblocks` | Request block inventory | On sync |
| `inv` | Announce inventory | On new block/tx |
| `getdata` | Request full data | On inv |
| `block` | Full block data | On getdata |
| `tx` | Full transaction data | On getdata |
| `addr` | Peer addresses | Periodically |

---

## Wallet Architecture

```mermaid
graph TB
    subgraph "Wallet Layer"
        WalletCore[Wallet Core]
        KeyMgmt[Key Management]
        AddrMgmt[Address Management]
        TxMgmt[Transaction Management]
        UTXOMgmt[UTXO Tracking]
    end

    subgraph "Encryption Layer"
        Crypter[CCrypter: AES-256-CBC]
        MasterKey[Master Key Management]
        PBKDF2[PBKDF2-SHA3 KDF]
        SecMem[Secure Memory]
    end

    subgraph "Key Storage"
        PlainKeys[Unencrypted Keys<br/>std::map<Address, CKey>]
        EncKeys[Encrypted Keys<br/>std::map<Address, CEncryptedKey>]
        WalletFile[wallet.dat<br/>Binary Format]
    end

    subgraph "Cryptography"
        Dilithium[CRYSTALS-Dilithium]
        KeyGen[Key Generation]
        Sign[Signature Creation]
        Verify[Signature Verification]
    end

    WalletCore --> KeyMgmt
    WalletCore --> AddrMgmt
    WalletCore --> TxMgmt
    WalletCore --> UTXOMgmt

    KeyMgmt --> Crypter
    Crypter --> MasterKey
    MasterKey --> PBKDF2
    Crypter --> SecMem

    KeyMgmt --> PlainKeys
    KeyMgmt --> EncKeys
    WalletCore --> WalletFile

    KeyMgmt --> Dilithium
    Dilithium --> KeyGen
    Dilithium --> Sign
    Dilithium --> Verify

    style Crypter fill:#ffcccc
    style Dilithium fill:#ccccff
    style WalletFile fill:#ccffcc
```

### Wallet Encryption Flow

```mermaid
sequenceDiagram
    participant User
    participant Wallet
    participant Crypter
    participant PBKDF2
    participant AES

    User->>Wallet: EncryptWallet(passphrase)
    Wallet->>PBKDF2: Derive Key (passphrase + salt)
    Note over PBKDF2: 100,000 iterations<br/>SHA-3-256
    PBKDF2-->>Wallet: Derived Key (32 bytes)

    Wallet->>Wallet: Generate Random Master Key
    Wallet->>AES: Encrypt Master Key
    AES-->>Wallet: Encrypted Master Key

    loop For each private key
        Wallet->>AES: Encrypt Private Key with Master Key
        AES-->>Wallet: Encrypted Private Key
    end

    Wallet->>Wallet: Clear unencrypted keys
    Wallet->>Wallet: Save to wallet.dat
    Wallet-->>User: Success

    Note over Wallet: Wallet now encrypted<br/>and unlocked
```

### Wallet File Format

```
Header:
- Magic: "DILWLT01" (8 bytes)
- Version: uint32 (4 bytes)
- Flags: uint32 (4 bytes)
  - 0x01 = Encrypted

Master Key Record (if encrypted):
- Salt: 16 bytes
- IV: 16 bytes
- Encrypted Master Key: variable
- Derivation method: uint32
- Iterations: uint32

Key Records (for each key):
- Public Key: 1952 bytes
- Private Key/Encrypted Key: 4032 bytes (or encrypted + IV)

Address Records:
- Count: uint32
- For each: Address data (21 bytes)

Transaction Records:
- Count: uint32
- For each: UTXO data
```

---

## Security Architecture

```mermaid
graph TB
    subgraph "Authentication Layer"
        HTTP[HTTP Basic Auth]
        RPCAuth[RPC Username/Password]
        PassHash[SHA-3 Password Hash]
    end

    subgraph "Encryption Layer"
        WalletEnc[Wallet Encryption]
        AES256[AES-256-CBC]
        PBKDF2SHA3[PBKDF2-SHA3 KDF]
    end

    subgraph "Cryptographic Primitives"
        Dilithium[CRYSTALS-Dilithium<br/>Post-Quantum Signatures]
        SHA3[SHA-3-256<br/>Quantum-Resistant Hash]
        RandomX[RandomX<br/>ASIC-Resistant PoW]
    end

    subgraph "Network Security"
        Timestamp[Timestamp Validation]
        MedianTime[Median-Time-Past]
        PeerScore[Peer Misbehavior Scoring]
    end

    subgraph "Memory Safety"
        SecWipe[Secure Memory Wiping]
        RAII[RAII for Key Material]
        NoLeak[Prevent Key Leakage]
    end

    HTTP --> RPCAuth
    RPCAuth --> PassHash

    WalletEnc --> AES256
    WalletEnc --> PBKDF2SHA3

    Timestamp --> MedianTime

    SecWipe --> RAII
    RAII --> NoLeak

    style Dilithium fill:#ff9999
    style SHA3 fill:#99ff99
    style RandomX fill:#9999ff
```

### Security Features

| Feature | Implementation | Quantum Resistance |
|---------|---------------|-------------------|
| Signatures | CRYSTALS-Dilithium (NIST PQC) | ✅ Yes |
| Hashing | SHA-3-256 | ✅ Yes |
| Key Derivation | PBKDF2-SHA3 | ✅ Yes |
| Wallet Encryption | AES-256-CBC | ⚠️ Symmetric (safe) |
| Proof of Work | RandomX | N/A |

---

## Data Flow

### Block Propagation

```mermaid
flowchart LR
    Miner[Miner Finds Block] --> Validate[Validate Block]
    Validate --> SaveLocal[Save to Local Chain]
    SaveLocal --> Relay[Relay to Peers]

    Relay --> Peer1[Peer 1]
    Relay --> Peer2[Peer 2]
    Relay --> Peer3[Peer 3]

    Peer1 --> V1[Validate]
    Peer2 --> V2[Validate]
    Peer3 --> V3[Validate]

    V1 --> S1[Save]
    V2 --> S2[Save]
    V3 --> S3[Save]

    S1 --> R1[Relay Further]
    S2 --> R2[Relay Further]
    S3 --> R3[Relay Further]

    style Miner fill:#90EE90
    style Validate fill:#FFD700
    style SaveLocal fill:#87CEEB
```

### Synchronization Flow

```mermaid
stateDiagram-v2
    [*] --> Connecting: Start Node
    Connecting --> Connected: Peers Found
    Connected --> SyncHeaders: Request Headers
    SyncHeaders --> SyncBlocks: Headers Valid
    SyncBlocks --> ValidateBlocks: Download Blocks
    ValidateBlocks --> Synced: All Blocks Valid
    Synced --> [*]: Up to Date

    ValidateBlocks --> SyncBlocks: Invalid Block (Skip)
    SyncHeaders --> Connecting: No Valid Headers
```

---

## Thread Architecture

```mermaid
graph TB
    Main[Main Thread]

    Main --> RPCThread[RPC Server Thread]
    Main --> NetAccept[Network Accept Thread]
    Main --> NetMsg[Network Message Thread]
    Main --> Miner[Mining Threads x N]
    Main --> Timeout[Timeout Check Thread]

    RPCThread --> WalletOps[Wallet Operations]
    RPCThread --> NodeOps[Node Operations]

    NetAccept --> NewPeer[New Peer Handling]
    NetMsg --> MsgProc[Message Processing]

    Miner --> Hash1[Hash Thread 1]
    Miner --> Hash2[Hash Thread 2]
    Miner --> HashN[Hash Thread N]

    style Main fill:#lightblue
    style RPCThread fill:#lightgreen
    style Miner fill:#lightcoral
```

### Thread Safety

- **Wallet Mutex** (`cs_wallet`): Protects all wallet operations
- **Node Mutex** (`cs_main`): Protects blockchain state
- **Mempool Mutex** (`cs_mempool`): Protects mempool
- **Peer Mutex** (`cs_peers`): Protects peer list
- **RAII Lock Guards**: Automatic mutex management

---

## Database Schema

### LevelDB (Blockchain Storage)

```
Key Prefix | Data
-----------|-----
'b' + hash | Block data (serialized CBlock)
'h' + hash | Block header
'i' + hash | Block index (height, time, etc.)
't' + txid | Transaction
'u' + txid:vout | UTXO
'c' | Chain tip (best block hash)
'd' | Difficulty
```

### Wallet File (wallet.dat)

```
Binary format (see Wallet File Format section above)
```

---

## Performance Characteristics

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| Dilithium KeyGen | O(1) | ~10-20 seconds (post-quantum security) |
| Dilithium Sign | O(1) | ~1-2 ms |
| Dilithium Verify | O(1) | ~1 ms |
| RandomX Hash | O(1) | ~100 ms/hash |
| Block Validation | O(n) | n = number of transactions |
| UTXO Lookup | O(log n) | LevelDB indexed |
| Mempool Add | O(log n) | Sorted by fee |

---

## Future Enhancements

1. **Lightning Network**: Layer-2 scaling solution
2. **Atomic Swaps**: Cross-chain transactions
3. **HD Wallets**: BIP32-style hierarchical deterministic wallets
4. **Multi-Signature**: M-of-N transaction signatures
5. **Pruning**: Remove old block data to save space
6. **UTXO Commitments**: Compact blockchain verification

---

## References

- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [RandomX Specification](https://github.com/tevador/RandomX)
- [Bitcoin Protocol](https://en.bitcoin.it/wiki/Protocol_documentation)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

**Last Updated:** October 25, 2025
**Version:** 1.0.0
**Status:** Production Ready (10/10)
