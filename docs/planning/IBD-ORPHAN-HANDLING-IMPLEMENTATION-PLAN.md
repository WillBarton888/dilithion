# Initial Block Download (IBD) and Orphan Block Handling Implementation Plan

**Project:** Dilithion Cryptocurrency Node  
**Bug ID:** #8 - Orphan Block Synchronization Failure  
**Date:** 2025-11-13  
**Estimated Duration:** 20-30 hours (4-6 work days)  
**Priority:** CRITICAL - Blocks testnet functionality

---

## Executive Summary

### Problem Statement

Dilithion nodes cannot synchronize when they start at different times. When a node receives a block whose parent it doesn't have, the node logs "ERROR: Cannot find parent block" and discards it, causing permanent chain divergence. This makes the testnet unusable for multi-node deployments.

**Root Cause:** Missing Initial Block Download (IBD) infrastructure with orphan block handling.

**Current Behavior:**
```cpp
// src/node/dilithion-node.cpp:941
if (pblockIndex->pprev == nullptr) {
    std::cerr << "[P2P] ERROR: Cannot find parent block..." << std::endl;
    return;  // BUG: Discards block without requesting parent!
}
```

### Solution Overview

Implement professional cryptocurrency node synchronization following Bitcoin Core's proven architecture:

1. **Orphan Block Pool** - Temporarily store blocks with missing parents
2. **Block Request Queue** - Systematically request missing parent blocks
3. **Headers-First Synchronization** - Download and validate headers before fetching block data
4. **Chain Selection** - Choose longest valid chain when processing orphaned blocks
5. **Recursive Orphan Processing** - Process orphan queue when parent blocks arrive

**Approach:** Bitcoin Core-inspired headers-first sync with orphan resolution (K.I.S.S principle - don't reinvent the wheel)

---

## Architecture Design

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     P2P Block Reception                      │
│                   (dilithion-node.cpp)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Block Synchronization Manager                   │
│                  (NEW: sync_manager.h/cpp)                   │
│                                                               │
│  ┌───────────────────┐  ┌──────────────────┐                │
│  │  Orphan Block Pool│  │ Block Request    │                │
│  │  (mapOrphanBlocks)│  │ Queue            │                │
│  └───────────────────┘  └──────────────────┘                │
│                                                               │
│  ┌───────────────────┐  ┌──────────────────┐                │
│  │  Headers-First    │  │ Peer Selector    │                │
│  │  Sync Logic       │  │ (best peer)      │                │
│  └───────────────────┘  └──────────────────┘                │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      Chain State                             │
│                  (consensus/chain.h)                         │
│                                                               │
│        ActivateBestChain() - Existing reorg logic            │
└─────────────────────────────────────────────────────────────┘
```

