// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CORE_NODE_CONTEXT_H
#define DILITHION_CORE_NODE_CONTEXT_H

#include <memory>
#include <atomic>
#include <string>

// Forward declarations
class CChainState;
class CPeerManager;
class CConnectionManager;
class CConnman;  // Phase 2: Event-driven connection manager
class CNetMessageProcessor;
class CHeadersManager;
class COrphanManager;
class CBlockFetcher;
class CAsyncBroadcaster;
class CBlockValidationQueue;  // Phase 2: Async block validation queue
// REMOVED: class CMessageProcessorQueue - unused (CConnman handles messages directly)
class CRPCServer;
class CMiningController;
class CWallet;
class CSocket;
class CHttpServer;

/**
 * NodeContext - Bitcoin Core-style global state management
 *
 * Consolidates all global pointers into a single struct to:
 * 1. Prevent static initialization order bugs (like BUG #85)
 * 2. Enable explicit initialization/shutdown
 * 3. Improve testability (can swap implementations)
 * 4. Make dependencies explicit
 *
 * Pattern from Bitcoin Core src/node/context.h
 */
struct NodeContext {
    // Core blockchain state
    CChainState* chainstate{nullptr};

    // P2P networking
    std::unique_ptr<CPeerManager> peer_manager;
    CConnectionManager* connection_manager{nullptr};  // Legacy - will be removed in Phase 5
    std::unique_ptr<CConnman> connman;  // Phase 2: Event-driven connection manager
    CNetMessageProcessor* message_processor{nullptr};

    // IBD (Initial Block Download) managers
    std::unique_ptr<CHeadersManager> headers_manager;
    std::unique_ptr<COrphanManager> orphan_manager;
    std::unique_ptr<CBlockFetcher> block_fetcher;
    std::unique_ptr<CBlockValidationQueue> validation_queue;  // Phase 2: Async block validation

    // Transaction relay
    CAsyncBroadcaster* async_broadcaster{nullptr};
    // REMOVED: CMessageProcessorQueue* message_queue - unused

    // Node services
    CRPCServer* rpc_server{nullptr};
    CMiningController* miner{nullptr};
    CWallet* wallet{nullptr};
    CSocket* p2p_socket{nullptr};
    CHttpServer* http_server{nullptr};

    // Node state flags
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};
    std::atomic<bool> mining_enabled{false};

    /**
     * Check if node is fully initialized
     */
    bool IsInitialized() const {
        return chainstate != nullptr &&
               peer_manager != nullptr &&
               headers_manager != nullptr &&
               orphan_manager != nullptr &&
               block_fetcher != nullptr;
    }

    /**
     * Initialize node context
     * 
     * Sets up all required components. Must be called before using the node.
     * 
     * @param datadir Data directory path for peer manager
     * @param chainstate_ptr Pointer to chain state (must outlive NodeContext)
     * @return true on success, false on failure
     */
    bool Init(const std::string& datadir, CChainState* chainstate_ptr);

    /**
     * Shutdown node context
     * 
     * Gracefully shuts down all components and releases resources.
     * Safe to call multiple times.
     */
    void Shutdown();

    /**
     * Reset all pointers (for shutdown or testing)
     * Note: Defined in node_context.cpp because unique_ptr::reset() requires complete types
     */
    void Reset();
};

/**
 * Global node context instance
 * 
 * Replaces scattered g_* global pointers with centralized state.
 * Initialized in main() and passed to components that need it.
 */
extern NodeContext g_node_context;

#endif // DILITHION_CORE_NODE_CONTEXT_H

