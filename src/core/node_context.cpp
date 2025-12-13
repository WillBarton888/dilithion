// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <core/node_context.h>
#include <net/peers.h>
#include <net/connman.h>  // Phase 2: For CConnman destructor
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/block_fetcher.h>
#include <util/logging.h>
#include <iostream>

// Global node context instance
NodeContext g_node_context;

bool NodeContext::Init(const std::string& datadir, CChainState* chainstate_ptr) {
    if (IsInitialized()) {
        LogPrintf(ALL, WARN, "NodeContext already initialized");
        return false;
    }

    if (!chainstate_ptr) {
        LogPrintf(ALL, ERROR, "NodeContext::Init: chainstate_ptr is null");
        return false;
    }

    chainstate = chainstate_ptr;

    // Initialize peer manager
    try {
        peer_manager = std::make_unique<CPeerManager>(datadir);
        LogPrintf(NET, INFO, "Initialized peer manager");
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "Failed to initialize peer manager: %s", e.what());
        return false;
    }

    // Initialize IBD managers
    try {
        headers_manager = std::make_unique<CHeadersManager>();
        orphan_manager = std::make_unique<COrphanManager>();
        block_fetcher = std::make_unique<CBlockFetcher>();
        LogPrintf(IBD, INFO, "Initialized IBD managers (headers, orphan, block_fetcher)");

        // BUG #125: Start async header validation thread
        if (headers_manager && !headers_manager->StartValidationThread()) {
            LogPrintf(IBD, WARN, "Failed to start header validation thread");
            // Non-fatal - will fall back to sync validation
        }
    } catch (const std::exception& e) {
        LogPrintf(IBD, ERROR, "Failed to initialize IBD managers: %s", e.what());
        return false;
    }

    // Initialize state flags
    running = false;
    new_block_found = false;
    mining_enabled = false;

    LogPrintf(ALL, INFO, "NodeContext initialized successfully");
    return true;
}

void NodeContext::Shutdown() {
    LogPrintf(ALL, INFO, "Shutting down NodeContext...");

    // Stop services first
    running = false;

    // Shutdown components in reverse order of initialization
    if (async_broadcaster) {
        // Async broadcaster cleanup handled by its destructor
        async_broadcaster = nullptr;
    }

    if (connection_manager) {
        connection_manager = nullptr;
    }

    // Phase 2: Stop CConnman
    if (connman) {
        connman->Stop();
        connman.reset();
    }

    if (message_processor) {
        message_processor = nullptr;
    }

    // Phase 2: Stop validation queue before IBD managers
    if (validation_queue) {
        validation_queue->Stop();
        validation_queue.reset();
    }

    // Reset IBD managers (unique_ptr will handle cleanup)
    block_fetcher.reset();
    orphan_manager.reset();

    // BUG #125: Stop validation thread before destroying headers_manager
    if (headers_manager) {
        headers_manager->StopValidationThread();
    }
    headers_manager.reset();

    // Reset peer manager (unique_ptr will handle cleanup)
    peer_manager.reset();

    // Clear pointers
    chainstate = nullptr;
    rpc_server = nullptr;
    miner = nullptr;
    wallet = nullptr;
    p2p_socket = nullptr;
    http_server = nullptr;

    LogPrintf(ALL, INFO, "NodeContext shutdown complete");
}

void NodeContext::Reset() {
    chainstate = nullptr;
    peer_manager.reset();
    connection_manager = nullptr;
    connman.reset();  // Phase 2: Reset CConnman
    message_processor = nullptr;
    headers_manager.reset();
    orphan_manager.reset();
    block_fetcher.reset();
    validation_queue.reset();  // Phase 2: Reset validation queue
    async_broadcaster = nullptr;
    rpc_server = nullptr;
    miner = nullptr;
    wallet = nullptr;
    p2p_socket = nullptr;
    http_server = nullptr;
    running = false;
    new_block_found = false;
    mining_enabled = false;
}

