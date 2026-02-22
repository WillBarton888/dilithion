// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <core/node_context.h>
#include <net/peers.h>
#include <net/connman.h>  // Phase 2: For CConnman destructor
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>  // IBD Redesign: Single source of truth
#include <net/blockencodings.h>  // BIP 152: For PartiallyDownloadedBlock destructor
#include <node/block_validation_queue.h>  // Phase 2: Async block validation
#include <digital_dna/dna_registry_db.h>  // Digital DNA: LevelDB-backed registry
#include <util/logging.h>
#include <iostream>

// Global node context instance
NodeContext g_node_context;

// Destructor defined here (not in header) because unique_ptr<DNARegistryDB>
// requires the complete type for default_delete.
NodeContext::~NodeContext() = default;

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
        block_fetcher = std::make_unique<CBlockFetcher>(peer_manager.get());
        block_tracker = std::make_unique<CBlockTracker>();  // IBD Redesign: Single source of truth
        LogPrintf(IBD, INFO, "Initialized IBD managers (headers, orphan, block_fetcher, block_tracker)");

        // BUG #125: Start async header validation thread
        if (headers_manager && !headers_manager->StartValidationThread()) {
            LogPrintf(IBD, WARN, "Failed to start header validation thread");
            // Non-fatal - will fall back to sync validation
        }
    } catch (const std::exception& e) {
        LogPrintf(IBD, ERROR, "Failed to initialize IBD managers: %s", e.what());
        return false;
    }

    // Initialize Digital DNA registry (LevelDB-backed)
    try {
        dna_registry = std::make_unique<digital_dna::DNARegistryDB>();
        std::string dna_path = datadir + "/dna_registry";
        if (dna_registry->Open(dna_path)) {
            LogPrintf(ALL, INFO, "DNA registry opened (%zu identities) at %s",
                      dna_registry->count(), dna_path.c_str());
        } else {
            LogPrintf(ALL, WARN, "Failed to open DNA registry at %s", dna_path.c_str());
            dna_registry.reset();  // Non-fatal, DNA is advisory
        }
    } catch (const std::exception& e) {
        LogPrintf(ALL, ERROR, "Failed to initialize Digital DNA registry: %s", e.what());
        dna_registry.reset();  // Non-fatal
    }

    // Initialize trust score manager
    try {
        trust_manager = std::make_unique<digital_dna::TrustScoreManager>();
        std::string trust_path = datadir + "/dna_trust";
        if (trust_manager->load(trust_path)) {
            LogPrintf(ALL, INFO, "Trust scores loaded (%zu identities) from %s",
                      trust_manager->count(), trust_path.c_str());
        } else {
            LogPrintf(ALL, INFO, "No existing trust scores at %s (fresh start)",
                      trust_path.c_str());
        }
    } catch (const std::exception& e) {
        LogPrintf(ALL, ERROR, "Failed to initialize trust score manager: %s", e.what());
        trust_manager.reset();  // Non-fatal
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
    block_tracker.reset();  // IBD Redesign
    block_fetcher.reset();
    orphan_manager.reset();

    // BUG #125: Stop validation thread before destroying headers_manager
    if (headers_manager) {
        headers_manager->StopValidationThread();
    }
    headers_manager.reset();

    // Reset peer manager (unique_ptr will handle cleanup)
    peer_manager.reset();

    // Digital DNA: Reset trust manager (caller saves before Shutdown)
    trust_manager.reset();
    if (dna_registry) {
        dna_registry->Close();
        dna_registry.reset();
    }
    SetDNACollector(nullptr);

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
    connman.reset();  // Phase 2: Reset CConnman
    message_processor = nullptr;
    headers_manager.reset();
    orphan_manager.reset();
    block_fetcher.reset();
    block_tracker.reset();  // IBD Redesign
    validation_queue.reset();  // Phase 2: Reset validation queue
    dna_registry.reset();  // Digital DNA
    trust_manager.reset();
    SetDNACollector(nullptr);
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

