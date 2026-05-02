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
#include <digital_dna/verification_manager.h>  // Phase 2: DNA Verification & Attestation
#include <consensus/ichain_selector.h>             // Phase 5: frozen interface
#include <consensus/port/chain_selector_impl.h>    // Phase 5: ChainSelectorAdapter
#include <net/port/sync_coordinator.h>             // Phase 6 PR6.5a: ISyncCoordinator complete type for unique_ptr destructor
#include <net/port/addrman_v2.h>                   // Phase 6 PR6.5b.0: port-namespace IAddressManager impl
#include <net/port/legacy_addrman_adapter.h>       // Phase 6 PR6.5b.0: legacy IAddressManager fallback
#include <net/port/peer_scorer.h>                  // Phase 6 PR6.5b.0: port-namespace IPeerScorer impl
#include <net/port/connman_adapter.h>              // Phase 6 PR6.5b.0: IConnectionManager adapter (complete type for unique_ptr)
#include <util/logging.h>

#include <cstdlib>  // std::getenv
#include <cstring>  // std::strcmp

// Global node context instance
NodeContext g_node_context;

// Destructor defined here (not in header) because unique_ptr<DNARegistryDB>
// requires the complete type for default_delete.
NodeContext::~NodeContext() = default;

// DNA collector stored in a separate global to avoid memory stomp from NodeContext fields.
// Something in the NodeContext layout overwrites byte 4 of the shared_ptr's internal pointer
// when stored as a member. Isolating it here eliminates that corruption.
static std::shared_ptr<digital_dna::DigitalDNACollector> g_dna_collector;
static std::mutex g_cs_dna_collector;

std::shared_ptr<digital_dna::DigitalDNACollector> NodeContext::GetDNACollector() const {
    std::lock_guard<std::mutex> lock(g_cs_dna_collector);
    return g_dna_collector;
}

void NodeContext::SetDNACollector(std::shared_ptr<digital_dna::DigitalDNACollector> new_collector) {
    std::lock_guard<std::mutex> lock(g_cs_dna_collector);
    g_dna_collector = std::move(new_collector);
}

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

    // Phase 5: instantiate chain selector adapter over the chainstate.
    // The adapter is a thin wrapper; lifetime is tied to NodeContext
    // and MUST be reset before chainstate is freed (handled in Shutdown/Reset).
    //
    // v4.1 IBD silent-drop fix: gate construction on env-var
    // DILITHION_USE_NEW_CHAIN_SELECTOR. Default = OFF.
    //
    // Why: ChainSelectorAdapter::ProcessNewHeader pre-populates
    // mapBlockIndex with BLOCK_VALID_HEADER entries during headers
    // sync. Legacy ActivateBestChain (the production path since PR5.4
    // reverted the chain-selector default) is the consumer of block
    // data, but it relies on AddBlockIndex to attach BLOCK_HAVE_DATA.
    // AddBlockIndex's silent return-false-on-duplicate semantics
    // (chain.cpp:96-98) drop the new flag, leaving every entry stuck
    // at BLOCK_VALID_HEADER. block_processing.cpp:891 then never sees
    // HaveData() == true, blocks are never activated, chain stays at
    // genesis. Reproduced on SYD mainnet 2026-05-02 with fresh datadir.
    //
    // Suppressing the adapter is a true revert to pre-Phase-6-PR6.1
    // behavior — legacy ActivateBestChain receives pindex by parameter
    // from the block-data path and never looks up by hash for
    // activation input, so removing the prepop side effect is safe.
    // The 6 ProcessNewHeader call sites in headers_manager.cpp and
    // the 2 use_port_pm gates in dilithion-node.cpp / dilv-node.cpp
    // already null-check chain_selector — they double as the suppression
    // gate. Zero changes needed at the call sites.
    //
    // Re-enable after v4.2 lands the proper AddBlockIndex flag-merge
    // semantics + caller audit. Setting env-var=1 in production is
    // known-broken; the WARN log at construction time signals operators.
    try {
        const char* selector_env = std::getenv("DILITHION_USE_NEW_CHAIN_SELECTOR");
        const bool use_new_selector = (selector_env != nullptr) && (std::strcmp(selector_env, "1") == 0);
        if (use_new_selector) {
            chain_selector = std::make_unique<::dilithion::consensus::port::ChainSelectorAdapter>(*chainstate);
            LogPrintf(ALL, INFO, "Phase 5: chain selector adapter wired (env-var=1, opt-in)");
            LogPrintf(ALL, WARN,
                "DILITHION_USE_NEW_CHAIN_SELECTOR=1 enables an opt-in path with a "
                "known IBD silent-drop bug (header pre-pop loses BLOCK_HAVE_DATA on "
                "block-data arrival). Do not use in production until v4.2.");
        } else {
            chain_selector = nullptr;
            LogPrintf(ALL, INFO,
                "Phase 5: chain selector adapter SUPPRESSED (default; env-var=1 "
                "known to have IBD silent-drop until v4.2)");
        }
    } catch (const std::exception& e) {
        LogPrintf(ALL, ERROR, "Failed to instantiate chain selector adapter: %s", e.what());
        return false;
    }

    // Initialize peer manager
    try {
        peer_manager = std::make_unique<CPeerManager>(datadir);
        LogPrintf(NET, INFO, "Initialized peer manager");
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "Failed to initialize peer manager: %s", e.what());
        return false;
    }

    // Phase 6 PR6.5b.0: port-namespace wiring prep instances.
    //
    // These coexist with legacy ::CPeerManager's private addrman / m_scorer
    // (constructed inside CPeerManager's ctor; peers.cpp:80,82,108). Legacy
    // peer-discovery still uses the private instances. The NodeContext-level
    // instances added here exist SOLELY so port-CPeerManager (PR6.5b.1a, under
    // --usenewpeerman=1) has refs to construct against. Inert under flag=0.
    //
    // Same env-var selection as peers.cpp:76-110 for operator consistency:
    //   DILITHION_USE_ADDRMAN_V2=0  -> LegacyAddrManAdapter (rollback escape)
    //   default                     -> CAddrMan_v2 (production)
    //   DILITHION_USE_NEW_PEER_SCORER=0  -> peer_scorer left null
    //   default                          -> CPeerScorer
    //
    // connman_adapter is NOT constructed here; it requires g_node_context.connman
    // which isn't set up until node startup (dilithion-node.cpp main() / dilv-
    // node.cpp main() construct CConnman locally then move into NodeContext).
    // Node startup wires connman_adapter immediately after that move.
    try {
        const char* addrman_env = std::getenv("DILITHION_USE_ADDRMAN_V2");
        const bool use_legacy_addrman = (addrman_env != nullptr) && (std::strcmp(addrman_env, "0") == 0);
        if (use_legacy_addrman) {
            addrman = std::make_unique<dilithion::net::port::LegacyAddrManAdapter>();
        } else {
            addrman = std::make_unique<dilithion::net::port::CAddrMan_v2>();
        }
        LogPrintf(NET, INFO, "PR6.5b.0: port-namespace addrman instance constructed (%s)",
                  use_legacy_addrman ? "LegacyAddrManAdapter" : "CAddrMan_v2");
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "PR6.5b.0: Failed to construct port-namespace addrman: %s", e.what());
        return false;
    }

    try {
        const char* scorer_env = std::getenv("DILITHION_USE_NEW_PEER_SCORER");
        const bool scorer_disabled = (scorer_env != nullptr) && (std::strcmp(scorer_env, "0") == 0);
        if (!scorer_disabled) {
            peer_scorer = std::make_unique<dilithion::net::port::CPeerScorer>();
            LogPrintf(NET, INFO, "PR6.5b.0: port-namespace peer_scorer instance constructed (CPeerScorer)");
        } else {
            LogPrintf(NET, INFO, "PR6.5b.0: port-namespace peer_scorer disabled via DILITHION_USE_NEW_PEER_SCORER=0");
        }
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "PR6.5b.0: Failed to construct port-namespace peer_scorer: %s", e.what());
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
            // Sybil defense Phase 2A: reject identities with DNA score >= 0.92
            dna_registry->SetEnforceDNADedup(true);
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

    // Initialize DNA verification manager (Phase 2: peer verification & attestation)
    if (dna_registry && trust_manager) {
        try {
            verification_manager = std::make_unique<digital_dna::verification::VerificationManager>(
                dna_registry.get(), trust_manager.get());
            LogPrintf(ALL, INFO, "DNA verification manager initialized");
        } catch (const std::exception& e) {
            LogPrintf(ALL, ERROR, "Failed to initialize verification manager: %s", e.what());
            verification_manager.reset();  // Non-fatal
        }
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


    // Phase 6 PR6.5b.1b: deregister port-CPeerManager from connman BEFORE the
    // sync_coordinator (which may own port-CPeerManager under flag=1) gets
    // destroyed. Avoids dangling raw ptr in connman if a peer event fires
    // during teardown. Connman's setter accepts nullptr to deregister.
    if (connman) {
        connman->RegisterPortPeerManager(nullptr);
    }

    // Phase 6 PR6.5b.0: reset CConnmanAdapter BEFORE connman because the
    // adapter holds a non-owning CConnman& reference. Resetting addrman /
    // peer_scorer here too — they don't depend on connman, but grouping with
    // other port-namespace instances keeps shutdown ordering legible.
    connman_adapter.reset();
    addrman.reset();
    peer_scorer.reset();

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

    // Phase 2: Reset verification manager before trust/registry
    verification_manager.reset();

    // Digital DNA: Reset trust manager (caller saves before Shutdown)
    trust_manager.reset();
    if (dna_registry) {
        dna_registry->Close();
        dna_registry.reset();
    }
    SetDNACollector(nullptr);

    // Phase 5: reset chain selector BEFORE clearing chainstate (adapter
    // holds a non-owning reference into chainstate).
    chain_selector.reset();

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
    // Phase 5: reset selector BEFORE clearing chainstate.
    chain_selector.reset();
    chainstate = nullptr;
    // Phase 6 PR6.5b.1b: deregister port-CPeerManager from connman before any
    // teardown (mirrors Shutdown). sync_coordinator (which may own port-pm)
    // gets destructed by NodeContext destructor / member destruction order.
    if (connman) {
        connman->RegisterPortPeerManager(nullptr);
    }
    // Phase 6 PR6.5b.0: reset adapter/instances BEFORE peer_manager/connman.
    connman_adapter.reset();
    addrman.reset();
    peer_scorer.reset();
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
    verification_manager.reset();  // Phase 2
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

