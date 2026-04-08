// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Fuzz stubs: minimal symbol definitions for consensus fuzz targets.
//
// Consensus objects (pow.o, validation.o, tx_validation.o) reference symbols
// from heavy modules (NodeContext, Digital DNA, VDF) that would cascade into
// 20+ additional object files if linked for real. Instead, we provide minimal
// stubs here. The fuzz targets exercise serialization and consensus math —
// they don't need real NodeContext init, DNA verification, or VDF proofs.
//
// Stubs provided:
//   g_node_context    — empty NodeContext global (all members default to null)
//   NodeContext methods — no-op implementations for destructor/Reset/Init/etc.
//   DNARegistryDB::get_verification_status — returns UNVERIFIED
//   CheckVDFProof     — returns true (skips VDF validation in fuzz context)

// NodeContext needs complete types for unique_ptr member destructors.
// Include all headers that define types held by unique_ptr in NodeContext.
#include <core/node_context.h>
#include <net/peers.h>
#include <net/connman.h>
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>
#include <net/blockencodings.h>
#include <node/block_validation_queue.h>
#include <digital_dna/dna_registry_db.h>
#include <digital_dna/verification_manager.h>
#include <digital_dna/dna_verification.h>
#include <consensus/vdf_validation.h>

// --- Destructor stubs for types held by unique_ptr in NodeContext ---
// These classes have non-trivial destructors defined in heavy .cpp files.
// We stub them here to avoid cascading into the full networking stack.

CBlockValidationQueue::~CBlockValidationQueue() {}
CHeadersManager::~CHeadersManager() {}
CConnman::~CConnman() {}
CPeerDiscovery::~CPeerDiscovery() {}
CBanManager::~CBanManager() {}
digital_dna::DNARegistryDB::~DNARegistryDB() {}

// --- NodeContext stubs ---

NodeContext g_node_context;

NodeContext::~NodeContext() = default;

void NodeContext::Reset() {
    // No-op in fuzz context — all unique_ptrs are null
}

bool NodeContext::Init(const std::string&, CChainState*) {
    return false;
}

void NodeContext::Shutdown() {}

std::shared_ptr<digital_dna::DigitalDNACollector> NodeContext::GetDNACollector() const {
    return nullptr;
}

void NodeContext::SetDNACollector(std::shared_ptr<digital_dna::DigitalDNACollector>) {}

// --- Digital DNA stubs ---

digital_dna::verification::VerificationStatus
digital_dna::DNARegistryDB::get_verification_status(
    const std::array<uint8_t, 20>&) const {
    return digital_dna::verification::VerificationStatus::UNVERIFIED;
}

// --- VDF validation stub ---

bool CheckVDFProof(
    const CBlock&,
    int,
    const uint256&,
    uint64_t,
    std::string&) {
    return true;
}
