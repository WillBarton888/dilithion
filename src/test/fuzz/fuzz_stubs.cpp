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

// --- NodeContext stubs ---

NodeContext g_node_context;

// Custom destructor that releases (leaks) unique_ptrs instead of deleting.
// This avoids cascading destructor dependencies for CPeerManager, CConnman,
// CHeadersManager, DNARegistryDB, etc. — each of which would pull in dozens
// of additional objects. In fuzz context all members are null anyway.
NodeContext::~NodeContext() {
    peer_manager.release();
    connman.release();
    headers_manager.release();
    orphan_manager.release();
    block_fetcher.release();
    block_tracker.release();
    validation_queue.release();
    dna_registry.release();
    trust_manager.release();
    verification_manager.release();
}

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
