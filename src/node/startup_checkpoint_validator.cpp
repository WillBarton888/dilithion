// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.1 mandatory upgrade — startup checkpoint enforcement.
//
// Two phases, separately wired in dilv-node.cpp at different points
// in the startup sequence:
//
//   Phase 1 (ValidateChainAgainstCheckpoints): runs after chain index
//     load + BLOCK_VALID_CHAIN repair walk, before undo integrity probe.
//     Walks every embedded checkpoint vs the local chain ancestry.
//     Wired at lines ~2506 (genesis-only SetTip) and ~2685 (full load).
//
//   Phase 2 (ValidateLifetimeMinerSnapshot): runs after the optional
//     cooldown_tracker startup revalidation block (Clear() + replay)
//     so we assert the tracker state the rest of the process uses.
//     Wired at line ~4712.
//
// Both phases exit cleanly with distinct exit codes on failure (1 / 3),
// printing operator-actionable error messages pointing at the canonical
// recovery procedure: dilv-node --reset-chain --yes && dilv-node --rescan.

#include <node/startup_checkpoint_validator.h>

#include <consensus/chain.h>           // CBlockIndex + GetAncestor
#include <core/chainparams.h>          // g_chainParams + checkpoints + lifetimeMinerCountAt44232
#include <vdf/cooldown_tracker.h>      // CCooldownTracker::GetLifetimeMinerCount

#include <iostream>

namespace Dilithion {

bool ValidateChainAgainstCheckpoints(const CBlockIndex* pindexTip) {
    if (!g_chainParams) return true;
    if (!pindexTip) return true;  // empty chain — fresh IBD will use header-time enforcement

    for (const auto& cp : g_chainParams->checkpoints) {
        if (cp.nHeight > pindexTip->nHeight) continue;

        const CBlockIndex* ancestor = pindexTip->GetAncestor(cp.nHeight);
        if (!ancestor) {
            std::cerr << "\n=== STARTUP CHECKPOINT VALIDATION FAILED ===\n"
                      << "Cannot resolve ancestor at checkpoint height " << cp.nHeight
                      << " — local chain index appears truncated or corrupted.\n\n"
                      << "  Run: dilv-node --reset-chain --yes\n"
                      << "  Then: dilv-node --rescan\n\n"
                      << "This will wipe blocks/ and chainstate/ (wallet.dat preserved)\n"
                      << "and trigger a clean resync from peers.\n"
                      << "===============================================\n\n";
            return false;
        }
        if (ancestor->GetBlockHash() != cp.hashBlock) {
            std::cerr << "\n=== STARTUP CHECKPOINT VALIDATION FAILED ===\n"
                      << "Local chain has a block at height " << cp.nHeight
                      << " that does NOT match the embedded checkpoint.\n\n"
                      << "  Expected: " << cp.hashBlock.GetHex() << "\n"
                      << "  Local:    " << ancestor->GetBlockHash().GetHex() << "\n\n"
                      << "Your local chain is on a fork that v4.1 rejects.\n"
                      << "  Run: dilv-node --reset-chain --yes\n"
                      << "  Then: dilv-node --rescan\n\n"
                      << "This will wipe blocks/ and chainstate/ (wallet.dat preserved)\n"
                      << "and trigger a clean resync from the canonical chain.\n"
                      << "===============================================\n\n";
            return false;
        }
    }
    return true;
}

bool ValidateLifetimeMinerSnapshot(const CBlockIndex* pindexTip,
                                    const CCooldownTracker* tracker) {
    if (!g_chainParams) return true;
    if (!pindexTip || !tracker) return true;

    // Only assert once the active chain has reached at least 44232. Below
    // that, the populator hasn't seen the boundary yet and the count is
    // an in-progress partial value.
    if (pindexTip->nHeight < 44232) return true;

    // Pass-1 placeholder build: lifetimeMinerCountAt44232 = 0 disables
    // the assertion. Pass-2 release build embeds the actual canonical N.
    if (g_chainParams->lifetimeMinerCountAt44232 <= 0) return true;

    const int observed = tracker->GetLifetimeMinerCount();
    const int expected = g_chainParams->lifetimeMinerCountAt44232;
    if (observed != expected) {
        std::cerr << "\n=== STARTUP LIFETIME-MINER SNAPSHOT MISMATCH ===\n"
                  << "Local cooldown_tracker computed " << observed
                  << " distinct miners at height 44232,\n"
                  << "but the canonical embedded snapshot is " << expected << ".\n\n"
                  << "This indicates non-deterministic pre-44233 history ingestion\n"
                  << "(e.g., a sibling header from a wrong-fork peer was walked\n"
                  << "into the populator before chain selection settled).\n\n"
                  << "  Run: dilv-node --reset-chain --yes\n"
                  << "  Then: dilv-node --rescan\n\n"
                  << "Patch C's lifetime gate is consensus-relevant at 44233+ and\n"
                  << "divergence by even 1 means a chain split. Refusing to run\n"
                  << "until the local lifetime-miner state matches canonical.\n"
                  << "================================================\n\n";
        return false;
    }
    return true;
}

} // namespace Dilithion
