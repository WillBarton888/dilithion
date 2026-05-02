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

    // v4.1 cross-component audit HIGH-3 fail-fast: if tip is past the
    // activation point but the embedded snapshot is still the placeholder
    // (0), the build was never updated with the canonical count via the
    // pass-2 procedure. This means the CRIT-1 mitigation is dead code on
    // a release that's already running. Refuse to start with a clear
    // error so the operator notices BEFORE the chain forks.
    if (g_chainParams->lifetimeMinerCountAt44232 <= 0) {
        std::cerr << "\n=== STARTUP LIFETIME-MINER PLACEHOLDER NOT UPDATED ===\n"
                  << "params.lifetimeMinerCountAt44232 is still the placeholder (0)\n"
                  << "but the chain has reached or surpassed activation height 44232.\n\n"
                  << "This means the v4.1 release was tagged WITHOUT running the\n"
                  << "pass-2 build procedure (spec §3.6) that captures the canonical\n"
                  << "lifetime miner count and embeds it. The CRIT-1 mitigation is\n"
                  << "currently dead code on this binary.\n\n"
                  << "Refusing to start. Build a fresh release with the embedded\n"
                  << "count, then restart.\n"
                  << "=========================================================\n\n";
        return false;
    }

    // v4.1 cross-component audit HIGH-2 fix: use the height-bounded accessor
    // (count distinct miners AT OR BELOW h=44232) so the comparison stays
    // stable as the chain extends past 44232 with new miners joining.
    // GetLifetimeMinerCount() returns the cumulative-to-tip count, which
    // would mismatch the embedded snapshot the moment ANY new MIK wins
    // a block at 44234+, bricking restart on every v4.1 node.
    const int observed = tracker->GetLifetimeMinerCountAtHeight(44232);
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
