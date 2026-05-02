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

#include <cstdlib>                     // std::getenv (pass-1 capture bypass)
#include <cstring>                     // std::strcmp (pass-1 capture bypass)
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
    //
    // v4.1 v0.7 amendment (pass-1 capture bypass): the spec §3.6 pass-1
    // procedure REQUIRES the operator to start a placeholder-binary node,
    // let it reach 44232, then query the count via RPC. HIGH-3 as
    // originally written prevented exactly that workflow on a running
    // node. Solution: env-var DILITHION_PASS_1_CAPTURE=1 logs the
    // observed count at startup and continues, bypassing fail-fast.
    // Production binaries (no env-var) retain the original strict check.
    if (g_chainParams->lifetimeMinerCountAt44232 <= 0) {
        const char* pass1_env = std::getenv("DILITHION_PASS_1_CAPTURE");
        const bool pass1_capture = (pass1_env != nullptr) && (std::strcmp(pass1_env, "1") == 0);
        if (pass1_capture) {
            const int observed_pass1 = tracker->GetLifetimeMinerCountAtHeight(44232);
            std::cerr << "\n=== PASS-1 CAPTURE: lifetime miner count at h=44232 = "
                      << observed_pass1 << " ===\n"
                      << "Embed in chainparams.cpp (search lifetimeMinerCountAt44232)\n"
                      << "then rebuild WITHOUT this env-var for the production binary.\n"
                      << "===================================================\n\n";
            return true;  // bypass fail-fast for pass-1 capture phase
        }
        std::cerr << "\n=== STARTUP LIFETIME-MINER PLACEHOLDER NOT UPDATED ===\n"
                  << "params.lifetimeMinerCountAt44232 is still the placeholder (0)\n"
                  << "but the chain has reached or surpassed activation height 44232.\n\n"
                  << "This means the v4.1 release was tagged WITHOUT running the\n"
                  << "pass-2 build procedure (spec §3.6) that captures the canonical\n"
                  << "lifetime miner count and embeds it. The CRIT-1 mitigation is\n"
                  << "currently dead code on this binary.\n\n"
                  << "Refusing to start. Build a fresh release with the embedded\n"
                  << "count, then restart. (Or, if this IS the pass-1 capture build,\n"
                  << "set env-var DILITHION_PASS_1_CAPTURE=1 to bypass and log the\n"
                  << "observed count to stderr.)\n"
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
                  << "On a v4.1.2+ binary with a canonical chain (Phase 1\n"
                  << "checkpoint at 44233 having already passed), this should\n"
                  << "be unreachable under normal operation. Investigate the\n"
                  << "cause before taking any operational action.\n\n"
                  << "Common causes, ranked by likelihood:\n"
                  << "  (a) embedded canonical value in chainparams was\n"
                  << "      captured against a different chain than yours\n"
                  << "      (build / release issue — file an incident,\n"
                  << "      do NOT --reset-chain), OR\n"
                  << "  (b) chainstate corruption (e.g. blocks/ or chainstate/\n"
                  << "      files damaged) — try `dilv-node --reindex` first to\n"
                  << "      rebuild the indexes from the on-disk block files\n"
                  << "      WITHOUT discarding the chain. Only `--reset-chain`\n"
                  << "      if --reindex itself fails or rebuilds incomplete\n"
                  << "      block data, OR\n"
                  << "  (c) the lifetime-miner state has regressed in the\n"
                  << "      tracker code (the invariance test in\n"
                  << "      v4_1_checkpoint_enforcement_tests.cpp should have\n"
                  << "      caught it — file an incident, do NOT reset).\n\n"
                  << "WARNING about pre-v4.1.2 binaries: they had a sliding-\n"
                  << "window query bug that made this banner fire spuriously\n"
                  << "after the chain advanced past 44232 by activeWindow\n"
                  << "blocks. On those binaries, --reset-chain did NOT help\n"
                  << "(tip would re-advance and the same mismatch would\n"
                  << "return). If you suspect you are on a pre-v4.1.2 binary,\n"
                  << "upgrade first. See memory/v4_1_lifetime_validator_bug.md\n"
                  << "for full context.\n"
                  << "================================================\n\n";
        return false;
    }
    return true;
}

} // namespace Dilithion
