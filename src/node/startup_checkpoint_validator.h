// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_STARTUP_CHECKPOINT_VALIDATOR_H
#define DILITHION_NODE_STARTUP_CHECKPOINT_VALIDATOR_H

class CBlockIndex;
class CCooldownTracker;

namespace Dilithion {

/**
 * Phase 1 of v4.1 startup validation: walk the in-memory chain from the
 * current tip back through every embedded checkpoint and verify the local
 * ancestry matches. Mismatch → log error pointing at --reset-chain --yes
 * + --rescan, return false (caller should exit with code 1).
 *
 * Wired in dilv-node.cpp at:
 *   - Site A: line ~2506 (genesis-only SetTip path) — for nodes with only
 *     genesis loaded (e.g., immediately after --reset-chain). Essentially
 *     a no-op for fresh genesis (no checkpoints at heights ≤ 0) but kept
 *     for consistency across both load paths.
 *   - Site B: line ~2685 (full-chain-load path, post-BLOCK_VALID_CHAIN walk,
 *     pre-undo integrity probe).
 *
 * Called BEFORE g_node_context.Init() and BEFORE any P2P startup so no
 * peer can observe a known-bad tip.
 *
 * @param pindexTip Current chain tip (use g_chainstate.GetTip()). May be
 *                  nullptr (empty chain — function returns true; fresh
 *                  IBD will use header-time enforcement instead).
 * @return true if chain is consistent with all embedded checkpoints
 *         (or no tip exists); false if a violation was detected.
 */
bool ValidateChainAgainstCheckpoints(const CBlockIndex* pindexTip);

/**
 * Phase 2 of v4.1 startup validation: assert that the cooldown tracker's
 * computed lifetime miner count at height 44232 matches the canonical
 * snapshot embedded in chainparams (params.lifetimeMinerCountAt44232).
 * Closes Layer-2 v0.1 CRIT-1 (non-deterministic Patch C lifetime gate
 * if pre-44233 history is ingested differently across nodes).
 *
 * Gated on params.lifetimeMinerCountAt44232 > 0 (placeholder = 0
 * disables the assertion for the pass-1 build that captures the count).
 *
 * Wired in dilv-node.cpp at line ~4712 (AFTER the optional startup
 * revalidation block ends, which would otherwise Clear() and replay
 * the tracker, wiping the populator's state).
 *
 * @param pindexTip Current chain tip.
 * @param tracker   The cooldown tracker after the populator + revalidation
 *                  block has finished. May be nullptr (returns true skip).
 * @return true if the embedded snapshot matches OR is the placeholder
 *         (snapshot disabled); false if a deterministic mismatch is
 *         detected at h ≥ 44232.
 */
bool ValidateLifetimeMinerSnapshot(const CBlockIndex* pindexTip,
                                    const CCooldownTracker* tracker);

} // namespace Dilithion

#endif // DILITHION_NODE_STARTUP_CHECKPOINT_VALIDATOR_H
