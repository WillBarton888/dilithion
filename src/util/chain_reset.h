// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_CHAIN_RESET_H
#define DILITHION_UTIL_CHAIN_RESET_H

/**
 * Chain state reset helper.
 *
 * Wipes chain-derived data (blocks, chainstate, headers, dna_registry, wal, mempool)
 * while preserving wallet and identity material (wallet.dat, peers.dat,
 * mik_registration.dat, banlist, configs, logs).
 *
 * Used by:
 *   - `--reset-chain` CLI flag (user-invoked)
 *   - Auto-rebuild marker handler (BUG #277, post-UTXO-corruption recovery)
 */

#include <atomic>
#include <string>
#include <vector>

// Forward decl — full include avoided so genesis_gen / check-wallet-balance
// (which link util/chain_reset.cpp but never include the chain header) keep
// minimal dependencies.
class CChainState;

namespace Dilithion {

struct ChainResetReport {
    std::vector<std::string> removed;    // Paths actually removed
    std::vector<std::string> preserved;  // Files explicitly kept (that existed)
    std::vector<std::string> errors;     // Paths we failed to remove
};

/**
 * Perform the reset. Does NOT prompt — callers handle confirmation.
 * Returns a report listing what was touched. No exceptions thrown.
 */
ChainResetReport ResetChainState(const std::string& datadir);

/**
 * Interactive confirmation prompt. Prints the plan, reads from stdin,
 * returns true iff the user typed "RESET" (uppercase). If `yesFlag` is
 * true, skips the prompt and returns true.
 */
bool ConfirmChainReset(const std::string& datadir, bool yesFlag);

/**
 * v4.0.19: Write the auto_rebuild marker file. Used by:
 *   - IBDCoordinator on persistent UTXO/UndoBlock failure (BUG #277, v4.0.19)
 *   - Startup integrity check on missing undo data (Fix B, v4.0.19)
 *   - forcerebuild RPC on operator demand (Fix C, v4.0.19)
 *
 * The marker is a single text file at <datadir>/auto_rebuild containing the
 * reason. Existence triggers the startup wipe path on next launch.
 *
 * @param datadir Data directory (creates marker as <datadir>/auto_rebuild)
 * @param reason Human-readable reason — written to the file as a single line
 * @return true on success, false if the write failed (logs to stderr on failure)
 */
bool WriteAutoRebuildMarker(const std::string& datadir, const std::string& reason);

/**
 * v4.3.2 (M1 fix): poll the chainstate's UTXO/chain rebuild flags and, on
 * first observed truth, write the auto_rebuild marker and trigger node
 * shutdown via g_node_state.running=false.
 *
 * MUST be called once per main-loop iteration in BOTH the legacy
 * (CIbdCoordinatorAdapter) and port (CPeerManager) sync-coordinator
 * configurations. The original recovery flow lived inside
 * CIbdCoordinator::Tick() at ibd_coordinator.cpp:126-167; under
 * `--usenewpeerman=1` that Tick() is bypassed entirely (the port
 * CPeerManager replaces it as the sync_coordinator), so flag-set sites
 * in chain.cpp (Fix 2) printed `[CRITICAL] Triggering auto_rebuild` but
 * no marker was ever written and the node continued running on broken
 * state. LDN canary 2026-05-04: chain regressed h=44518 → h=44265 in
 * 4 minutes before manual kill.
 *
 * Behaviour invariants (preserved verbatim from the legacy
 * CIbdCoordinator block):
 *   - Static-once latch — fires AT MOST once per process lifetime.
 *   - Reads NeedsUTXORebuild() AND NeedsChainRebuild() — combined-reason
 *     formatting when both fire.
 *   - Reason format: `"UTXO corruption AND persistent UndoBlock failure
 *     at height N hash=..."` / `"UTXO corruption detected at height N"`
 *     / `"Persistent UndoBlock failure at height N hash=..."`.
 *   - On WriteAutoRebuildMarker failure: still sets running=false (better
 *     to crash-loop with logged ERROR than continue on broken chain).
 *
 * Thread safety: relies on the underlying flags being std::atomic<bool>;
 * GetLastUndoFailureHash() takes its own internal mutex briefly. Static
 * latch is single-thread access (main loop only).
 *
 * @param chainstate The active CChainState whose flags to poll.
 * @param datadir Where to write `<datadir>/auto_rebuild`. Empty datadir
 *        causes WriteAutoRebuildMarker to log a warning and skip the
 *        write — shutdown is still requested.
 * @param running_flag Atomic bool the caller wants cleared on trigger
 *        (production: pointer to `g_node_state.running`). Pass nullptr
 *        to skip the shutdown signal — used in unit tests that only
 *        verify the marker-write path. Production callers MUST pass a
 *        non-null flag; otherwise the node will stay alive on broken
 *        chain state, defeating the purpose of the helper.
 * @return true if the trigger fired this call (first-time activation),
 *         false otherwise (no flags set, OR latch already consumed).
 *         Production callers ignore the return; tests use it to assert
 *         exactly-once behaviour across repeated invocations.
 */
bool MaybeTriggerChainRebuild(CChainState& chainstate,
                              const std::string& datadir,
                              std::atomic<bool>* running_flag);

/**
 * v4.3.2 (M1 fix) — TEST-ONLY: reset the static-once latch inside
 * MaybeTriggerChainRebuild so a single test process can drive the
 * helper through multiple independent scenarios. Production code MUST
 * NOT call this; the latch is intentionally process-lifetime to
 * prevent a thrashing recovery loop.
 */
void ResetMaybeTriggerLatchForTesting();

} // namespace Dilithion

#endif // DILITHION_UTIL_CHAIN_RESET_H
