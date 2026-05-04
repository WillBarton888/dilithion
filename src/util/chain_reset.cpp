// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/chain_reset.h>

#include <consensus/chain.h>  // v4.3.2 M1: CChainState flag accessors
#include <uint256.h>          // v4.3.2 M1: GetLastUndoFailureHash() return type

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>

namespace Dilithion {

namespace {

// Chain-derived directories that get wiped on reset.
// dfmp_identity/ MUST be wiped alongside chain data: it tracks which MIKs
// have registered on-chain, and a non-empty identity DB with an empty chain
// would cause BuildMiningTemplate to emit a Reference coinbase (type 0x02)
// before the registration block exists on the rebuilt chain, breaking
// consensus. dna_trust/ is also chain-adjacent (trust scores derived from
// on-chain behavior) so it goes too.
const char* const kRemoveDirs[] = {
    "blocks",
    "chainstate",
    "headers",
    "dna_registry",
    "dfmp_identity",
    "dna_trust",
    "wal",
};

// Chain-derived individual files that get wiped on reset.
// dfmp_heat.dat and dfmp_payout_heat.dat are derived from block history;
// stale heat against a reset chain would penalize miners incorrectly.
const char* const kRemoveFiles[] = {
    "mempool.dat",
    "auto_rebuild",
    "fee_estimates.dat",
    "dfmp_heat.dat",
    "dfmp_payout_heat.dat",
};

// User-owned state that must survive a reset. Used for the "preserved" report
// and defensive logging — anything NOT in kRemoveDirs/kRemoveFiles is already
// safe (we only delete what's explicitly listed). Common user backup spots
// are called out here so the reset output reassures the user they weren't
// touched.
const char* const kPreserveFiles[] = {
    "wallet.dat",
    "wallet.dat.bak",
    "mik_registration.dat",
    "peers.dat",
    "banlist.json",
    "dilithion.conf",
    "dilv.conf",
    "backups",
    "backup",
};

} // namespace

ChainResetReport ResetChainState(const std::string& datadir) {
    ChainResetReport report;
    std::filesystem::path base(datadir);

    for (const char* name : kRemoveDirs) {
        std::filesystem::path p = base / name;
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            std::filesystem::remove_all(p, ec);
            if (ec) {
                report.errors.push_back(p.string() + " (" + ec.message() + ")");
            } else {
                report.removed.push_back(p.string());
            }
        }
    }

    for (const char* name : kRemoveFiles) {
        std::filesystem::path p = base / name;
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            std::filesystem::remove(p, ec);
            if (ec) {
                report.errors.push_back(p.string() + " (" + ec.message() + ")");
            } else {
                report.removed.push_back(p.string());
            }
        }
    }

    for (const char* name : kPreserveFiles) {
        std::filesystem::path p = base / name;
        std::error_code ec;
        if (std::filesystem::exists(p, ec)) {
            report.preserved.push_back(p.string());
        }
    }

    return report;
}

bool WriteAutoRebuildMarker(const std::string& datadir, const std::string& reason) {
    if (datadir.empty()) {
        std::cerr << "[Recovery] WriteAutoRebuildMarker: empty datadir, refusing to write marker"
                  << std::endl;
        return false;
    }
    std::filesystem::path markerPath = std::filesystem::path(datadir) / "auto_rebuild";
    std::ofstream marker(markerPath);
    if (!marker.is_open()) {
        std::cerr << "[Recovery] WriteAutoRebuildMarker: failed to open " << markerPath.string()
                  << " for write" << std::endl;
        return false;
    }
    // Single-line reason. The startup handler reads this and logs it; some operators
    // also tail the file directly. Keep newline-terminated for log readability.
    marker << reason << std::endl;
    marker.close();
    if (marker.fail()) {
        std::cerr << "[Recovery] WriteAutoRebuildMarker: write to " << markerPath.string()
                  << " failed (stream error)" << std::endl;
        return false;
    }
    std::cerr << "[Recovery] Wrote auto_rebuild marker to " << markerPath.string()
              << " (reason: " << reason << ")" << std::endl;
    return true;
}

// =============================================================================
// v4.3.2 M1 fix — process-lifetime once-latch for MaybeTriggerChainRebuild.
//
// The legacy implementation in CIbdCoordinator::Tick() used a function-static
// `bool recovery_triggered = false`. The free-function version preserves the
// semantics with a translation-unit-static atomic; ResetMaybeTriggerLatchForTesting
// resets it for unit tests that drive multiple scenarios in one process.
//
// Atomic chosen over plain bool so that, if a future refactor calls the helper
// from multiple threads, the compare_exchange_strong ensures exactly-once
// semantics under any interleaving.
// =============================================================================
namespace {
std::atomic<bool> g_chain_rebuild_latch_consumed{false};
}  // namespace

void ResetMaybeTriggerLatchForTesting() {
    g_chain_rebuild_latch_consumed.store(false, std::memory_order_release);
}

bool MaybeTriggerChainRebuild(CChainState& chainstate,
                              const std::string& datadir,
                              std::atomic<bool>* running_flag) {
    // 1) Cheap path: poll both flags. Atomic loads, no lock.
    const bool utxo_rebuild = chainstate.NeedsUTXORebuild();
    const bool chain_rebuild = chainstate.NeedsChainRebuild();
    if (!utxo_rebuild && !chain_rebuild) {
        return false;
    }

    // 2) Latch: ensure exactly-once activation per process. compare_exchange_strong
    // returns true ONLY for the thread that flipped false→true; everyone else
    // observes already-consumed and bails. Production main loop is
    // single-threaded so the atomicity is defensive, not load-bearing.
    bool expected = false;
    if (!g_chain_rebuild_latch_consumed.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        return false;
    }

    // 3) Determine the cause class. v4.3.3 F11 (Layer-3 round 2 MEDIUM-1):
    // chain_rebuild flag can fire from either UndoBlock-family failures
    // (BUG #277, v4.0.19, v4.3.1 BLOCKER #1 sites) or from F8's reorg-
    // depth rejection. Read the cause via the chainstate accessor; the
    // FlagChainRebuild helper guarantees release-store of the reason
    // BEFORE the flag, so this acquire-load sees a consistent pair.
    const CChainState::ChainRebuildReason chain_cause =
        chain_rebuild ? chainstate.GetChainRebuildReason()
                      : CChainState::ChainRebuildReason::UndoFailure;

    // 4) Print the CRITICAL banner. UTXO-rebuild text unchanged. Chain-
    // rebuild text branches on cause so operators get accurate diagnostics
    // (pre-F11 the M1 helper always said "Persistent UndoBlock failure"
    // for any chain-rebuild fire — operationally misleading, log scrapers
    // misdiagnose). F11 added DepthRejection; F16 (Layer-3 round 3 INFO-1)
    // added ConnectTipFailure / DisconnectTipFailure / ReadBlockFailure /
    // WriteBestBlockFailure cause classes for the previously-mislabeled
    // BLOCKER #1 sites. Each gets a banner that names the actual cause.
    std::cerr << "\n==========================================================" << std::endl;
    if (utxo_rebuild) {
        std::cerr << "CRITICAL: UTXO corruption detected! Auto-recovery initiated." << std::endl;
    } else {
        switch (chain_cause) {
            case CChainState::ChainRebuildReason::DepthRejection:
                std::cerr << "CRITICAL: Reorg depth exceeded MAX_REORG_DEPTH — "
                          << "bootstrap too stale for in-process catch-up. "
                          << "Auto-recovery initiated." << std::endl;
                break;
            case CChainState::ChainRebuildReason::ConnectTipFailure:
                std::cerr << "CRITICAL: ConnectTip failure mid-reorg — chain "
                          << "truncated. Auto-recovery initiated." << std::endl;
                break;
            case CChainState::ChainRebuildReason::DisconnectTipFailure:
                std::cerr << "CRITICAL: DisconnectTip failure mid-reorg — chain "
                          << "partially rewound. Auto-recovery initiated." << std::endl;
                break;
            case CChainState::ChainRebuildReason::ReadBlockFailure:
                std::cerr << "CRITICAL: ReadBlock failure after disconnects "
                          << "committed — chain truncated. Auto-recovery initiated." << std::endl;
                break;
            case CChainState::ChainRebuildReason::WriteBestBlockFailure:
                std::cerr << "CRITICAL: WriteBestBlock failure mid-reorg — "
                          << "DB/in-memory tip divergence. Auto-recovery initiated." << std::endl;
                break;
            case CChainState::ChainRebuildReason::UndoFailure:
            default:
                std::cerr << "CRITICAL: Persistent UndoBlock failure detected! Auto-recovery initiated." << std::endl;
                break;
        }
    }
    std::cerr << "The node will shut down and rebuild on next restart." << std::endl;
    std::cerr << "==========================================================" << std::endl;

    // 5) Build the marker reason string. UTXO branches preserved; chain-
    // rebuild branches on cause to give the operator a useful root-cause
    // string in <datadir>/auto_rebuild for runbook diagnosis.
    std::string reason;
    const std::string heightStr = std::to_string(chainstate.GetHeight());
    if (utxo_rebuild && chain_rebuild) {
        uint256 failing = chainstate.GetLastUndoFailureHash();
        reason = "UTXO corruption AND persistent UndoBlock failure at height "
                 + heightStr + " hash=" + failing.GetHex();
    } else if (utxo_rebuild) {
        reason = "UTXO corruption detected at height " + heightStr;
    } else {
        switch (chain_cause) {
            case CChainState::ChainRebuildReason::DepthRejection:
                reason = "Reorg depth exceeded MAX_REORG_DEPTH at height " + heightStr
                         + "; bootstrap too stale for in-process catch-up; wipe-and-IBD required";
                break;
            case CChainState::ChainRebuildReason::ConnectTipFailure:
                reason = "ConnectTip failure mid-reorg at height " + heightStr
                         + "; chain truncated; wipe-and-IBD required";
                break;
            case CChainState::ChainRebuildReason::DisconnectTipFailure:
                reason = "DisconnectTip failure mid-reorg at height " + heightStr
                         + "; chain partially rewound; wipe-and-IBD required";
                break;
            case CChainState::ChainRebuildReason::ReadBlockFailure:
                reason = "ReadBlock failure after disconnects committed at height " + heightStr
                         + "; chain truncated; wipe-and-IBD required";
                break;
            case CChainState::ChainRebuildReason::WriteBestBlockFailure:
                reason = "WriteBestBlock failure mid-reorg at height " + heightStr
                         + "; DB/in-memory tip divergence; wipe-and-IBD required";
                break;
            case CChainState::ChainRebuildReason::UndoFailure:
            default: {
                uint256 failing = chainstate.GetLastUndoFailureHash();
                reason = "Persistent UndoBlock failure at height "
                         + heightStr + " hash=" + failing.GetHex();
                break;
            }
        }
    }

    // 5) Write the marker. On failure WriteAutoRebuildMarker logs to stderr
    // itself; we still log a node-level ERROR so log scrapers picking up
    // [Recovery] lines also see [CRITICAL] context. Disk failure must NOT
    // suppress shutdown — running on broken chain state is strictly worse
    // than crash-looping with an obvious error.
    const bool wrote = WriteAutoRebuildMarker(datadir, reason);
    if (!wrote) {
        std::cerr << "[CRITICAL] MaybeTriggerChainRebuild: marker write failed "
                  << "(datadir='" << datadir << "'). Forcing shutdown anyway — "
                  << "operator must wipe datadir manually before restart."
                  << std::endl;
    }

    // 6) Signal node shutdown. Tests pass nullptr to skip this step.
    if (running_flag != nullptr) {
        running_flag->store(false, std::memory_order_release);
    }

    return true;
}

bool ConfirmChainReset(const std::string& datadir, bool yesFlag) {
    std::cout << "\n=== --reset-chain ===" << std::endl;
    std::cout << "Data directory: " << datadir << std::endl;
    std::cout << "\nWill REMOVE (chain-derived state, can be re-synced):" << std::endl;
    for (const char* n : kRemoveDirs) std::cout << "  - " << n << "/" << std::endl;
    for (const char* n : kRemoveFiles) std::cout << "  - " << n << std::endl;

    std::cout << "\nWill PRESERVE (if present):" << std::endl;
    for (const char* n : kPreserveFiles) std::cout << "  + " << n << std::endl;
    std::cout << "  + (any other file you put here — logs, backups, notes, etc.)" << std::endl;

    if (yesFlag) {
        std::cout << "\n--yes flag set, proceeding without prompt." << std::endl;
        return true;
    }

    std::cout << "\nType RESET (uppercase) to proceed, anything else to abort: " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        std::cout << "Aborted." << std::endl;
        return false;
    }
    if (answer != "RESET") {
        std::cout << "Aborted." << std::endl;
        return false;
    }
    return true;
}

} // namespace Dilithion
