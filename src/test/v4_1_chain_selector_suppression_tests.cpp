// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.1 IBD silent-drop fix — chain selector suppression tests.
//
// Bug background:
//   ChainSelectorAdapter::ProcessNewHeader (chain_selector_impl.cpp:119-195)
//   pre-populates CChainState::mapBlockIndex with BLOCK_VALID_HEADER entries
//   during headers sync. Legacy ActivateBestChain (the production path since
//   PR5.4 reverted the chain-selector default) is the consumer of block data,
//   but AddBlockIndex (chain.cpp:96-98) silently returns false when the
//   header entry already exists. The block-data path's BLOCK_HAVE_DATA flag
//   is dropped; HaveData() never returns true; chain stays at genesis.
//   Reproduced on SYD mainnet 2026-05-02 with a fresh datadir: 559/600
//   incoming blocks (93%) rejected as "Block already in chainstate, skipping"
//   while chain count stayed at 0.
//
//   Fix: gate ChainSelectorAdapter construction in NodeContext::Init on
//   DILITHION_USE_NEW_CHAIN_SELECTOR env-var. Default = OFF (suppressed).
//
// Coverage:
//   T1 — default (env-var unset) → chain_selector == nullptr
//   T2 — env-var = "1"           → chain_selector != nullptr
//   T3 — env-var = "0"           → chain_selector == nullptr (only "1" enables)
//   T4 — env-var = ""            → chain_selector == nullptr
//
// The behavioral assertion (no IBD silent-drop when chain_selector is null)
// is verified end-to-end by the SYD mainnet canary (spec §5.3).

#include <consensus/chain.h>
#include <core/node_context.h>

#include <cassert>
#include <cstdlib>     // setenv / _putenv_s / unsetenv
#include <cstring>
#include <iostream>

namespace {

// RAII guard: save the current env-var, set it for the test, restore on dtor.
// Setting value=nullptr unsets the variable.
class EnvVarScope {
public:
    EnvVarScope(const char* name, const char* value) : m_name(name) {
        const char* prev = std::getenv(name);
        m_had_prev = (prev != nullptr);
        if (m_had_prev) m_prev_value = prev;
        Apply(value);
    }
    ~EnvVarScope() {
        if (m_had_prev) {
            Apply(m_prev_value.c_str());
        } else {
            Apply(nullptr);
        }
    }
private:
    void Apply(const char* value) {
#ifdef _WIN32
        // _putenv_s with empty value unsets on Windows.
        _putenv_s(m_name, value ? value : "");
#else
        if (value) setenv(m_name, value, 1);
        else       unsetenv(m_name);
#endif
    }
    const char* m_name;
    bool m_had_prev;
    std::string m_prev_value;
};

// Minimal NodeContext setup helper: reset, init, return result.
// Caller is responsible for the CChainState lifetime (must outlive this call).
//
// Note: NodeContext::Init may return false in this minimal test harness
// because downstream init steps (IBD managers, DNA registry, etc.) need
// global state (ChainParams, datadir) that we don't set up here. That's
// OK for THIS test — the chain_selector gating decision (lines 63-112 in
// node_context.cpp) runs FIRST, before any of those downstream steps,
// so chain_selector is correctly set/null by the time Init returns
// regardless of its return value.
bool ResetAndInit(CChainState& chainstate) {
    g_node_context.Reset();
    return g_node_context.Init("/tmp/v4_1_chain_selector_suppression_test", &chainstate);
}

}  // anonymous

int main() {
    std::cout << "[v4.1 chain_selector suppression tests] starting\n";

    // T1 — default (env-var unset) → suppressed.
    {
        EnvVarScope env("DILITHION_USE_NEW_CHAIN_SELECTOR", nullptr);
        CChainState chainstate;
        (void)ResetAndInit(chainstate);  // ok-or-not — chain_selector decided early
        assert(g_node_context.chain_selector == nullptr &&
               "T1: chain_selector must be SUPPRESSED when env-var is unset");
        std::cout << "  T1 PASS — env-var unset → chain_selector suppressed\n";
        g_node_context.Reset();
    }

    // T2 — env-var = "1" → enabled.
    {
        EnvVarScope env("DILITHION_USE_NEW_CHAIN_SELECTOR", "1");
        CChainState chainstate;
        (void)ResetAndInit(chainstate);  // ok-or-not — chain_selector decided early
        assert(g_node_context.chain_selector != nullptr &&
               "T2: chain_selector must be CONSTRUCTED when env-var=1");
        std::cout << "  T2 PASS — env-var=1 → chain_selector constructed\n";
        g_node_context.Reset();
    }

    // T3 — env-var = "0" → suppressed (only literal "1" enables).
    {
        EnvVarScope env("DILITHION_USE_NEW_CHAIN_SELECTOR", "0");
        CChainState chainstate;
        (void)ResetAndInit(chainstate);  // ok-or-not — chain_selector decided early
        assert(g_node_context.chain_selector == nullptr &&
               "T3: chain_selector must be SUPPRESSED when env-var=0");
        std::cout << "  T3 PASS — env-var=0 → chain_selector suppressed\n";
        g_node_context.Reset();
    }

    // T4 — env-var = "" → suppressed (empty string is not "1").
    //
    // Cross-platform note (Layer-2 red-team v0.6 NEW-2): on Windows,
    // _putenv_s(name, "") UNSETS the variable, so T4 on Windows is
    // effectively a duplicate of T1 (env-var unset). On Linux,
    // setenv(name, "", 1) sets to empty string, so T4 exercises the
    // production code's `selector_env != nullptr && strcmp(...) != 0`
    // empty-string branch. Both platforms suppress chain_selector and
    // the assertion passes; the divergent code path is only exercised
    // on Linux. Acceptable — the empty-string-suppression behavior is
    // verified on Linux CI, and Windows always falls through the unset
    // path which is identical in outcome.
    {
        EnvVarScope env("DILITHION_USE_NEW_CHAIN_SELECTOR", "");
        CChainState chainstate;
        (void)ResetAndInit(chainstate);  // ok-or-not — chain_selector decided early
        assert(g_node_context.chain_selector == nullptr &&
               "T4: chain_selector must be SUPPRESSED when env-var is empty");
        std::cout << "  T4 PASS — env-var=\"\" → chain_selector suppressed\n";
        g_node_context.Reset();
    }

    std::cout << "[v4.1 chain_selector suppression tests] all 4 PASS\n";
    return 0;
}
