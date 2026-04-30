// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6 PR6.5b.7-close-prep — Static-grep lock-order tests for peer_manager.cpp.
//
// Purpose: pin the locked partial order
//   connman_peer_lock < m_peers_mutex < m_sync_state_mutex
//                     < m_blocks_in_flight_mutex < cs_main
// (declared in peer_manager.h §"Lock-order partial order").
//
// These are STATIC tests: they read peer_manager.cpp source via std::ifstream
// and assert structural invariants via regex + brace-depth tracking. They do
// NOT compile/run the production code — that's what the runtime tests do
// (peer_manager_misbehavior_tests, peer_manager_sync_state_tests, etc.).
//
// Why static? The locked partial order is inspectable as a documentation
// invariant only; a future "innocent" refactor could violate the order
// silently because no compiler/runtime check fires. These tests freeze
// the documentation surface so a reviewer of any future patch sees an
// obvious failure when the discipline drifts.
//
// Cases (3 mandatory + 1 optional):
//   1. lock_order_no_reverse_acquisition — there is no spot in the file
//      where m_blocks_in_flight_mutex is held and m_peers_mutex /
//      m_sync_state_mutex is then acquired in the SAME brace scope
//      (would invert the documented partial order).
//   2. no_callout_under_peer_manager_mutex — m_scorer.* / m_connman.* /
//      m_chain_selector.* / m_addrman.* method-call invocations never
//      appear nested inside an active `lock_guard<...>(m_*_mutex)` brace
//      scope (the copy-state-out discipline).
//   3. no_node_context_callout_under_peer_manager_mutex — same as #2 but
//      for `g_node_context.*` accesses and `hdr_mgr->` calls (which would
//      reach back into headers_manager / sync_coordinator under a held
//      PeerManager mutex, risking re-entry through chain_selector_impl's
//      delegation path).
//
// Optional case 4 (safe_annotation_present) — DROPPED PER CONTRACT 10-MIN
// CAP. Enforcement of "every PeerManager mutex acquisition has a
// SAFE: copy-state-out comment" is brittle to regex-scope-track because
// comment placement varies by author. Dropped after 10 min of regex
// drafts produced false positives on multi-line lock_guard declarations.
//
// Pattern: void test_*() + custom main(). No Boost.

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace {

// Strip C++ // line comments and /* ... */ block comments from source so
// regex matches are not poisoned by example text inside doc comments.
// (We DO want to scan strings — there are no quoted regex-bait literals
// in peer_manager.cpp that would matter.)
std::string StripComments(const std::string& src) {
    std::string out;
    out.reserve(src.size());
    size_t i = 0;
    while (i < src.size()) {
        // Block comment.
        if (i + 1 < src.size() && src[i] == '/' && src[i + 1] == '*') {
            i += 2;
            while (i + 1 < src.size() && !(src[i] == '*' && src[i + 1] == '/')) {
                // Preserve newlines so brace tracking still aligns with line counts.
                if (src[i] == '\n') out.push_back('\n');
                ++i;
            }
            if (i + 1 < src.size()) i += 2;  // skip past */
            continue;
        }
        // Line comment.
        if (i + 1 < src.size() && src[i] == '/' && src[i + 1] == '/') {
            while (i < src.size() && src[i] != '\n') ++i;
            continue;
        }
        out.push_back(src[i]);
        ++i;
    }
    return out;
}

// Read peer_manager.cpp from the standard test-run cwd (repo root).
std::string ReadPeerManagerSource() {
    std::ifstream f("src/net/port/peer_manager.cpp");
    if (!f) {
        std::cerr << "FATAL: could not open src/net/port/peer_manager.cpp"
                  << " (test must run from repo root)\n";
        std::exit(2);
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Track brace depth at every offset in the (comment-stripped) source.
// Returns a vector of brace depths indexed by character position.
std::vector<int> ComputeBraceDepth(const std::string& src) {
    std::vector<int> depth(src.size() + 1, 0);
    int d = 0;
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '{') ++d;
        depth[i] = d;
        if (src[i] == '}') --d;
    }
    depth[src.size()] = d;
    return depth;
}

// Find all match offsets for a regex within src; returns (begin_offset, end_offset)
// pairs ordered by appearance.
std::vector<std::pair<size_t, size_t>> FindAll(const std::string& src,
                                               const std::regex& rx) {
    std::vector<std::pair<size_t, size_t>> out;
    auto it = std::sregex_iterator(src.begin(), src.end(), rx);
    auto end = std::sregex_iterator();
    for (; it != end; ++it) {
        const auto& m = *it;
        out.emplace_back(static_cast<size_t>(m.position()),
                         static_cast<size_t>(m.position() + m.length()));
    }
    return out;
}

}  // anonymous namespace

// ============================================================================
// Test 1 — lock_order_no_reverse_acquisition.
//
// The locked partial order from peer_manager.h is:
//   connman_peer_lock < m_peers_mutex < m_sync_state_mutex
//                     < m_blocks_in_flight_mutex < cs_main
//
// Therefore: when m_blocks_in_flight_mutex is held, neither m_peers_mutex
// nor m_sync_state_mutex may be subsequently acquired in the SAME brace
// scope. (A new inner-scope acquisition AFTER the in-flight mutex is
// dropped is fine — that's a sequential acquire, not a nested one.)
//
// Strategy: for each `lock_guard<std::mutex> X(m_blocks_in_flight_mutex)`
// match, find the next closing brace at the same depth (the scope-end)
// and verify NO subsequent `lock_guard<...>(m_peers_mutex|m_sync_state_mutex)`
// appears before that scope-end at a strictly-deeper depth.
// ============================================================================
void test_lock_order_no_reverse_acquisition()
{
    std::cout << "  test_lock_order_no_reverse_acquisition..." << std::flush;

    const std::string raw  = ReadPeerManagerSource();
    const std::string src  = StripComments(raw);
    const std::vector<int> depth = ComputeBraceDepth(src);

    // Find every block-in-flight lock acquisition (lock_guard / scoped_lock /
    // unique_lock variants).
    std::regex bf_rx(
        R"((std::lock_guard|std::scoped_lock|std::unique_lock)\s*<[^>]*>\s+\w+\s*\(\s*m_blocks_in_flight_mutex\s*\))");
    auto bf_matches = FindAll(src, bf_rx);

    // Find every peers-mutex / sync-state-mutex acquisition (the "outer"
    // mutexes that should NEVER be acquired while blocks_in_flight is held).
    std::regex outer_rx(
        R"((std::lock_guard|std::scoped_lock|std::unique_lock)\s*<[^>]*>\s+\w+\s*\(\s*(m_peers_mutex|m_sync_state_mutex)\s*\))");
    auto outer_matches = FindAll(src, outer_rx);

    int reverse_violations = 0;
    for (const auto& [bf_begin, bf_end] : bf_matches) {
        // Find the scope end: the first position p > bf_end where
        // depth[p] < depth[bf_end].
        const int bf_depth = depth[bf_end];
        size_t scope_end = src.size();
        for (size_t p = bf_end; p < src.size(); ++p) {
            if (depth[p] < bf_depth) {
                scope_end = p;
                break;
            }
        }

        // Check whether any outer-mutex acquisition appears strictly
        // INSIDE the same scope (depth[outer_begin] >= bf_depth) and
        // BEFORE scope_end.
        for (const auto& [o_begin, o_end] : outer_matches) {
            if (o_begin > bf_end && o_begin < scope_end) {
                if (depth[o_begin] >= bf_depth) {
                    std::cerr << "\n  REVERSE LOCK ORDER at offset "
                              << o_begin << " (inside m_blocks_in_flight_mutex"
                              << " scope opened at " << bf_begin << ")\n";
                    ++reverse_violations;
                }
            }
        }
    }

    assert(reverse_violations == 0);

    // Sanity check: at least ONE m_blocks_in_flight_mutex acquisition
    // exists in the file (otherwise the regex broke and the test passes
    // vacuously).
    assert(!bf_matches.empty());

    std::cout << " OK (" << bf_matches.size() << " in-flight scopes scanned, 0 violations)\n";
}

// ============================================================================
// Test 2 — no_callout_under_peer_manager_mutex.
//
// Discipline (peer_manager.h "SAFE: copy-state-out"): no method invocation on
// m_scorer / m_connman / m_chain_selector / m_addrman is permitted while
// any peer-manager mutex (m_peers_mutex / m_sync_state_mutex /
// m_blocks_in_flight_mutex) is held.
//
// Strategy: for every `lock_guard<...>(m_*_mutex)` acquisition, scan the
// rest of its brace scope for ANY of the four callout patterns. If any
// is found at depth >= the lock-acquisition depth, that's a violation.
// ============================================================================
void test_no_callout_under_peer_manager_mutex()
{
    std::cout << "  test_no_callout_under_peer_manager_mutex..." << std::flush;

    const std::string raw  = ReadPeerManagerSource();
    const std::string src  = StripComments(raw);
    const std::vector<int> depth = ComputeBraceDepth(src);

    // PeerManager mutex acquisitions.
    std::regex pm_lock_rx(
        R"((std::lock_guard|std::scoped_lock|std::unique_lock)\s*<[^>]*>\s+\w+\s*\(\s*(m_peers_mutex|m_sync_state_mutex|m_blocks_in_flight_mutex)\s*\))");
    auto pm_lock_matches = FindAll(src, pm_lock_rx);

    // Callouts: m_scorer.X( / m_connman.X( / m_chain_selector.X( /
    // m_addrman.X( — method invocations only (followed by `(` after the
    // member name).
    std::regex callout_rx(
        R"((m_scorer|m_connman|m_chain_selector|m_addrman)\.\w+\s*\()");
    auto callout_matches = FindAll(src, callout_rx);

    int callout_violations = 0;
    for (const auto& [lk_begin, lk_end] : pm_lock_matches) {
        const int lk_depth = depth[lk_end];

        // Find scope_end: first p > lk_end with depth[p] < lk_depth.
        size_t scope_end = src.size();
        for (size_t p = lk_end; p < src.size(); ++p) {
            if (depth[p] < lk_depth) {
                scope_end = p;
                break;
            }
        }

        for (const auto& [c_begin, c_end] : callout_matches) {
            if (c_begin > lk_end && c_begin < scope_end) {
                if (depth[c_begin] >= lk_depth) {
                    // Surface line context for debugging.
                    size_t line_start = src.rfind('\n', c_begin);
                    line_start = (line_start == std::string::npos) ? 0 : line_start + 1;
                    size_t line_end = src.find('\n', c_begin);
                    if (line_end == std::string::npos) line_end = src.size();
                    std::cerr << "\n  CALLOUT-UNDER-LOCK at offset " << c_begin
                              << ": " << src.substr(line_start, line_end - line_start) << "\n";
                    ++callout_violations;
                }
            }
        }
    }

    assert(callout_violations == 0);
    assert(!pm_lock_matches.empty());
    assert(!callout_matches.empty());

    std::cout << " OK (" << pm_lock_matches.size() << " PM-lock scopes, "
              << callout_matches.size() << " callouts, 0 violations)\n";
}

// ============================================================================
// Test 3 — no_node_context_callout_under_peer_manager_mutex.
//
// Same shape as Test 2 but covers the `g_node_context.*` and `hdr_mgr->*`
// re-entry surfaces. Background: the chain-selector adapter (chain_
// selector_impl.cpp:255-261) delegates IsInitialBlockDownload back to
// g_node_context.sync_coordinator, which IS the port CPeerManager under
// flag=1. A callout to g_node_context.* under a PeerManager mutex risks
// recursive re-entry through that delegation path.
// ============================================================================
void test_no_node_context_callout_under_peer_manager_mutex()
{
    std::cout << "  test_no_node_context_callout_under_peer_manager_mutex..." << std::flush;

    const std::string raw  = ReadPeerManagerSource();
    const std::string src  = StripComments(raw);
    const std::vector<int> depth = ComputeBraceDepth(src);

    std::regex pm_lock_rx(
        R"((std::lock_guard|std::scoped_lock|std::unique_lock)\s*<[^>]*>\s+\w+\s*\(\s*(m_peers_mutex|m_sync_state_mutex|m_blocks_in_flight_mutex)\s*\))");
    auto pm_lock_matches = FindAll(src, pm_lock_rx);

    // Re-entry surfaces:
    //   - g_node_context.X.Y (any depth)
    //   - g_node_context.X->Y (any depth)
    //   - hdr_mgr->Y          (legacy headers manager)
    std::regex reentry_rx(
        R"((g_node_context\.\w+|hdr_mgr->)\w*)");
    auto reentry_matches = FindAll(src, reentry_rx);

    int reentry_violations = 0;
    for (const auto& [lk_begin, lk_end] : pm_lock_matches) {
        const int lk_depth = depth[lk_end];
        size_t scope_end = src.size();
        for (size_t p = lk_end; p < src.size(); ++p) {
            if (depth[p] < lk_depth) {
                scope_end = p;
                break;
            }
        }

        for (const auto& [r_begin, r_end] : reentry_matches) {
            if (r_begin > lk_end && r_begin < scope_end) {
                if (depth[r_begin] >= lk_depth) {
                    size_t line_start = src.rfind('\n', r_begin);
                    line_start = (line_start == std::string::npos) ? 0 : line_start + 1;
                    size_t line_end = src.find('\n', r_begin);
                    if (line_end == std::string::npos) line_end = src.size();
                    std::cerr << "\n  REENTRY-UNDER-LOCK at offset " << r_begin
                              << ": " << src.substr(line_start, line_end - line_start) << "\n";
                    ++reentry_violations;
                }
            }
        }
    }

    assert(reentry_violations == 0);
    // pm_lock_matches non-empty already asserted in Test 2; re-entry
    // surfaces may legitimately be empty if no g_node_context / hdr_mgr->
    // call exists in peer_manager.cpp at all (defensive check):
    (void)reentry_matches;

    std::cout << " OK (" << pm_lock_matches.size() << " PM-lock scopes, "
              << reentry_matches.size() << " reentry surfaces, 0 violations)\n";
}

// ============================================================================
int main()
{
    std::cout << "Phase 6 PR6.5b.7-close-prep — Static-grep lock-order tests\n";
    std::cout << "  (3-case suite per active_contract.md; Test 4 dropped per 10-min cap)\n\n";

    try {
        test_lock_order_no_reverse_acquisition();
        test_no_callout_under_peer_manager_mutex();
        test_no_node_context_callout_under_peer_manager_mutex();
    } catch (const std::exception& e) {
        std::cerr << "\nFAILED: " << e.what() << "\n";
        return 1;
    }

    std::cout << "\nAll 3 PR6.5b.7-close-prep static-grep lock-order tests passed.\n";
    return 0;
}
