// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 — ChainSelectorAdapter PR5.1 scaffold. All 11 IChainSelector
// methods declared and stubbed with assert(false). Real bodies land in:
//   * PR5.2.A — GetChainTips (status-enum mapping)
//   * PR5.3   — ProcessNewBlock, ProcessNewHeader, FindMostWorkChain,
//               InvalidateBlock, ReconsiderBlock, IsInitialBlockDownload
//   * PR5.1   — GetActiveTip / GetActiveHeight / GetActiveTipHash /
//               LookupBlockIndex (4 trivial getters wired now to keep
//               the type-system honest and validate adapter wiring)

#include <consensus/port/chain_selector_impl.h>

#include <consensus/chain.h>
#include <consensus/chain_work.h>
#include <node/block_index.h>
#include <primitives/block.h>

#include <atomic>
#include <cassert>

namespace dilithion::consensus::port {

ChainSelectorAdapter::ChainSelectorAdapter(CChainState& chainstate)
    : m_chainstate(chainstate)
{
}

// ============================================================================
// PR5.1 trivial getters — real wiring (NOT assert(false)).
// ============================================================================

CBlockIndex* ChainSelectorAdapter::GetActiveTip() const
{
    return m_chainstate.GetTip();
}

int ChainSelectorAdapter::GetActiveHeight() const
{
    return m_chainstate.GetHeight();
}

uint256 ChainSelectorAdapter::GetActiveTipHash() const
{
    const CBlockIndex* tip = m_chainstate.GetTip();
    return tip ? tip->GetBlockHash() : uint256();
}

CBlockIndex* ChainSelectorAdapter::LookupBlockIndex(const uint256& hash) const
{
    return m_chainstate.GetBlockIndex(hash);
}

// ============================================================================
// PR5.2.A / PR5.3 — assert(false) until those PRs land bodies.
// ============================================================================

bool ChainSelectorAdapter::ProcessNewBlock(std::shared_ptr<const CBlock> /*block*/,
                                           bool /*force_processing*/,
                                           bool* /*triggered_reorg*/)
{
    assert(false && "ChainSelectorAdapter::ProcessNewBlock — real impl in PR5.3");
    return false;
}

// Phase 5 PR5.3 prerequisite (Day 2 PM, 2026-04-26):
// Populate CChainState::mapBlockIndex with EVERY received header, matching
// upstream Bitcoin Core's invariant. Pre-validation entries get nStatus =
// BLOCK_VALID_HEADER (NOT BLOCK_VALID_TRANSACTIONS); the existing
// block-receive code path upgrades the status when the block arrives and
// validates (PR5.3 Day 3+).
//
// Guardrails (per Cursor sign-off 2026-04-26):
//   G1 — pre-validation siblings remain visible to fork detection.
//   G2 — BLOCK_VALID_HEADER-only entries are NOT IsInvalid(); BLOCK_FAILED_*
//        flags are only set on entries that reached full block validation.
//
// Returns false (orphan) if parent is missing — caller (HeadersSync /
// HeadersManager) is responsible for topological-order delivery. Returns
// true (idempotent) if entry already exists.
bool ChainSelectorAdapter::ProcessNewHeader(const CBlockHeader& header)
{
    const uint256 hash = header.GetHash();

    // Idempotency: already in mapBlockIndex (could be from a prior
    // ProcessNewHeader call OR from full-block validation). No work needed.
    if (m_chainstate.HasBlockIndex(hash)) {
        return true;
    }

    // Locate parent. A null hashPrevBlock means genesis (height 0, no parent).
    CBlockIndex* pprev = nullptr;
    int nHeight = 0;
    uint256 nChainWork = ::dilithion::consensus::ComputeChainWork(header.nBits);
    if (!header.hashPrevBlock.IsNull()) {
        pprev = m_chainstate.GetBlockIndex(header.hashPrevBlock);
        if (!pprev) {
            // Orphan — caller must order parents before children.
            return false;
        }
        nHeight = pprev->nHeight + 1;
        nChainWork = ::dilithion::consensus::AddChainWork(
            pprev->nChainWork,
            ::dilithion::consensus::ComputeChainWork(header.nBits));
    }

    auto pindex = std::make_unique<CBlockIndex>(header);
    pindex->pprev = pprev;
    pindex->nHeight = nHeight;
    pindex->nChainWork = nChainWork;
    pindex->nStatus = CBlockIndex::BLOCK_VALID_HEADER;  // G2: pre-validation only
    pindex->phashBlock = hash;

    // Deterministic insertion order for the candidate-set comparator
    // tiebreak. Process-local atomic — every header receipt gets a
    // fresh sequence id.
    static std::atomic<uint32_t> s_seq{1};
    pindex->nSequenceId = s_seq.fetch_add(1, std::memory_order_relaxed);

    return m_chainstate.AddBlockIndex(hash, std::move(pindex));
}

// Phase 5 PR5.2.A: real implementation. Forwards into the (extended)
// CChainState::GetChainTips and converts each string status into the
// frozen ChainTipInfo::Status enum.
//
// Mapping (must stay in sync with chain.cpp::GetChainTips status assignments):
//   "active"        -> Status::Active
//   "invalid"       -> Status::InvalidBlock
//   "valid-fork"    -> Status::ValidFork
//   "valid-headers" -> Status::ValidHeaders
//   "unknown"       -> Status::Unknown   (also fallback for any drift)
std::vector<ChainTipInfo> ChainSelectorAdapter::GetChainTips() const
{
    using Status = ChainTipInfo::Status;
    const auto legacy_tips = m_chainstate.GetChainTips();

    std::vector<ChainTipInfo> out;
    out.reserve(legacy_tips.size());
    for (const auto& t : legacy_tips) {
        ChainTipInfo info;
        info.hash = t.hash;
        info.height = t.height;
        info.branchlen = t.branchlen;
        info.chain_work = t.chain_work;
        if      (t.status == "active")        info.status = Status::Active;
        else if (t.status == "invalid")       info.status = Status::InvalidBlock;
        else if (t.status == "valid-fork")    info.status = Status::ValidFork;
        else if (t.status == "valid-headers") info.status = Status::ValidHeaders;
        else                                  info.status = Status::Unknown;
        out.push_back(info);
    }
    return out;
}

CBlockIndex* ChainSelectorAdapter::FindMostWorkChain() const
{
    assert(false && "ChainSelectorAdapter::FindMostWorkChain — real impl in PR5.3");
    return nullptr;
}

bool ChainSelectorAdapter::InvalidateBlock(const uint256& /*hash*/)
{
    assert(false && "ChainSelectorAdapter::InvalidateBlock — real impl in PR5.3");
    return false;
}

bool ChainSelectorAdapter::ReconsiderBlock(const uint256& /*hash*/)
{
    assert(false && "ChainSelectorAdapter::ReconsiderBlock — real impl in PR5.3");
    return false;
}

bool ChainSelectorAdapter::IsInitialBlockDownload() const
{
    assert(false && "ChainSelectorAdapter::IsInitialBlockDownload — real impl in PR5.3");
    return false;
}

}  // namespace dilithion::consensus::port
