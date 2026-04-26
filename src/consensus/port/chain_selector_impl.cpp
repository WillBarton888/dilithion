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
#include <node/block_index.h>
#include <primitives/block.h>

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

bool ChainSelectorAdapter::ProcessNewHeader(const CBlockHeader& /*header*/)
{
    assert(false && "ChainSelectorAdapter::ProcessNewHeader — real impl in PR5.3");
    return false;
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
