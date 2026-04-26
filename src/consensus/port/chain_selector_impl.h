// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 — concrete IChainSelector implementation for Dilithion. The
// adapter wraps an existing CChainState and routes the frozen Phase 0
// IChainSelector surface (11 methods) into the underlying chain-state
// machinery. Real method bodies land in PR5.2.A / PR5.3 — PR5.1 ships
// the scaffold with assert(false) so the whole subsystem links and
// the type system can be exercised.
//
// PR5.1 scope (this file):
//   * Class declaration only — bodies in chain_selector_impl.cpp
//   * No new state owned by the adapter at scaffolding time. Per plan
//     §2.1: the candidate-set (`m_setBlockIndexCandidates`) lives on
//     CChainState itself, not on the adapter.
//   * Adapter holds a CChainState& reference; lifetime managed by the
//     factory + g_node_context.

#ifndef DILITHION_CONSENSUS_PORT_CHAIN_SELECTOR_IMPL_H
#define DILITHION_CONSENSUS_PORT_CHAIN_SELECTOR_IMPL_H

#include <consensus/ichain_selector.h>

class CChainState;

namespace dilithion::consensus::port {

class ChainSelectorAdapter final : public ::dilithion::consensus::IChainSelector {
public:
    explicit ChainSelectorAdapter(CChainState& chainstate);
    ~ChainSelectorAdapter() override = default;

    ChainSelectorAdapter(const ChainSelectorAdapter&) = delete;
    ChainSelectorAdapter& operator=(const ChainSelectorAdapter&) = delete;

    bool ProcessNewBlock(std::shared_ptr<const CBlock> block,
                         bool force_processing,
                         bool* triggered_reorg = nullptr) override;
    bool ProcessNewHeader(const CBlockHeader& header) override;

    CBlockIndex* GetActiveTip() const override;
    int GetActiveHeight() const override;
    uint256 GetActiveTipHash() const override;

    std::vector<::dilithion::consensus::ChainTipInfo> GetChainTips() const override;
    CBlockIndex* FindMostWorkChain() const override;
    CBlockIndex* LookupBlockIndex(const uint256& hash) const override;

    bool InvalidateBlock(const uint256& hash) override;
    bool ReconsiderBlock(const uint256& hash) override;

    bool IsInitialBlockDownload() const override;

private:
    CChainState& m_chainstate;
};

}  // namespace dilithion::consensus::port

#endif  // DILITHION_CONSENSUS_PORT_CHAIN_SELECTOR_IMPL_H
