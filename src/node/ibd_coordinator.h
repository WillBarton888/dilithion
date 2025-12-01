// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_IBD_COORDINATOR_H
#define DILITHION_NODE_IBD_COORDINATOR_H

#include <chrono>

class CChainState;
class CHeadersManager;
class CBlockFetcher;
class CPeerManager;
class CConnectionManager;
class CNetMessageProcessor;

/**
 * @brief Encapsulates the Initial Block Download coordination logic.
 *
 * Dilithion originally embedded all block download orchestration inside
 * the main node loop.  This class collects the state (backoff counters,
 * header deltas) and exposes a single Tick() entry point, mirroring the
 * structure used by Bitcoin Core's net_processing loop.
 */
class CIbdCoordinator {
public:
    CIbdCoordinator(CChainState& chainstate,
                    CHeadersManager& headers_manager,
                    CBlockFetcher& block_fetcher,
                    CPeerManager& peer_manager,
                    CConnectionManager& connection_manager,
                    CNetMessageProcessor& message_processor);

    /**
     * @brief Executes one maintenance pass of block download coordination.
     *
     * Call this from the main event loop once per second.  It handles:
     *  - Exponential backoff when no peers are available.
     *  - Queueing headers-ahead blocks for download.
     *  - Dispatching GETDATA requests up to the in-flight limit.
     *  - Retrying timed-out blocks and disconnecting stalling peers.
     */
    void Tick();

private:
    void ResetBackoffOnNewHeaders(int header_height);
    bool ShouldAttemptDownload() const;
    void HandleNoPeers(std::chrono::steady_clock::time_point now);
    void DownloadBlocks(int header_height, int chain_height, std::chrono::steady_clock::time_point now);
    void QueueMissingBlocks(int chain_height, int blocks_to_queue);
    bool FetchBlocks();
    void RetryTimeoutsAndStalls();

    CChainState& m_chainstate;
    CHeadersManager& m_headers_manager;
    CBlockFetcher& m_block_fetcher;
    CPeerManager& m_peer_manager;
    CConnectionManager& m_connection_manager;
    CNetMessageProcessor& m_message_processor;

    int m_last_header_height{0};
    int m_ibd_no_peer_cycles{0};
    std::chrono::steady_clock::time_point m_last_ibd_attempt;
};

#endif // DILITHION_NODE_IBD_COORDINATOR_H

