// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <miner/vdf_miner.h>
#include <vdf/coinbase_vdf.h>
#include <consensus/pow.h>  // HashLessThan for VDF distribution comparison
#include <crypto/sha3.h>
#include <util/logging.h>

#include <cstring>
#include <iostream>

CVDFMiner::CVDFMiner() = default;

CVDFMiner::~CVDFMiner()
{
    Stop();
}

void CVDFMiner::Start()
{
    if (m_running.exchange(true))
        return;  // Already running

    m_abort = false;
    m_lastHeightChangeTime = std::chrono::steady_clock::now();
    m_thread = std::thread(&CVDFMiner::MiningLoop, this);
}

void CVDFMiner::Stop()
{
    if (!m_running.exchange(false))
        return;  // Already stopped

    m_abort = true;
    m_epochCV.notify_all();

    if (m_thread.joinable())
        m_thread.join();

    m_currentHeight = 0;
}

void CVDFMiner::OnNewBlock(int newTipHeight)
{
    // Record when we learned about this height change (for minimum block time)
    m_lastHeightChangeTime = std::chrono::steady_clock::now();

    // VDF Distribution: If the new block is at the SAME height we're computing for,
    // don't abort. Our VDF output may be lower and win the distribution.
    if (newTipHeight > 0 && newTipHeight == static_cast<int>(m_currentHeight.load())) {
        std::cout << "[VDF Miner] Competing block at height " << newTipHeight
                  << " -- continuing computation (distribution)" << std::endl;
        return;
    }

    // Different height: standard epoch change (abort current work)
    {
        std::lock_guard<std::mutex> lock(m_epochMutex);
        m_epochChanged = true;
    }
    m_abort = true;
    m_epochCV.notify_all();
}

void CVDFMiner::SetBlockFoundCallback(BlockFoundCallback cb)
{
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_blockFoundCallback = std::move(cb);
}

void CVDFMiner::SetTemplateProvider(TemplateProvider provider)
{
    m_templateProvider = std::move(provider);
}

void CVDFMiner::SetMinerAddress(const Address& addr)
{
    m_minerAddress = addr;
}

void CVDFMiner::SetMIKIdentity(const Address& mikId)
{
    m_mikIdentity = mikId;
}

void CVDFMiner::SetIterations(uint64_t iterations)
{
    m_iterations = iterations;
}

void CVDFMiner::SetCooldownTracker(CCooldownTracker* tracker)
{
    m_cooldownTracker = tracker;
}

void CVDFMiner::SetTipOutputProvider(TipOutputProvider provider)
{
    m_tipOutputProvider = std::move(provider);
}

void CVDFMiner::SetMinBlockTime(int seconds)
{
    m_minBlockTimeSec = seconds;
}

// ---------------------------------------------------------------------------
// Main mining loop
// ---------------------------------------------------------------------------

void CVDFMiner::MiningLoop()
{
    std::cout << "[VDF Miner] Started (iterations=" << m_iterations << ")" << std::endl;

    while (m_running) {
        // ---------------------------------------------------------------
        // 0. Minimum block time wait
        // ---------------------------------------------------------------
        // Wait until vdfMinBlockTime seconds have elapsed since the last
        // height change. This ensures all miners (fast and slow) finish
        // their current-height VDF and participate in the distribution before
        // the chain advances to the next height.
        if (m_minBlockTimeSec > 0 && !m_firstRound) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_lastHeightChangeTime).count();
            int remaining = m_minBlockTimeSec - static_cast<int>(elapsed);

            if (remaining > 0) {
                std::cout << "[VDF Miner] Waiting " << remaining
                          << "s (min block time " << m_minBlockTimeSec << "s)"
                          << std::endl;
                std::unique_lock<std::mutex> lock(m_epochMutex);
                m_epochCV.wait_for(lock, std::chrono::seconds(remaining),
                    [this] { return m_epochChanged || !m_running; });

                // If epoch changed during wait, restart loop (re-check wait)
                if (m_epochChanged) {
                    m_epochChanged = false;
                    continue;
                }
                if (!m_running) break;
            }
        }
        m_firstRound = false;

        // ---------------------------------------------------------------
        // 1. Get a fresh block template
        // ---------------------------------------------------------------
        std::optional<CBlockTemplate> templateOpt;
        if (m_templateProvider) {
            templateOpt = m_templateProvider();
        }

        if (!templateOpt) {
            // No template available — wait and retry
            std::unique_lock<std::mutex> lock(m_epochMutex);
            m_epochCV.wait_for(lock, std::chrono::seconds(5),
                [this] { return m_epochChanged || !m_running; });
            m_epochChanged = false;
            continue;
        }

        uint32_t height = templateOpt->nHeight;
        uint256 prevHash = templateOpt->block.hashPrevBlock;
        m_currentHeight = height;

        // Extract miner address from the template's coinbase (authoritative source).
        // This ensures the VDF challenge matches the coinbase payout address.
        Address minerAddr = m_minerAddress;  // fallback
        {
            std::array<uint8_t, 20> extracted{};
            if (ExtractCoinbaseAddress(templateOpt->block, extracted)) {
                minerAddr = extracted;
            }
        }

        // ---------------------------------------------------------------
        // 2. Check cooldown (uses MIK identity, not payout address)
        // ---------------------------------------------------------------
        // Cooldown tracks by MIK identity to prevent address rotation bypass.
        // MIK is set from the wallet's MIK key; falls back to payout address.
        Address cooldownId = (m_mikIdentity != Address{}) ? m_mikIdentity : minerAddr;
        bool stallBypassed = false;

        if (m_cooldownTracker && m_cooldownTracker->IsInCooldown(cooldownId, height)) {
            // Chain stall detection: if no block has been produced for a long
            // time, bypass cooldown so the chain can recover.  Without this,
            // a stall is permanent — height never advances so cooldowns never
            // expire.  Threshold: 10 minutes (raised from 5 min to match
            // consensus stallExemptionV2 and prevent private fork mining).
            static constexpr int STALL_THRESHOLD_SEC = 600;
            auto now = std::chrono::steady_clock::now();
            auto sinceLastBlock = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_lastHeightChangeTime).count();

            if (sinceLastBlock >= STALL_THRESHOLD_SEC) {
                std::cout << "[VDF Miner] Chain stall detected (" << sinceLastBlock
                          << "s since last block) -- bypassing cooldown" << std::endl;
                stallBypassed = true;
                // Fall through to VDF computation
            } else {
                int cd = m_cooldownTracker->GetCooldownBlocks();
                int lastWin = m_cooldownTracker->GetLastWinHeight(cooldownId);
                int resumeAt = lastWin + cd + 1;
                std::cout << "[VDF Miner] In cooldown until block " << resumeAt
                          << " (current: " << height << ", cooldown: " << cd << " blocks)"
                          << std::endl;

                // Wait for new block, or timeout after 2 minutes so a solo miner
                // (cooldown=0 with MIN_COOLDOWN=0) never deadlocks if it somehow
                // enters this branch due to a stale cached miner count.
                std::unique_lock<std::mutex> lock(m_epochMutex);
                m_epochCV.wait_for(lock, std::chrono::seconds(120),
                                   [this] { return m_epochChanged || !m_running; });
                m_epochChanged = false;
                continue;
            }
        }

        // ---------------------------------------------------------------
        // 3. Compute VDF challenge
        // ---------------------------------------------------------------
        auto challenge = ComputeVDFChallenge(prevHash, height, minerAddr);

        // ---------------------------------------------------------------
        // 4. Run VDF computation (blocking, ~200s mainnet / ~10s testnet)
        // ---------------------------------------------------------------
        m_abort = false;
        std::cout << "[VDF Miner] Computing VDF for block " << height
                  << " (" << m_iterations << " iterations)..." << std::endl;

        auto startTime = std::chrono::steady_clock::now();

        vdf::VDFConfig cfg;
        cfg.target_iterations = m_iterations;
        cfg.progress_interval = 1'000'000;  // Progress every ~1M iterations

        vdf::VDFResult result = vdf::compute(challenge, m_iterations, cfg,
            [this](uint64_t current, uint64_t total) {
                // Progress reporting (can't truly abort chiavdf mid-computation,
                // but we'll check the flag after compute() returns)
                if (current > 0 && current % 10'000'000 == 0) {
                    double pct = 100.0 * current / total;
                    std::cout << "[VDF Miner] Progress: " << pct << "%" << std::endl;
                }
            });

        auto elapsed = std::chrono::steady_clock::now() - startTime;
        double elapsedSec = std::chrono::duration<double>(elapsed).count();

        // ---------------------------------------------------------------
        // 5. Check if epoch changed during computation
        // ---------------------------------------------------------------
        if (m_abort.load() || !m_running) {
            std::cout << "[VDF Miner] Computation for block " << height
                      << " discarded (new block arrived after "
                      << static_cast<int>(elapsedSec) << "s)" << std::endl;
            std::lock_guard<std::mutex> lock(m_epochMutex);
            m_epochChanged = false;
            continue;
        }

        std::cout << "[VDF Miner] VDF computed in " << elapsedSec << "s"
                  << " (proof: " << result.proof.size() << " bytes)" << std::endl;

        // ---------------------------------------------------------------
        // 6. Finalize VDF block
        // ---------------------------------------------------------------
        CBlock block = templateOpt->block;
        if (!FinalizeVDFBlock(block, result, minerAddr, height)) {
            std::cerr << "[VDF Miner] ERROR: Failed to finalize VDF block" << std::endl;
            continue;
        }

        // ---------------------------------------------------------------
        // 7. Final epoch check (block may have arrived during finalization)
        // ---------------------------------------------------------------
        if (m_abort.load() || !m_running) {
            std::cout << "[VDF Miner] Block discarded after finalization (epoch changed)"
                      << std::endl;
            std::lock_guard<std::mutex> lock(m_epochMutex);
            m_epochChanged = false;
            continue;
        }

        // ---------------------------------------------------------------
        // 7b. VDF Distribution: Pre-submission output comparison
        // ---------------------------------------------------------------
        // If a competing block arrived at the same height during our computation,
        // only submit if our VDF output is lower (we'd win the distribution).
        // NOTE: There's an inherent race between this check and actual submission —
        // the tip could change between here and ActivateBestChain. That's fine:
        // ActivateBestChain does the authoritative comparison. This is just an
        // optimization to avoid unnecessary block construction + relay.
        if (m_tipOutputProvider) {
            auto [tipHeight, tipVdfOutput] = m_tipOutputProvider();
            if (tipHeight == static_cast<int>(height) && !tipVdfOutput.IsNull()) {
                uint256 ourOutput;
                std::memcpy(ourOutput.data, result.output.data(), 32);
                if (!HashLessThan(ourOutput, tipVdfOutput)) {
                    std::cout << "[VDF Miner] Our output is NOT lower than tip -- skipping"
                              << std::endl;
                    std::cout << "  Our output: " << ourOutput.GetHex().substr(0, 16) << "..." << std::endl;
                    std::cout << "  Tip output: " << tipVdfOutput.GetHex().substr(0, 16) << "..." << std::endl;
                    std::unique_lock<std::mutex> lk(m_epochMutex);
                    m_epochCV.wait_for(lk, std::chrono::seconds(10),
                        [this] { return m_epochChanged || !m_running; });
                    m_epochChanged = false;
                    continue;
                }
                std::cout << "[VDF Miner] Our output is LOWER than tip -- submitting!" << std::endl;
                std::cout << "  Our output: " << ourOutput.GetHex().substr(0, 16) << "..." << std::endl;
                std::cout << "  Tip output: " << tipVdfOutput.GetHex().substr(0, 16) << "..." << std::endl;
            }
        }

        // ---------------------------------------------------------------
        // 7c. Pre-submission cooldown recheck
        // ---------------------------------------------------------------
        // The cooldown parameters (active miner count) may have changed
        // during VDF computation (~45s) as new blocks arrived.  Re-check
        // now so we don't submit a block that consensus will reject.
        // Exception: if we bypassed cooldown due to a chain stall, honour
        // that decision — otherwise we create a deadlock where the stall
        // bypass computes the VDF but the re-check always blocks submission.
        if (!stallBypassed && m_cooldownTracker && m_cooldownTracker->IsInCooldown(cooldownId, height)) {
            int cd = m_cooldownTracker->GetCooldownBlocks();
            int lastWin = m_cooldownTracker->GetLastWinHeight(cooldownId);
            std::cout << "[VDF Miner] Cooldown changed during computation -- skipping submission"
                      << " (last win: " << lastWin << ", cooldown: " << cd
                      << ", height: " << height << ")" << std::endl;
            std::unique_lock<std::mutex> lk(m_epochMutex);
            m_epochCV.wait_for(lk, std::chrono::seconds(10),
                               [this] { return m_epochChanged || !m_running; });
            m_epochChanged = false;
            continue;
        }

        // ---------------------------------------------------------------
        // 8. Submit block via callback
        // ---------------------------------------------------------------
        {
            std::lock_guard<std::mutex> lock(m_callbackMutex);
            if (m_blockFoundCallback) {
                std::cout << std::endl;
                std::cout << "======================================" << std::endl;
                std::cout << "[VDF Miner] BLOCK PRODUCED!" << std::endl;
                std::cout << "======================================" << std::endl;
                std::cout << "  Height: " << height << std::endl;
                std::cout << "  Hash: " << block.GetHash().GetHex() << std::endl;
                std::cout << "  VDF time: " << elapsedSec << "s" << std::endl;
                std::cout << "======================================" << std::endl;
                std::cout << std::endl;

                m_blockFoundCallback(block);
                m_blocksFound++;

                // Record submission time as height change (our own block advances chain)
                m_lastHeightChangeTime = std::chrono::steady_clock::now();
            }
        }

        // Wait for epoch change. Step 0 at the top of the loop handles
        // the minimum block time delay, so we just need to wait for
        // notification here.
        std::unique_lock<std::mutex> lock(m_epochMutex);
        m_epochCV.wait_for(lock, std::chrono::seconds(5),
            [this] { return m_epochChanged || !m_running; });
        m_epochChanged = false;
    }

    std::cout << "[VDF Miner] Stopped" << std::endl;
    m_currentHeight = 0;
}

// ---------------------------------------------------------------------------
// FinalizeVDFBlock
// ---------------------------------------------------------------------------

bool CVDFMiner::FinalizeVDFBlock(CBlock& block, const vdf::VDFResult& result,
                                  const Address& /* minerAddr */, uint32_t /* height */)
{
    // --- Set header VDF fields ---
    block.nVersion = CBlockHeader::VDF_VERSION;
    std::memcpy(block.vdfOutput.data, result.output.data(), 32);
    block.vdfProofHash = CoinbaseVDF::ComputeProofHash(result.proof);

    // --- Modify coinbase to embed VDF proof ---
    if (block.vtx.empty()) {
        std::cerr << "[VDF] FinalizeVDFBlock: empty vtx" << std::endl;
        return false;
    }

    const uint8_t* data = block.vtx.data();
    size_t dataSize = block.vtx.size();

    // Parse tx count varint
    uint64_t txCount = 0;
    size_t txCountSize = 0;
    if (data[0] < 253) {
        txCount = data[0];
        txCountSize = 1;
    } else if (data[0] == 253 && dataSize >= 3) {
        txCount = static_cast<uint64_t>(data[1]) | (static_cast<uint64_t>(data[2]) << 8);
        txCountSize = 3;
    } else {
        std::cerr << "[VDF] FinalizeVDFBlock: unsupported tx count encoding" << std::endl;
        return false;
    }

    if (txCount == 0) {
        std::cerr << "[VDF] FinalizeVDFBlock: zero transactions" << std::endl;
        return false;
    }

    // Deserialize the coinbase transaction (first tx after count)
    CTransaction coinbase;
    size_t coinbaseBytes = 0;
    std::string deserErr;
    if (!coinbase.Deserialize(data + txCountSize, dataSize - txCountSize,
                              &deserErr, &coinbaseBytes)) {
        std::cerr << "[VDF] FinalizeVDFBlock: failed to deserialize coinbase: "
                  << deserErr << std::endl;
        return false;
    }
    size_t coinbaseEnd = txCountSize + coinbaseBytes;

    // Embed VDF proof in coinbase scriptSig
    if (coinbase.vin.empty()) {
        std::cerr << "[VDF] FinalizeVDFBlock: coinbase has no inputs" << std::endl;
        return false;
    }
    CoinbaseVDF::EmbedProof(coinbase.vin[0], result.proof);

    // Re-serialize the modified coinbase
    std::vector<uint8_t> newCoinbaseBytes = coinbase.Serialize();

    // Rebuild vtx: [tx_count] [modified coinbase] [remaining txs unchanged]
    std::vector<uint8_t> newVtx;
    newVtx.reserve(txCountSize + newCoinbaseBytes.size() + (dataSize - coinbaseEnd));

    // tx count (unchanged)
    newVtx.insert(newVtx.end(), data, data + txCountSize);
    // Modified coinbase
    newVtx.insert(newVtx.end(), newCoinbaseBytes.begin(), newCoinbaseBytes.end());
    // Remaining transactions (unchanged bytes)
    if (coinbaseEnd < dataSize) {
        newVtx.insert(newVtx.end(), data + coinbaseEnd, data + dataSize);
    }

    block.vtx = std::move(newVtx);

    // --- Recompute merkle root ---
    // Deserialize all transactions to get their hashes
    std::vector<uint256> txHashes;
    txHashes.reserve(txCount);

    const uint8_t* newData = block.vtx.data();
    size_t newSize = block.vtx.size();
    size_t offset = txCountSize;

    for (uint64_t i = 0; i < txCount; i++) {
        CTransaction tx;
        size_t consumed = 0;
        if (!tx.Deserialize(newData + offset, newSize - offset, nullptr, &consumed)) {
            std::cerr << "[VDF] FinalizeVDFBlock: failed to deserialize tx " << i
                      << " for merkle root" << std::endl;
            return false;
        }
        txHashes.push_back(tx.GetHash());
        offset += consumed;
    }

    // Build merkle tree (same algorithm as CMiningController::BuildMerkleRoot)
    if (txHashes.empty()) return false;

    std::vector<uint256> tree = txHashes;
    while (tree.size() > 1) {
        std::vector<uint256> nextLevel;
        nextLevel.reserve((tree.size() + 1) / 2);

        for (size_t i = 0; i < tree.size(); i += 2) {
            size_t j = std::min(i + 1, tree.size() - 1);

            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(), tree[i].begin(), tree[i].end());
            combined.insert(combined.end(), tree[j].begin(), tree[j].end());

            uint256 hash;
            SHA3_256(combined.data(), combined.size(), hash.data);
            nextLevel.push_back(hash);
        }
        tree = std::move(nextLevel);
    }

    block.hashMerkleRoot = tree[0];

    // Invalidate hash cache since header changed
    block.InvalidateCache();

    return true;
}
