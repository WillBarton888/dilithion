// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/fork_manager.h>
#include <node/fork_candidate.h>
#include <node/blockchain_storage.h>
#include <node/block_index.h>
#include <consensus/chain.h>
#include <consensus/pow.h>
#include <consensus/validation.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/block_fetcher.h>
#include <net/headers_manager.h>
#include <dfmp/mik.h>
#include <dfmp/identity_db.h>

#include <ctime>
#include <iostream>
#include <sstream>

// External chainstate reference
extern CChainState g_chainstate;

// ============================================================================
// ForkCandidate Implementation
// ============================================================================

ForkCandidate::ForkCandidate(const uint256& forkTipHash, int32_t forkPointHeight, int32_t expectedTipHeight,
                             const std::map<int32_t, uint256>& expectedHashes)
    : m_forkId(forkTipHash)
    , m_forkPointHeight(forkPointHeight)
    , m_expectedTipHeight(expectedTipHeight)
    , m_expectedHashes(expectedHashes)
    , m_lastBlockTime(std::chrono::steady_clock::now())
{
    std::cout << "[ForkCandidate] Created: fork_point=" << forkPointHeight
              << " expected_tip=" << expectedTipHeight
              << " blocks_needed=" << (expectedTipHeight - forkPointHeight)
              << " expected_hashes=" << expectedHashes.size()
              << " id=" << forkTipHash.GetHex().substr(0, 16) << "..." << std::endl;
}

bool ForkCandidate::IsExpectedBlock(const uint256& hash, int32_t height) const
{
    // First check height range
    if (height <= m_forkPointHeight || height > m_expectedTipHeight) {
        return false;
    }

    // If no expected hashes, fall back to height-only check
    if (m_expectedHashes.empty()) {
        return true;  // Height is in range, can't verify hash
    }

    // Check if hash matches expected
    auto it = m_expectedHashes.find(height);
    if (it == m_expectedHashes.end()) {
        // No expected hash at this height (shouldn't happen if built correctly)
        std::cerr << "[ForkCandidate] No expected hash for height " << height << std::endl;
        return true;  // Fall back to accepting by height
    }

    if (it->second != hash) {
        std::cerr << "[ForkCandidate] Hash mismatch at height " << height
                  << " expected=" << it->second.GetHex().substr(0, 16)
                  << " got=" << hash.GetHex().substr(0, 16) << std::endl;
        return false;
    }

    return true;
}

bool ForkCandidate::HasExpectedHashes() const
{
    return !m_expectedHashes.empty();
}

uint256 ForkCandidate::GetExpectedHashAtHeight(int32_t height) const
{
    auto it = m_expectedHashes.find(height);
    return (it != m_expectedHashes.end()) ? it->second : uint256();
}

bool ForkCandidate::AddBlock(const CBlock& block, const uint256& hash, int32_t height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Check height is in valid range
    if (height <= m_forkPointHeight || height > m_expectedTipHeight) {
        std::cerr << "[ForkCandidate] Block height " << height << " out of range ["
                  << (m_forkPointHeight + 1) << ", " << m_expectedTipHeight << "]" << std::endl;
        return false;
    }

    // Check for duplicate
    if (m_blocks.find(height) != m_blocks.end()) {
        std::cout << "[ForkCandidate] Duplicate block at height " << height << ", ignoring" << std::endl;
        return true;  // Not an error, just a duplicate
    }

    // Add the block
    m_blocks.emplace(height, ForkBlock(block, hash, height));
    m_lastBlockTime = std::chrono::steady_clock::now();

    std::cout << "[ForkCandidate] Added block at height " << height
              << " (" << m_blocks.size() << "/" << GetBlockCount() << " received)"
              << " hash=" << hash.GetHex().substr(0, 16) << "..." << std::endl;

    return true;
}

ForkBlock* ForkCandidate::GetBlockAtHeight(int32_t height)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_blocks.find(height);
    return (it != m_blocks.end()) ? &it->second : nullptr;
}

const ForkBlock* ForkCandidate::GetBlockAtHeight(int32_t height) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_blocks.find(height);
    return (it != m_blocks.end()) ? &it->second : nullptr;
}

bool ForkCandidate::HasAllBlocks() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    int expected = m_expectedTipHeight - m_forkPointHeight;
    return static_cast<int>(m_blocks.size()) >= expected;
}

bool ForkCandidate::AllBlocksPrevalidated() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!HasAllBlocks()) {
        return false;
    }

    for (const auto& [height, forkBlock] : m_blocks) {
        if (forkBlock.status != ForkBlockStatus::PREVALIDATED) {
            return false;
        }
    }
    return true;
}

bool ForkCandidate::IsTimedOut() const
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastBlockTime);
    return elapsed.count() >= FORK_TIMEOUT_SECONDS;
}

void ForkCandidate::TouchLastBlockTime()
{
    m_lastBlockTime = std::chrono::steady_clock::now();
}

std::vector<std::pair<int32_t, ForkBlock*>> ForkCandidate::GetBlocksInOrder()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::pair<int32_t, ForkBlock*>> result;
    result.reserve(m_blocks.size());

    for (auto& [height, forkBlock] : m_blocks) {
        result.push_back({height, &forkBlock});
    }

    // Already sorted by height (std::map is ordered)
    return result;
}

std::string ForkCandidate::GetStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream ss;

    int pending = 0, powValid = 0, prevalidated = 0, invalid = 0;
    for (const auto& [height, forkBlock] : m_blocks) {
        switch (forkBlock.status) {
            case ForkBlockStatus::PENDING: pending++; break;
            case ForkBlockStatus::POW_VALID: powValid++; break;
            case ForkBlockStatus::PREVALIDATED: prevalidated++; break;
            case ForkBlockStatus::INVALID: invalid++; break;
        }
    }

    ss << "ForkCandidate[id=" << m_forkId.GetHex().substr(0, 16) << "..."
       << " fork_point=" << m_forkPointHeight
       << " tip=" << m_expectedTipHeight
       << " blocks=" << m_blocks.size() << "/" << GetBlockCount()
       << " (pending=" << pending
       << " pow_valid=" << powValid
       << " prevalidated=" << prevalidated
       << " invalid=" << invalid << ")]";

    return ss.str();
}

// ============================================================================
// ForkManager Implementation
// ============================================================================

ForkManager& ForkManager::GetInstance()
{
    static ForkManager instance;
    return instance;
}

std::shared_ptr<ForkCandidate> ForkManager::CreateForkCandidate(
    const uint256& forkTipHash,
    int32_t forkPointHeight,
    int32_t expectedTipHeight,
    const std::map<int32_t, uint256>& expectedHashes)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Only one active fork at a time
    if (m_activeFork) {
        std::cerr << "[ForkManager] Cannot create fork - already have active fork: "
                  << m_activeFork->GetForkId().GetHex().substr(0, 16) << "..." << std::endl;
        return nullptr;
    }

    // Validate parameters
    if (forkPointHeight < 0 || expectedTipHeight <= forkPointHeight) {
        std::cerr << "[ForkManager] Invalid fork parameters: fork_point=" << forkPointHeight
                  << " expected_tip=" << expectedTipHeight << std::endl;
        return nullptr;
    }

    // Check reorg depth limit (MAX_REORG_DEPTH = 100 in ActivateBestChain)
    int reorgDepth = expectedTipHeight - forkPointHeight;
    if (reorgDepth > 100) {
        std::cerr << "[ForkManager] Fork too deep (" << reorgDepth << " blocks), max is 100" << std::endl;
        return nullptr;
    }

    m_activeFork = std::make_shared<ForkCandidate>(forkTipHash, forkPointHeight, expectedTipHeight, expectedHashes);

    std::cout << "[ForkManager] Created fork candidate: " << m_activeFork->GetStats() << std::endl;

    return m_activeFork;
}

void ForkManager::CancelFork(const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_activeFork) {
        return;
    }

    std::cout << "[ForkManager] Canceling fork: " << reason << std::endl;
    std::cout << "[ForkManager] Fork stats: " << m_activeFork->GetStats() << std::endl;

    m_activeFork.reset();
}

std::shared_ptr<ForkCandidate> ForkManager::GetActiveFork()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activeFork;
}

bool ForkManager::HasActiveFork() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activeFork != nullptr;
}

bool ForkManager::IsBlockForActiveFork(const uint256& blockHash, int32_t height) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_activeFork) {
        return false;
    }

    // Check if height is in fork range
    int32_t forkPoint = m_activeFork->GetForkPointHeight();
    int32_t expectedTip = m_activeFork->GetExpectedTipHeight();

    return (height > forkPoint && height <= expectedTip);
}

bool ForkManager::AddBlockToFork(const CBlock& block, const uint256& hash, int32_t height)
{
    std::shared_ptr<ForkCandidate> fork;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        fork = m_activeFork;
    }

    if (!fork) {
        std::cerr << "[ForkManager] No active fork to add block to" << std::endl;
        return false;
    }

    // Add the block to the fork candidate
    if (!fork->AddBlock(block, hash, height)) {
        return false;
    }

    return true;
}

bool ForkManager::PreValidateBlock(ForkBlock& forkBlock, CBlockchainDB& db)
{
    std::cout << "[ForkManager] Pre-validating block at height " << forkBlock.height
              << " hash=" << forkBlock.hash.GetHex().substr(0, 16) << "..." << std::endl;

    // Step 1: Validate block structure
    if (!ValidateBlockStructure(forkBlock.block)) {
        forkBlock.status = ForkBlockStatus::INVALID;
        forkBlock.invalidReason = "Invalid block structure";
        std::cerr << "[ForkManager] Block " << forkBlock.height << " failed structure check" << std::endl;
        return false;
    }

    // Step 2: Validate PoW
    if (!ValidatePoW(forkBlock.block, forkBlock.hash)) {
        forkBlock.status = ForkBlockStatus::INVALID;
        forkBlock.invalidReason = "Invalid proof of work";
        std::cerr << "[ForkManager] Block " << forkBlock.height << " failed PoW check" << std::endl;
        return false;
    }

    forkBlock.status = ForkBlockStatus::POW_VALID;

    // Step 3: Validate MIK/DFMP
    if (!ValidateMIK(forkBlock.block, forkBlock.height, db)) {
        forkBlock.status = ForkBlockStatus::INVALID;
        forkBlock.invalidReason = "Invalid MIK signature";
        std::cerr << "[ForkManager] Block " << forkBlock.height << " failed MIK check" << std::endl;
        return false;
    }

    forkBlock.status = ForkBlockStatus::PREVALIDATED;
    std::cout << "[ForkManager] Block " << forkBlock.height << " pre-validated successfully" << std::endl;

    return true;
}

bool ForkManager::ValidatePoW(const CBlock& block, const uint256& hash)
{
    // Basic PoW check (hash < target)
    return CheckProofOfWork(hash, block.nBits);
}

bool ForkManager::ValidateMIK(const CBlock& block, int32_t height, CBlockchainDB& db)
{
    // Get DFMP activation height
    int dfmpActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpActivationHeight : 0;

    // Pre-DFMP blocks don't need MIK validation
    if (height < dfmpActivationHeight) {
        return true;
    }

    // CRITICAL: For fork pre-validation, we do NOT use CheckProofOfWorkDFMP
    // because it honors dfmpAssumeValidHeight and can skip MIK validation.
    // We must ALWAYS validate MIK for fork blocks to catch invalid miners.
    //
    // This implements the "Hybrid Approach" from the plan:
    // 1. Try identity database lookup first
    // 2. If found in DB -> validate signature using DB pubkey
    // 3. If NOT found in DB:
    //    - If block has embedded pubkey (registration) -> validate using embedded pubkey
    //    - If block does NOT have embedded pubkey -> REJECT as invalid

    // Deserialize transactions to get coinbase
    CBlockValidator validator;
    std::vector<CTransactionRef> transactions;
    std::string deserializeError;
    if (!validator.DeserializeBlockTransactions(block, transactions, deserializeError)) {
        std::cerr << "[ForkManager] Failed to deserialize transactions: " << deserializeError << std::endl;
        return false;
    }

    if (transactions.empty()) {
        std::cerr << "[ForkManager] No transactions in block" << std::endl;
        return false;
    }

    // Get coinbase transaction (first transaction)
    const CTransaction& coinbaseTx = *transactions[0];

    // Parse MIK from coinbase scriptSig
    DFMP::CMIKScriptData mikData;
    const std::vector<uint8_t>& scriptSig = coinbaseTx.vin[0].scriptSig;

    if (!DFMP::ParseMIKFromScriptSig(scriptSig, mikData)) {
        std::cerr << "[ForkManager] Block " << height << ": Missing or malformed MIK data in coinbase" << std::endl;
        return false;
    }

    // Get the MIK public key for signature verification
    std::vector<uint8_t> pubkey;
    DFMP::Identity identity;

    if (mikData.isRegistration) {
        // Registration: pubkey is embedded in coinbase
        pubkey = mikData.pubkey;

        // Verify identity = SHA3-256(pubkey)[:20]
        DFMP::Identity derivedIdentity = DFMP::DeriveIdentityFromMIK(pubkey);
        if (derivedIdentity != mikData.identity) {
            std::cerr << "[ForkManager] Block " << height << ": MIK identity mismatch "
                      << "(derived: " << derivedIdentity.GetHex().substr(0, 16)
                      << ", claimed: " << mikData.identity.GetHex().substr(0, 16) << ")" << std::endl;
            return false;
        }

        identity = mikData.identity;
        std::cout << "[ForkManager] Block " << height << ": MIK registration - validating embedded pubkey" << std::endl;
    } else {
        // Reference: look up stored pubkey from identity database
        identity = mikData.identity;

        if (DFMP::g_identityDb == nullptr) {
            std::cerr << "[ForkManager] Block " << height << ": Identity database not initialized" << std::endl;
            return false;
        }

        if (!DFMP::g_identityDb->GetMIKPubKey(identity, pubkey)) {
            // Unknown identity AND no embedded pubkey - REJECT
            // This is the key fix: unknown identities MUST provide embedded pubkey
            std::cerr << "[ForkManager] Block " << height << ": Unknown MIK identity "
                      << identity.GetHex().substr(0, 16) << "... (no registration found, no embedded pubkey)" << std::endl;
            return false;
        }

        std::cout << "[ForkManager] Block " << height << ": MIK reference - found pubkey in DB" << std::endl;
    }

    // Verify MIK signature
    // Message = SHA3-256(prevBlockHash || height || timestamp || identity)
    if (!DFMP::VerifyMIKSignature(pubkey, mikData.signature,
                                   block.hashPrevBlock, height, block.nTime,
                                   identity)) {
        std::cerr << "[ForkManager] Block " << height << ": Invalid MIK signature for identity "
                  << identity.GetHex().substr(0, 16) << "..." << std::endl;
        return false;
    }

    std::cout << "[ForkManager] Block " << height << ": MIK signature verified for identity "
              << identity.GetHex().substr(0, 16) << "..." << std::endl;
    return true;
}

bool ForkManager::ValidateBlockStructure(const CBlock& block)
{
    // Basic structure checks for pre-validation
    // Full merkle root and transaction validation is done by ActivateBestChain

    // Must have transaction data
    if (block.vtx.empty()) {
        std::cerr << "[ForkManager] Block has no transaction data" << std::endl;
        return false;
    }

    // Check prevBlock is not null (except for genesis, but we don't expect genesis in forks)
    if (block.hashPrevBlock.IsNull()) {
        std::cerr << "[ForkManager] Block has null prevBlock hash" << std::endl;
        return false;
    }

    // Check timestamp is reasonable (not more than 2 hours in future)
    int64_t now = std::time(nullptr);
    if (block.nTime > now + 7200) {
        std::cerr << "[ForkManager] Block timestamp too far in future" << std::endl;
        return false;
    }

    // Note: Full merkle root validation requires deserializing transactions,
    // which is expensive. ActivateBestChain will do full validation including
    // merkle root, coinbase rules, and UTXO checks when connecting blocks.

    return true;
}

bool ForkManager::TriggerChainSwitch(NodeContext& ctx, CBlockchainDB& db)
{
    std::shared_ptr<ForkCandidate> fork;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        fork = m_activeFork;
    }

    if (!fork) {
        std::cerr << "[ForkManager] No active fork to switch to" << std::endl;
        return false;
    }

    // Verify all blocks are pre-validated
    if (!fork->AllBlocksPrevalidated()) {
        std::cerr << "[ForkManager] Cannot switch - not all blocks pre-validated" << std::endl;
        std::cerr << "[ForkManager] Fork stats: " << fork->GetStats() << std::endl;
        return false;
    }

    std::cout << "[ForkManager] All fork blocks pre-validated, triggering chain switch via ActivateBestChain" << std::endl;

    // Get the fork tip block index
    int32_t tipHeight = fork->GetExpectedTipHeight();
    ForkBlock* tipBlock = fork->GetBlockAtHeight(tipHeight);
    if (!tipBlock) {
        std::cerr << "[ForkManager] Cannot find fork tip block at height " << tipHeight << std::endl;
        return false;
    }

    // Get block index for the tip
    CBlockIndex* pindexNew = g_chainstate.GetBlockIndex(tipBlock->hash);
    if (!pindexNew) {
        std::cerr << "[ForkManager] No block index for fork tip " << tipBlock->hash.GetHex() << std::endl;
        return false;
    }

    // Call ActivateBestChain - it handles:
    // - WAL crash safety
    // - UTXO disconnect/connect
    // - Reorg depth limits
    // - Checkpoint validation
    // - Rollback on failure
    bool reorgOccurred = false;
    bool success = g_chainstate.ActivateBestChain(pindexNew, tipBlock->block, reorgOccurred);

    if (success) {
        std::cout << "[ForkManager] Chain switch successful! New tip at height " << tipHeight
                  << " reorg=" << (reorgOccurred ? "yes" : "no") << std::endl;
    } else {
        std::cerr << "[ForkManager] Chain switch failed! ActivateBestChain returned false" << std::endl;
    }

    // Clear fork state regardless of success/failure
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_activeFork.reset();
    }

    return success;
}

void ForkManager::ClearInFlightState(NodeContext& ctx, int32_t forkPointHeight)
{
    std::cout << "[ForkManager] Clearing in-flight state above height " << forkPointHeight << std::endl;

    // Clear block fetcher state
    if (ctx.block_fetcher) {
        int cleared = ctx.block_fetcher->ClearAboveHeight(forkPointHeight);
        std::cout << "[ForkManager] Cleared " << cleared << " in-flight blocks" << std::endl;
    }

    // Optionally clear headers manager state (fork headers)
    // Note: This may not be needed if we invalidate headers separately
}

bool ForkManager::CheckTimeout()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_activeFork) {
        return false;
    }

    if (m_activeFork->IsTimedOut()) {
        std::cout << "[ForkManager] Fork timed out (60s since last block)" << std::endl;
        return true;
    }

    return false;
}

std::string ForkManager::GetStats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_activeFork) {
        return "ForkManager[no active fork]";
    }

    return m_activeFork->GetStats();
}
