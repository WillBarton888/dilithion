<?php
/**
 * Block Explorer API - Stats Endpoint
 *
 * Returns network statistics:
 *   blocks, difficulty, networkhashps, supply, connections,
 *   avgBlockTime, chainTips
 */

require_once __DIR__ . '/rpc.php';

// Gather stats from multiple RPC calls
$blockchainInfo = dilithionRPC('getblockchaininfo');
$connectionCount = dilithionRPC('getconnectioncount');
$chainTips = dilithionRPC('getchaintips');

// Estimate network hashrate from difficulty and block time
// Formula: hashrate = difficulty * (2^32 / max_mantissa) / avg_block_time
// max_target compact = 0x1f060000, mantissa = 0x060000 = 393216
// 2^32 / 393216 = 10922.667
$networkHashps = null;

if ($blockchainInfo === null) {
    sendError('Failed to connect to node.', 503);
}

$height = $blockchainInfo['blocks'] ?? 0;

// Calculate approximate supply based on block height
// Dilithion: 50 DIL per block (adjust if different)
$supply = null;
$mikInfo = dilithionRPC('getmikdistribution');
if ($mikInfo !== null && isset($mikInfo['total_supply'])) {
    $supply = $mikInfo['total_supply'];
} else {
    // Fallback: estimate from block height
    $supply = $height * 50;
}

// Calculate average block time from last 10 blocks
$avgBlockTime = null;
if ($height >= 10) {
    $tipHashResult = dilithionRPC('getblockhash', ['height' => $height]);
    $oldHashResult = dilithionRPC('getblockhash', ['height' => $height - 10]);

    $tipHash = is_array($tipHashResult) ? ($tipHashResult['blockhash'] ?? null) : $tipHashResult;
    $oldHash = is_array($oldHashResult) ? ($oldHashResult['blockhash'] ?? null) : $oldHashResult;

    if ($tipHash !== null && $oldHash !== null) {
        $tipBlock = dilithionRPC('getblock', ['hash' => $tipHash, 'verbosity' => 1]);
        $oldBlock = dilithionRPC('getblock', ['hash' => $oldHash, 'verbosity' => 1]);

        if ($tipBlock !== null && $oldBlock !== null) {
            $timeDiff = ($tipBlock['time'] ?? 0) - ($oldBlock['time'] ?? 0);
            $avgBlockTime = $timeDiff / 10.0;
        }
    }
}

// Estimate network hashrate from difficulty and average block time
$difficulty = $blockchainInfo['difficulty'] ?? 0;
if ($difficulty > 0 && $avgBlockTime !== null && $avgBlockTime > 0) {
    // hashrate = difficulty * (2^32 / max_mantissa) / avg_block_time
    $networkHashps = $difficulty * 10922.667 / $avgBlockTime;
}

sendJSON([
    'blocks' => $height,
    'difficulty' => $difficulty,
    'networkhashps' => $networkHashps,
    'supply' => $supply,
    'connections' => $connectionCount,
    'avgBlockTime' => $avgBlockTime,
    'chain' => $blockchainInfo['chain'] ?? 'main',
    'chainTips' => $chainTips ?? [],
    'bestblockhash' => $blockchainInfo['bestblockhash'] ?? null,
]);
