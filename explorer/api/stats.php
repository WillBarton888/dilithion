<?php
/**
 * Block Explorer API - Stats Endpoint
 *
 * Returns network statistics:
 *   blocks, difficulty, networkhashps, supply, connections,
 *   avgBlockTime, chainTips, holders
 *
 * Caches results for 10 seconds to avoid RPC overload.
 * Holder count cached separately for 60 seconds (expensive query).
 */

require_once __DIR__ . "/rpc.php";

// Chain-specific cache files
$config = getChainConfig();
$chainSuffix = $config['chain'] === 'dilv' ? '-dilv' : '';
$cacheFile = __DIR__ . "/../cache/stats{$chainSuffix}.json";
if (file_exists($cacheFile)) {
    $cacheAge = time() - filemtime($cacheFile);
    if ($cacheAge < 10) {
        $cached = file_get_contents($cacheFile);
        if ($cached !== false) {
            $data = json_decode($cached, true);
            if ($data !== null) {
                $data["cached"] = true;
                $data["cacheAge"] = $cacheAge;
                sendJSON($data);
            }
        }
    }
}

// Gather stats from multiple RPC calls
$blockchainInfo = dilithionRPC("getblockchaininfo");
$connectionCount = dilithionRPC("getconnectioncount");
$chainTips = dilithionRPC("getchaintips");

$networkHashps = null;

if ($blockchainInfo === null) {
    sendError("Failed to connect to node.", 503);
}

$height = $blockchainInfo["blocks"] ?? 0;

// Calculate approximate supply based on block height
$supply = null;
$mikInfo = dilithionRPC("getmikdistribution");
if ($mikInfo !== null && isset($mikInfo["total_supply"])) {
    $supply = $mikInfo["total_supply"];
} else {
    $supply = $height * $config['reward'];
}

// DilV: add pre-fund (genesis) supply from chain reset
if ($config['chain'] === 'dilv') {
    $supply += 2681636.92;
}

// Calculate average block time from last 10 blocks
$avgBlockTime = null;
if ($height >= 10) {
    $tipHashResult = dilithionRPC("getblockhash", ["height" => $height]);
    $oldHashResult = dilithionRPC("getblockhash", ["height" => $height - 10]);

    $tipHash = is_array($tipHashResult) ? ($tipHashResult["blockhash"] ?? null) : $tipHashResult;
    $oldHash = is_array($oldHashResult) ? ($oldHashResult["blockhash"] ?? null) : $oldHashResult;

    if ($tipHash !== null && $oldHash !== null) {
        $tipBlock = dilithionRPC("getblock", ["hash" => $tipHash, "verbosity" => 1]);
        $oldBlock = dilithionRPC("getblock", ["hash" => $oldHash, "verbosity" => 1]);

        if ($tipBlock !== null && $oldBlock !== null) {
            $timeDiff = ($tipBlock["time"] ?? 0) - ($oldBlock["time"] ?? 0);
            $avgBlockTime = $timeDiff / 10.0;
        }
    }
}

// Estimate network hashrate (RandomX only, not applicable for VDF)
$difficulty = $blockchainInfo["difficulty"] ?? 0;
if ($config['chain'] === 'dil' && $difficulty > 0 && $avgBlockTime !== null && $avgBlockTime > 0) {
    $networkHashps = $difficulty * 10922.667 / $avgBlockTime;
}

// Get holder count (cached separately for 60s - expensive UTXO scan)
$holders = null;
$holderCacheFile = __DIR__ . "/../cache/holders{$chainSuffix}.json";
$holderCacheValid = false;
if (file_exists($holderCacheFile)) {
    $holderCacheAge = time() - filemtime($holderCacheFile);
    if ($holderCacheAge < 60) {
        $holderCached = file_get_contents($holderCacheFile);
        if ($holderCached !== false) {
            $holderData = json_decode($holderCached, true);
            if ($holderData !== null) {
                $holders = $holderData["holders"] ?? null;
                $holderCacheValid = true;
            }
        }
    }
}
if (!$holderCacheValid) {
    $holderInfo = dilithionRPC("getholdercount");
    if ($holderInfo !== null && isset($holderInfo["holders"])) {
        $holders = $holderInfo["holders"];
        @file_put_contents($holderCacheFile, json_encode($holderInfo));
    }
}

$result = [
    "blocks" => $height,
    "difficulty" => $difficulty,
    "networkhashps" => $networkHashps,
    "supply" => $supply,
    "connections" => $connectionCount,
    "avgBlockTime" => $avgBlockTime,
    "holders" => $holders,
    "chain" => $blockchainInfo["chain"] ?? "main",
    "chainTips" => $chainTips ?? [],
    "bestblockhash" => $blockchainInfo["bestblockhash"] ?? null,
    "unit" => $config['unit'],
    "chainName" => $config['name'],
    "consensusType" => $config['chain'] === 'dilv' ? 'VDF' : 'RandomX',
];

// Write cache
@file_put_contents($cacheFile, json_encode($result));

sendJSON($result);
