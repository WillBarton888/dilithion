<?php
/**
 * Block Explorer API - Top Holders Endpoint
 *
 * Returns top holder addresses ranked by balance.
 * Cached for 60 seconds (expensive UTXO scan).
 *
 *   /api/holders.php?chain=dil           → top 100 holders (default)
 *   /api/holders.php?chain=dil&count=50  → top 50 holders
 */

require_once __DIR__ . "/rpc.php";

$config = getChainConfig();
$chainSuffix = $config['chain'] === 'dilv' ? '-dilv' : '';

$count = min(max((int)($_GET['count'] ?? 100), 1), 500);

$cacheFile = __DIR__ . "/../cache/topholders{$chainSuffix}-{$count}.json";

// Check cache (60s TTL - expensive query)
if (file_exists($cacheFile)) {
    $cacheAge = time() - filemtime($cacheFile);
    if ($cacheAge < 60) {
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

// Query node
$result = dilithionRPC("gettopholders", ["count" => $count]);

if ($result === null) {
    sendError("Failed to query top holders. Node may be unavailable.", 503);
}

// Calculate supply for percentage
$supply = ($result["holders"] ?? 0) > 0 ? 0 : 0;
$blockchainInfo = dilithionRPC("getblockchaininfo");
if ($blockchainInfo !== null) {
    $height = $blockchainInfo["blocks"] ?? 0;
    $supply = $height * $config['reward'];
}

$response = [
    "holders" => $result["holders"] ?? 0,
    "utxos" => $result["utxos"] ?? 0,
    "supply" => $supply,
    "unit" => $config['unit'],
    "chain" => $config['chain'],
    "top" => $result["top"] ?? [],
    "updated_at" => time(),
];

// Write cache
@file_put_contents($cacheFile, json_encode($response));

sendJSON($response);
