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
// Include pre-funded supply from genesis (chain reset balances)
$prefundSupply = $config['chain'] === 'dilv' ? 2610191.92 : 0;  // DilV reset pre-fund total
$blockchainInfo = dilithionRPC("getblockchaininfo");
$height = 0;
if ($blockchainInfo !== null) {
    $height = $blockchainInfo["blocks"] ?? 0;
}
$supply = ($height * $config['reward']) + $prefundSupply;

// Known address labels
$labels = [
    "DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq" => "Dev Fund",
    "DTHGN3XiZ9LRxHVPUWMumX8B9q6B4BuPdp" => "Bridge",
    "DNaTbwZgm6x23zf4DnJm4vjEG2qGc6cinx" => "Bridge",
];

// Add labels to top holders
$top = $result["top"] ?? [];
foreach ($top as &$holder) {
    $addr = $holder["address"] ?? "";
    if (isset($labels[$addr])) {
        $holder["label"] = $labels[$addr];
    }
}
unset($holder);

$response = [
    "holders" => $result["holders"] ?? 0,
    "utxos" => $result["utxos"] ?? 0,
    "supply" => $supply,
    "unit" => $config['unit'],
    "chain" => $config['chain'],
    "top" => $top,
    "updated_at" => time(),
];

// Write cache
@file_put_contents($cacheFile, json_encode($response));

sendJSON($response);
