<?php
/**
 * Supply API Endpoint for CoinGecko / CoinMarketCap integration
 *
 * Returns supply data in formats expected by aggregators:
 *   /api/supply.php?chain=dil                → full JSON response
 *   /api/supply.php?chain=dil&q=circulating  → plain text circulating supply
 *   /api/supply.php?chain=dil&q=total        → plain text total supply
 *   /api/supply.php?chain=dil&q=max          → plain text max supply
 *
 * CoinGecko expects plain text numbers for automated polling.
 * Caches results for 30 seconds.
 */

require_once __DIR__ . "/rpc.php";

$config = getChainConfig();
$chainSuffix = $config['chain'] === 'dilv' ? '-dilv' : '';
$cacheFile = __DIR__ . "/../cache/supply{$chainSuffix}.json";

// Check cache (10s TTL)
$supplyData = null;
if (file_exists($cacheFile)) {
    $cacheAge = time() - filemtime($cacheFile);
    if ($cacheAge < 10) {
        $cached = file_get_contents($cacheFile);
        if ($cached !== false) {
            $supplyData = json_decode($cached, true);
        }
    }
}

// Build supply data if not cached
if ($supplyData === null) {
    $blockchainInfo = dilithionRPC("getblockchaininfo");
    if ($blockchainInfo === null) {
        sendError("Failed to connect to node.", 503);
    }

    $height = $blockchainInfo["blocks"] ?? 0;

    // Total mined supply
    $totalSupply = $height * $config['reward'];

    // Try to get more accurate supply from MIK distribution
    $mikInfo = dilithionRPC("getmikdistribution");
    if ($mikInfo !== null && isset($mikInfo["total_supply"])) {
        $totalSupply = $mikInfo["total_supply"];
    }

    // DilV: add pre-fund (genesis) supply — 2,681,636.92 DilV distributed at chain reset
    // These coins are circulating (held by existing holders from DIL→DilV migration)
    if ($config['chain'] === 'dilv') {
        $totalSupply += 2681636.92;
    }

    // Dev fund is 2% mining tax (1% dev fund + 1% dev reward)
    // These coins are circulating (paid to miners/dev addresses), so circulating = total
    $circulatingSupply = $totalSupply;

    // Max supply constants
    $maxSupply = $config['chain'] === 'dilv' ? 210000000 : 21000000;

    $supplyData = [
        "circulating_supply" => $circulatingSupply,
        "total_supply" => $totalSupply,
        "max_supply" => $maxSupply,
        "height" => $height,
        "block_reward" => $config['reward'],
        "chain" => $config['chain'],
        "unit" => $config['unit'],
        "updated_at" => time(),
    ];

    // Write cache
    @file_put_contents($cacheFile, json_encode($supplyData));
}

// Plain text mode for CoinGecko/CMC automated polling
$query = $_GET['q'] ?? null;
if ($query !== null) {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: text/plain');

    switch ($query) {
        case 'circulating':
            echo $supplyData['circulating_supply'];
            break;
        case 'total':
            echo $supplyData['total_supply'];
            break;
        case 'max':
            echo $supplyData['max_supply'];
            break;
        default:
            http_response_code(400);
            echo "Invalid query. Use ?q=circulating, ?q=total, or ?q=max";
    }
    exit;
}

// Full JSON response
sendJSON($supplyData);
