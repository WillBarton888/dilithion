<?php
/**
 * Block Explorer API — Financial Data
 *
 * Returns: price USD, market cap, liquidity, 24h volume, 24h price change.
 *
 * Data source: dexscreener.com (free public API). They aggregate Aerodrome
 * pool data on Base. One call per token gives us everything we need.
 *
 * This is a separate endpoint from stats.php because:
 *   - external dependency (dexscreener can fail while the chain is fine)
 *   - different cache TTL (prices stale for 2 min is fine; chain stats need 30 s)
 *   - rate limits on dexscreener's side, not ours
 *
 * Usage: /api/financial.php?chain=dil|dilv
 */

require_once __DIR__ . "/rpc.php";

$config = getChainConfig();
$chain  = $config['chain'];

// Wrapped token contract addresses on Base mainnet
const WDIL_BASE  = '0x30629128d1d3524F1A01B9c385FbE84fDCbD36C2';
const WDILV_BASE = '0xF162F6B432FeeD73458D4653ef8E74Ba014403E8';
$tokenAddr = $chain === 'dilv' ? WDILV_BASE : WDIL_BASE;

// 1 min cache — prices don't move that fast and dexscreener has rate limits.
$cacheFile = __DIR__ . "/../cache/financial-{$chain}.json";
if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 60) {
    $cached = @file_get_contents($cacheFile);
    if ($cached !== false) {
        $data = json_decode($cached, true);
        if ($data !== null) {
            $data['cached']    = true;
            $data['cacheAge']  = time() - filemtime($cacheFile);
            sendJSON($data);
        }
    }
}

// Fetch from dexscreener
$url = "https://api.dexscreener.com/latest/dex/tokens/{$tokenAddr}";
$ch  = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 5,
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_HTTPHEADER     => ['Accept: application/json'],
    CURLOPT_USERAGENT      => 'dilithion-explorer/1.0',
]);
$resp = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// On failure, return null fields rather than 5xx — website should show "—"
// rather than breaking when dexscreener is down.
$result = [
    'chain'          => $chain,
    'unit'           => $config['unit'],
    'priceUSD'       => null,
    'priceNative'    => null,  // token/ETH for Base pairs
    'marketCapUSD'   => null,
    'liquidityUSD'   => null,
    'volume24hUSD'   => null,
    'priceChange24h' => null,
    'pairAddress'    => null,
    'dex'            => null,
    'source'         => 'dexscreener',
    'lastUpdated'    => time(),
    'error'          => null,
];

if ($code !== 200 || !$resp) {
    $result['error'] = "dexscreener HTTP {$code}";
    @file_put_contents($cacheFile, json_encode($result));
    sendJSON($result);
}

$parsed = json_decode($resp, true);
$pairs  = $parsed['pairs'] ?? [];

if (empty($pairs)) {
    $result['error'] = 'no pairs found';
    @file_put_contents($cacheFile, json_encode($result));
    sendJSON($result);
}

// Dexscreener returns multiple pairs (USDC, WETH, wDIL/wDilV). Pick the one
// with the highest USD liquidity — that's the most meaningful price signal.
usort($pairs, function ($a, $b) {
    $la = $a['liquidity']['usd'] ?? 0;
    $lb = $b['liquidity']['usd'] ?? 0;
    return $lb <=> $la;
});
$top = $pairs[0];

$result['priceUSD']       = isset($top['priceUsd'])    ? (float)$top['priceUsd']    : null;
$result['priceNative']    = isset($top['priceNative']) ? (float)$top['priceNative'] : null;
$result['marketCapUSD']   = $top['marketCap']          ?? ($top['fdv'] ?? null);
$result['liquidityUSD']   = $top['liquidity']['usd']   ?? null;
$result['volume24hUSD']   = $top['volume']['h24']      ?? null;
$result['priceChange24h'] = $top['priceChange']['h24'] ?? null;
$result['pairAddress']    = $top['pairAddress']        ?? null;
$result['dex']            = $top['dexId']              ?? null;

@file_put_contents($cacheFile, json_encode($result));
sendJSON($result);
