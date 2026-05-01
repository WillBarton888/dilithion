<?php
/**
 * Block Explorer API - Miners Leaderboard
 *
 * Walks the last N blocks of the chain, aggregates per-MIK statistics from
 * coinbase data: block count, share, total rewards, payout addresses, last
 * seen, plus optional human label.
 *
 *   /api/miners.php?chain=dil&window=24h
 *   /api/miners.php?chain=dilv&window=1h
 *
 * Window accepts: 1h, 6h, 24h, 7d, 30d, OR a literal seconds value.
 * Capped at 5000 blocks to bound RPC cost on cold cache.
 *
 * Cache TTL: 5 minutes (a 1440-block walk is ~1440 RPCs).
 *
 * Response shape (camelCase, new endpoint convention):
 *   {
 *     "chain": "dil",
 *     "windowSeconds": 86400,
 *     "windowBlocks": 1440,
 *     "blocksWalked": 1440,
 *     "tipHeight": 46684,
 *     "uniqueMiners": 23,
 *     "miners": [
 *       {
 *         "mik": "<20-byte hex>",
 *         "address": "D...",
 *         "label": "Dev Fund" | null,
 *         "blocksFound": 142,
 *         "share": 0.0986,
 *         "rewards": 7100.0,
 *         "lastSeen": 1777194000,
 *         "firstSeen": 1777107600,
 *         "blocksInWindow": 142
 *       }
 *     ]
 *   }
 */

require_once __DIR__ . "/rpc.php";

$config = getChainConfig();
$chain  = $config['chain'];
$unit   = $config['unit'];

// Block target per chain. DIL=60s (whitepaper), DilV=12s.
$blockTargetSeconds = ($chain === 'dilv') ? 12 : 60;

// Parse window
$windowParam = strtolower($_GET['window'] ?? '24h');
$windowMap = [
    '1h'   => 3600,
    '6h'   => 21600,
    '12h'  => 43200,
    '24h'  => 86400,
    '7d'   => 604800,
    '30d'  => 2592000,
];
if (isset($windowMap[$windowParam])) {
    $windowSeconds = $windowMap[$windowParam];
} elseif (ctype_digit($windowParam)) {
    $windowSeconds = max(60, min(2592000, (int)$windowParam));
} else {
    $windowSeconds = 86400;
}

// Convert seconds to blocks, cap at 5000
$windowBlocks = (int)ceil($windowSeconds / $blockTargetSeconds);
$windowBlocks = max(1, min(5000, $windowBlocks));

// Cache
$cacheKey  = "miners-{$chain}-{$windowBlocks}";
$cacheFile = __DIR__ . "/../cache/{$cacheKey}.json";
if (file_exists($cacheFile)) {
    $cacheAge = time() - filemtime($cacheFile);
    if ($cacheAge < 300) {  // 5 min
        $cached = json_decode(@file_get_contents($cacheFile), true);
        if (is_array($cached)) {
            $cached['cached']   = true;
            $cached['cacheAge'] = $cacheAge;
            sendJSON($cached);
        }
    }
}

// Get tip
$tipHeight = dilithionRPC('getblockcount');
if ($tipHeight === null) {
    sendError('Failed to query node for tip height.', 503);
}
$tipHeight = (int)$tipHeight;

// Same address labels used by holders.php
$labels = [
    'DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq' => 'Dev Fund',
    'DTHGN3XiZ9LRxHVPUWMumX8B9q6B4BuPdp' => 'Bridge',
    'DNaTbwZgm6x23zf4DnJm4vjEG2qGc6cinx' => 'Bridge',
];

// Get starting hash and walk backwards via previousblockhash
$tipHashRes = dilithionRPC('getblockhash', ['height' => $tipHeight]);
$currentHash = is_array($tipHashRes) ? ($tipHashRes['blockhash'] ?? null) : $tipHashRes;
if ($currentHash === null) {
    sendError('Failed to get tip block hash.', 503);
}

$miners = [];      // mikHex => aggregated record
$blocksWalked = 0;
$startHeight = max(1, $tipHeight - $windowBlocks + 1);

for ($i = 0; $i < $windowBlocks && $currentHash !== null; $i++) {
    usleep(5000);  // 5ms between calls to avoid socket exhaustion
    $block = dilithionRPC('getblock', ['hash' => $currentHash, 'verbosity' => 2]);
    if ($block === null) break;

    $blockHeight = $block['height'] ?? -1;
    if ($blockHeight < $startHeight) break;

    $blockTime   = $block['time']   ?? 0;
    $mikHex      = $block['mik']    ?? null;

    // Extract reward + miner address from coinbase (vout sum, first-output address)
    // vout values are in subunits (ions for DIL, volts for DilV); divide by 1e8 for whole coins.
    $rewardSubunits = 0.0;
    $minerAddr  = '';
    if (isset($block['tx']) && is_array($block['tx']) && count($block['tx']) > 0) {
        $coinbase = $block['tx'][0];
        if (isset($coinbase['vout']) && is_array($coinbase['vout'])) {
            foreach ($coinbase['vout'] as $vout) {
                $rewardSubunits += (float)($vout['value'] ?? 0);
                if ($minerAddr === '' && !empty($vout['address'])) {
                    $minerAddr = $vout['address'];
                }
            }
        }
    }
    $reward = $rewardSubunits / 100000000.0;

    if ($mikHex !== null && $mikHex !== '') {
        if (!isset($miners[$mikHex])) {
            $miners[$mikHex] = [
                'mik'         => $mikHex,
                'address'     => $minerAddr,
                'label'       => $labels[$minerAddr] ?? null,
                'blocksFound' => 0,
                'rewards'     => 0.0,
                'firstSeen'   => $blockTime,
                'lastSeen'    => $blockTime,
            ];
        }
        $miners[$mikHex]['blocksFound']++;
        $miners[$mikHex]['rewards'] += $reward;
        // We're walking backwards so the first sighting is the latest.
        if ($miners[$mikHex]['lastSeen'] < $blockTime) {
            $miners[$mikHex]['lastSeen'] = $blockTime;
        }
        if ($miners[$mikHex]['firstSeen'] > $blockTime || $miners[$mikHex]['firstSeen'] === 0) {
            $miners[$mikHex]['firstSeen'] = $blockTime;
        }
        // Late-binding: if we got an address this block but didn't earlier
        if ($miners[$mikHex]['address'] === '' && $minerAddr !== '') {
            $miners[$mikHex]['address'] = $minerAddr;
            $miners[$mikHex]['label']   = $labels[$minerAddr] ?? null;
        }
    }

    $blocksWalked++;
    $currentHash = $block['previousblockhash'] ?? null;
}

// Compute share, attach window-equiv field, sort by blocksFound desc
$totalAttributed = array_sum(array_column($miners, 'blocksFound'));
foreach ($miners as &$m) {
    $m['share']           = $totalAttributed > 0 ? ($m['blocksFound'] / $totalAttributed) : 0.0;
    $m['blocksInWindow']  = $m['blocksFound'];  // alias for v0 spec
    // Round rewards to 8 decimals
    $m['rewards']         = round($m['rewards'], 8);
    $m['share']           = round($m['share'], 6);
}
unset($m);

$minersList = array_values($miners);
usort($minersList, function ($a, $b) {
    return $b['blocksFound'] <=> $a['blocksFound'];
});

$response = [
    'chain'         => $chain,
    'unit'          => $unit,
    'windowSeconds' => $windowSeconds,
    'windowBlocks'  => $windowBlocks,
    'blocksWalked'  => $blocksWalked,
    'tipHeight'     => $tipHeight,
    'startHeight'   => $startHeight,
    'uniqueMiners'  => count($minersList),
    'miners'        => $minersList,
    'updatedAt'     => time(),
    'cached'        => false,
];

// Persist to cache
$cacheDir = dirname($cacheFile);
if (!is_dir($cacheDir)) {
    @mkdir($cacheDir, 0755, true);
}
@file_put_contents($cacheFile, json_encode($response));

sendJSON($response);
