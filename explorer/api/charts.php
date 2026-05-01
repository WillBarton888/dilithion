<?php
/**
 * Block Explorer API - Time-Series Charts
 *
 * Samples ~60 blocks across the requested range and computes per-metric
 * values. Cached 5 minutes per (chain, metric, range) tuple.
 *
 *   /api/charts.php?chain=dil&metric=hashrate&range=24h
 *   /api/charts.php?chain=dilv&metric=blocktime&range=7d
 *
 * Supported metrics:
 *   - hashrate    : difficulty * 2^32 / windowed_blocktime
 *   - difficulty  : block.difficulty (float)
 *   - blocktime   : average seconds-per-block over the sample stride
 *   - rewards     : coinbase output sum at the sample (subsidy + fees)
 *   - fees        : coinbase total minus subsidy at that height
 *
 * Not yet supported (returns 400 with notice):
 *   - peers       : no historical peer-count snapshots are recorded today
 *
 * Supported ranges:
 *   - 1h, 6h, 24h, 7d, 30d
 *
 * Response shape:
 *   {
 *     "chain": "dil",
 *     "metric": "hashrate",
 *     "range": "24h",
 *     "rangeSeconds": 86400,
 *     "sampleCount": 60,
 *     "sampleStrideBlocks": 24,
 *     "points": [{ "t": 1777190000, "v": 767683 }, ...]
 *   }
 */

require_once __DIR__ . "/rpc.php";

$config = getChainConfig();
$chain  = $config['chain'];

$metric = strtolower($_GET['metric'] ?? 'hashrate');
$range  = strtolower($_GET['range']  ?? '24h');

$validMetrics = ['hashrate', 'difficulty', 'blocktime', 'rewards', 'fees', 'peers'];
if (!in_array($metric, $validMetrics, true)) {
    sendError("Unsupported metric '{$metric}'. Supported: " . implode(', ', $validMetrics) . '.', 400);
}

if ($metric === 'peers') {
    sendError(
        "metric=peers is not yet supported. Historical peer-count snapshots " .
        "are not currently recorded; this requires a separate snapshot daemon. " .
        "Use /api/nodes.php for the current peer count per seed.",
        400
    );
}

$rangeMap = [
    '1h'  => 3600,
    '6h'  => 21600,
    '12h' => 43200,
    '24h' => 86400,
    '7d'  => 604800,
    '30d' => 2592000,
];
if (!isset($rangeMap[$range])) {
    sendError("Unsupported range '{$range}'. Supported: " . implode(', ', array_keys($rangeMap)) . '.', 400);
}
$rangeSeconds = $rangeMap[$range];

// Block target for the chain (same logic as miners.php).
$blockTargetSeconds = ($chain === 'dilv') ? 12 : 60;

// Aim for ~60 points across the range. Cap stride so we don't waste samples
// on very short ranges where #blocks < 60.
$rangeBlocks = max(1, (int)ceil($rangeSeconds / $blockTargetSeconds));
$sampleCount = min(60, $rangeBlocks);
$sampleStride = max(1, (int)floor($rangeBlocks / $sampleCount));
$sampleCount = (int)floor($rangeBlocks / $sampleStride);  // re-derive after stride floor
if ($sampleCount < 2) $sampleCount = 2;

// Cache lookup
$cacheKey  = "charts-{$chain}-{$metric}-{$range}";
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

// Tip
$tipHeight = dilithionRPC('getblockcount');
if ($tipHeight === null) {
    sendError('Failed to query node for tip height.', 503);
}
$tipHeight = (int)$tipHeight;

// Halving subsidy helper (Bitcoin-style 210k epoch).
$baseReward = $config['reward'];
$subsidyAt = function (int $height) use ($baseReward): float {
    $epoch = intdiv($height, 210000);
    if ($epoch >= 64) return 0.0;
    return (float)($baseReward / (1 << $epoch));
};

// Difficulty helper (matches src/api/cached_stats.cpp:113-125 math).
// max target = 0x1f060000 for Dilithion.
$difficultyFromBits = function ($bits): float {
    if (!$bits || !is_string($bits)) return 0.0;
    $cur = hexdec($bits);
    if ($cur === 0) return 0.0;
    $maxBits = 0x1f060000;
    $maxExp = $maxBits >> 24;
    $maxMantissa = $maxBits & 0x7fffff;
    $curExp = $cur >> 24;
    $curMantissa = $cur & 0x7fffff;
    if ($curMantissa === 0) return 0.0;
    return (float)(($maxMantissa / $curMantissa) * pow(256.0, $maxExp - $curExp));
};

// Walk sample heights from oldest -> newest, fetching each block once.
$points = [];
$prevSample = null;

// Build height list (ascending order so we have prev->current deltas).
$heights = [];
$startHeight = max(1, $tipHeight - ($sampleCount - 1) * $sampleStride);
for ($h = $startHeight; $h <= $tipHeight; $h += $sampleStride) {
    $heights[] = $h;
}
// Always include the tip as the final point.
if (end($heights) !== $tipHeight) {
    $heights[] = $tipHeight;
}

// We also need ONE sample below startHeight to compute blocktime/hashrate
// for the first point. Add it if possible.
$priorHeight = $startHeight - $sampleStride;
if ($priorHeight >= 1) {
    array_unshift($heights, $priorHeight);
}

// For rewards/fees we need verbosity=2; for difficulty/blocktime/hashrate
// verbosity=1 is enough.
$needsVouts = in_array($metric, ['rewards', 'fees'], true);
$verbosity  = $needsVouts ? 2 : 1;

foreach ($heights as $i => $sampleHeight) {
    usleep(5000);
    $hashRes = dilithionRPC('getblockhash', ['height' => $sampleHeight]);
    $hash = is_array($hashRes) ? ($hashRes['blockhash'] ?? null) : $hashRes;
    if ($hash === null) continue;

    $block = dilithionRPC('getblock', ['hash' => $hash, 'verbosity' => $verbosity]);
    if ($block === null) continue;

    $blockTime = (int)($block['time'] ?? 0);
    $blockHeight = (int)($block['height'] ?? $sampleHeight);

    $value = null;

    if ($metric === 'difficulty') {
        // getblock typically returns 'difficulty' as a float.
        if (isset($block['difficulty'])) {
            $value = (float)$block['difficulty'];
        } elseif (isset($block['bits'])) {
            $value = $difficultyFromBits($block['bits']);
        }
    } elseif ($metric === 'blocktime' || $metric === 'hashrate') {
        // Need delta from previous sample.
        if ($prevSample !== null) {
            $deltaSec    = $blockTime - $prevSample['time'];
            $deltaBlocks = $blockHeight - $prevSample['height'];
            if ($deltaBlocks > 0 && $deltaSec > 0) {
                $avgBlockTime = $deltaSec / $deltaBlocks;
                if ($metric === 'blocktime') {
                    $value = round($avgBlockTime, 2);
                } else {
                    // hashrate = difficulty * 2^32 / blocktime
                    $diff = isset($block['difficulty']) ? (float)$block['difficulty'] : (
                        isset($block['bits']) ? $difficultyFromBits($block['bits']) : 0.0
                    );
                    if ($diff > 0) {
                        $value = (int)round($diff * pow(2, 32) / $avgBlockTime);
                    }
                }
            }
        }
    } elseif ($metric === 'rewards' || $metric === 'fees') {
        // Coinbase total = vout sum of the first tx. vouts are in subunits (ions for DIL,
        // volts for DilV); divide by 1e8 to express as whole coins.
        $coinbaseTotalSubunits = 0.0;
        if (isset($block['tx']) && is_array($block['tx']) && count($block['tx']) > 0) {
            $cb = $block['tx'][0];
            if (isset($cb['vout']) && is_array($cb['vout'])) {
                foreach ($cb['vout'] as $vout) {
                    $coinbaseTotalSubunits += (float)($vout['value'] ?? 0);
                }
            }
        }
        $coinbaseTotalDIL = $coinbaseTotalSubunits / 100000000.0;
        if ($metric === 'rewards') {
            $value = round($coinbaseTotalDIL, 8);
        } else {
            // fees = coinbase total - subsidy at this height (both in DIL)
            $subsidy = $subsidyAt($blockHeight);
            $value   = round(max(0.0, $coinbaseTotalDIL - $subsidy), 8);
        }
    }

    // Skip the priming sample (the prior block we added before startHeight).
    $isPrimingSample = ($i === 0 && $priorHeight >= 1 && $sampleHeight === $priorHeight);
    if (!$isPrimingSample && $value !== null) {
        $points[] = ['t' => $blockTime, 'v' => $value];
    }

    $prevSample = ['time' => $blockTime, 'height' => $blockHeight];
}

$response = [
    'chain'              => $chain,
    'metric'             => $metric,
    'range'              => $range,
    'rangeSeconds'       => $rangeSeconds,
    'sampleCount'        => count($points),
    'sampleStrideBlocks' => $sampleStride,
    'tipHeight'          => $tipHeight,
    'points'             => $points,
    'updatedAt'          => time(),
    'cached'             => false,
];

$cacheDir = dirname($cacheFile);
if (!is_dir($cacheDir)) {
    @mkdir($cacheDir, 0755, true);
}
@file_put_contents($cacheFile, json_encode($response));

sendJSON($response);
