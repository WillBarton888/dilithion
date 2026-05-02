<?php
/**
 * One-shot warm-up: populate total_tx cache for a chain.
 *
 * Usage:
 *   sudo -u www-data php warmup_total_tx.php dil [--throttle-ms=50]
 *   sudo -u www-data php warmup_total_tx.php dilv [--throttle-ms=50]
 *
 * Run as www-data so cache files are writable by PHP-FPM later.
 *
 * Scans every block from 0 to tip, writes the cache file that
 * metrics_helpers.php::getTotalTransactions() will read on subsequent
 * requests.
 *
 * --throttle-ms (default 50): sleep this many ms between block fetches so
 * the warmup doesn't saturate the local node and break live explorer
 * traffic. 50ms ≈ 20 blk/s, ~40 min for 49k blocks. Set to 0 only when
 * the explorer is offline / no live load.
 */

if (php_sapi_name() !== 'cli') {
    echo "Run from CLI only\n";
    exit(1);
}

$chain = $argv[1] ?? 'dil';
if (!in_array($chain, ['dil', 'dilv'], true)) {
    fwrite(STDERR, "Usage: php warmup_total_tx.php [dil|dilv] [--throttle-ms=N]\n");
    exit(1);
}

$throttleMs = 50;
foreach (array_slice($argv, 2) as $arg) {
    if (preg_match('/^--throttle-ms=(\d+)$/', $arg, $m)) {
        $throttleMs = (int)$m[1];
    }
}
$throttleUs = $throttleMs * 1000;

// Simulate the query-string chain selection so rpc.php picks the right port
$_GET['chain'] = $chain;
require_once __DIR__ . '/rpc.php';
require_once __DIR__ . '/metrics_helpers.php';

$cacheDir  = _explorerCacheDir();
$cacheFile = "{$cacheDir}/total_tx-{$chain}.json";

$info = dilithionRPC('getblockchaininfo');
if (!$info || !isset($info['blocks'])) {
    fwrite(STDERR, "RPC failed for chain={$chain}\n");
    exit(2);
}
$tip = (int)$info['blocks'];
echo "[{$chain}] tip height: {$tip}, throttle: {$throttleMs}ms/block\n";

// Resume from existing partial cache if present.
$startHeight = 0;
$total       = 0;
if (file_exists($cacheFile)) {
    $loaded = json_decode(@file_get_contents($cacheFile), true);
    if (is_array($loaded) && isset($loaded['lastHeight'], $loaded['totalTxs']) && $loaded['lastHeight'] >= 0) {
        $startHeight = (int)$loaded['lastHeight'] + 1;
        $total       = (int)$loaded['totalTxs'];
        echo "[{$chain}] resuming from h={$startHeight} (totalTxs={$total})\n";
    }
}

$startTs = microtime(true);
$batch   = 500; // progress print cadence

for ($h = $startHeight; $h <= $tip; $h++) {
    $hashResp = dilithionRPC('getblockhash', ['height' => $h]);
    $hash = is_array($hashResp) ? ($hashResp['blockhash'] ?? null) : $hashResp;
    if (!$hash) { fwrite(STDERR, "  skip h={$h} (no hash)\n"); continue; }

    $block = dilithionRPC('getblock', ['hash' => $hash, 'verbosity' => 0]);
    if (!$block) { fwrite(STDERR, "  skip h={$h} (no block)\n"); continue; }

    $total += (int)($block['tx_count'] ?? 0);

    if ($throttleUs > 0) usleep($throttleUs);

    if ($h > $startHeight && ($h - $startHeight) % $batch === 0) {
        $elapsed = max(1, microtime(true) - $startTs);
        $rate    = ($h - $startHeight) / $elapsed;
        $eta     = ($tip - $h) / max(0.1, $rate);
        printf("  h=%d / %d  total_txs=%d  rate=%.1f blk/s  eta=%ds\n",
               $h, $tip, $total, $rate, (int)$eta);
        // Periodic checkpoint write so a crash doesn't lose progress.
        @file_put_contents($cacheFile, json_encode([
            'lastHeight' => $h,
            'totalTxs'   => $total,
            'tipHeight'  => $tip,
            'warmedUp'   => false,
            'updatedAt'  => time(),
        ]));
    }
}

$state = [
    'lastHeight' => $tip,
    'totalTxs'   => $total,
    'tipHeight'  => $tip,
    'warmedUp'   => true,
    'updatedAt'  => time(),
];
file_put_contents($cacheFile, json_encode($state));
@chmod($cacheFile, 0664);

$elapsed = microtime(true) - $startTs;
printf("[%s] DONE: scanned h=%d..%d, %d total txs, %.1fs\n",
       $chain, $startHeight, $tip, $total, $elapsed);
printf("[%s] Cache written: %s\n", $chain, $cacheFile);
