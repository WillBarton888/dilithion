<?php
/**
 * One-shot warm-up: populate total_tx cache for a chain.
 *
 * Usage (from /var/www/explorer/api/):
 *   php warmup_total_tx.php dil
 *   php warmup_total_tx.php dilv
 *
 * Scans every block from 0 to tip, writes the cache file that
 * metrics_helpers.php::getTotalTransactions() will read on subsequent
 * requests. Run ONCE before deploying the extended stats.php, so the
 * first user request doesn't get a partially-warmed counter.
 */

if (php_sapi_name() !== 'cli') {
    echo "Run from CLI only\n";
    exit(1);
}

$chain = $argv[1] ?? 'dil';
if (!in_array($chain, ['dil', 'dilv'], true)) {
    fwrite(STDERR, "Usage: php warmup_total_tx.php [dil|dilv]\n");
    exit(1);
}

// Simulate the query-string chain selection so rpc.php picks the right port
$_GET['chain'] = $chain;
require_once __DIR__ . '/rpc.php';

$cacheDir  = __DIR__ . '/../cache';
$cacheFile = "{$cacheDir}/total_tx-{$chain}.json";
if (!is_dir($cacheDir)) mkdir($cacheDir, 0775, true);

$info = dilithionRPC('getblockchaininfo');
if (!$info || !isset($info['blocks'])) {
    fwrite(STDERR, "RPC failed for chain={$chain}\n");
    exit(2);
}
$tip = (int)$info['blocks'];
echo "[{$chain}] tip height: {$tip}\n";

$startTs = microtime(true);
$total   = 0;
$batch   = 500; // progress print cadence

for ($h = 0; $h <= $tip; $h++) {
    $hashResp = dilithionRPC('getblockhash', ['height' => $h]);
    $hash = is_array($hashResp) ? ($hashResp['blockhash'] ?? null) : $hashResp;
    if (!$hash) { fwrite(STDERR, "  skip h={$h} (no hash)\n"); continue; }

    $block = dilithionRPC('getblock', ['hash' => $hash, 'verbosity' => 0]);
    if (!$block) { fwrite(STDERR, "  skip h={$h} (no block)\n"); continue; }

    $total += (int)($block['tx_count'] ?? 0);

    if ($h > 0 && $h % $batch === 0) {
        $rate = $h / max(1, microtime(true) - $startTs);
        $eta  = ($tip - $h) / max(1, $rate);
        printf("  h=%d / %d  total_txs=%d  rate=%.0f blk/s  eta=%ds\n",
               $h, $tip, $total, $rate, (int)$eta);
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
chmod($cacheFile, 0664);

$elapsed = microtime(true) - $startTs;
printf("[%s] DONE: %d blocks scanned, %d total txs, %.1fs\n",
       $chain, $tip + 1, $total, $elapsed);
printf("[%s] Cache written: %s\n", $chain, $cacheFile);
