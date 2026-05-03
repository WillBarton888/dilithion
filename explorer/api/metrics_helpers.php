<?php
/**
 * Shared helpers for extended /api/stats.php metrics:
 *   - active miners (distinct MIKs in last-N blocks)
 *   - nodes online (unique peers across 4 seeds, deduped by addr)
 *   - total transactions (incremental per-chain cache)
 *
 * Each helper has its own cache TTL tuned to how expensive the computation is
 * and how fast the underlying data actually changes.
 *
 * Single-flight: each helper takes a non-blocking flock on a sibling .lock
 * file before the heavy path. If contended, the caller returns whatever cache
 * exists (even if stale). Without this, every TTL expiry can stampede 100
 * PHP-FPM workers into the same RPC walk, self-DOS the local node, and turn
 * a 10s call into a 60s call. (Lesson from the 2026-05-02 explorer outage.)
 */

require_once __DIR__ . "/rpc.php";

// Active window sizes (blocks). DIL ≈ 24h; DilV ≈ 2.5h.
// Aligned with src/core/chainparams.cpp vdfCooldownActiveWindow.
const ACTIVE_WINDOW_DIL  = 360;
const ACTIVE_WINDOW_DILV = 200;

const SEED_NODES = [
    ['138.197.68.128', '127.0.0.1'],      // NYC (local)
    ['167.172.56.119', '167.172.56.119'], // London
    ['165.22.103.114', '165.22.103.114'], // Singapore
    ['134.199.159.83', '134.199.159.83'], // Sydney
];

// Cache dir lives at explorer/cache (sibling of api/). PHP-FPM (www-data)
// must be able to write here. Bootstrap on first call so a fresh deploy
// doesn't need a manual mkdir.
//
// IMPORTANT operator note: if the cache dir already exists owned by root
// (e.g. created by a manual `mkdir` or a one-off root-run script), this
// function does NOT chown it. www-data will fail _acquireSingleFlight()
// silently (fopen 'c' returns false), every miss falls into the contended
// path, and the explorer appears to flap. Fix: `chown -R www-data:www-data
// /root/dilithion/explorer/cache/`. Lesson from the 2026-05-03 explorer
// flap incident.
function _explorerCacheDir(): string {
    $dir = __DIR__ . "/../cache";
    if (!is_dir($dir)) @mkdir($dir, 0775, true);
    return $dir;
}

/**
 * Acquire a non-blocking exclusive lock on $cacheFile.lock. Returns the file
 * handle on success (caller MUST release via _releaseSingleFlight) or null if
 * another worker holds it.
 */
function _acquireSingleFlight(string $cacheFile) {
    $fh = @fopen("{$cacheFile}.lock", 'c');
    if (!$fh) return null;
    if (!flock($fh, LOCK_EX | LOCK_NB)) {
        fclose($fh);
        return null;
    }
    return $fh;
}

function _releaseSingleFlight($fh): void {
    if ($fh) {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}

/**
 * Active miners: distinct MIKs that produced a block in the last N blocks.
 * TTL 10 min — value drifts slowly, no point recomputing every minute.
 */
function getActiveMinerCount(int $tipHeight, string $chain): ?int {
    $window    = $chain === 'dilv' ? ACTIVE_WINDOW_DILV : ACTIVE_WINDOW_DIL;
    $cacheFile = _explorerCacheDir() . "/active_miners-{$chain}.json";

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 600) {
        $c = json_decode(@file_get_contents($cacheFile), true);
        if (is_array($c) && isset($c['count'])) return (int)$c['count'];
    }

    $lock = _acquireSingleFlight($cacheFile);
    if (!$lock) {
        // Another worker is computing — serve whatever we have, even if stale.
        if (file_exists($cacheFile)) {
            $c = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($c) && isset($c['count'])) return (int)$c['count'];
        }
        return null;
    }

    try {
        // Re-check inside the lock; another worker may have just refreshed.
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 600) {
            $c = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($c) && isset($c['count'])) return (int)$c['count'];
        }

        $startHeight = max(0, $tipHeight - $window + 1);
        $miks = [];
        for ($h = $startHeight; $h <= $tipHeight; $h++) {
            $hashResp = dilithionRPC('getblockhash', ['height' => $h]);
            $hash = is_array($hashResp) ? ($hashResp['blockhash'] ?? null) : $hashResp;
            if (!$hash) continue;
            $block = dilithionRPC('getblock', ['hash' => $hash, 'verbosity' => 1]);
            if (!$block) continue;
            $mik = $block['mik'] ?? null;
            if ($mik) $miks[$mik] = true;
        }
        $count = count($miks);

        @file_put_contents($cacheFile, json_encode([
            'count'      => $count,
            'window'     => $window,
            'tipHeight'  => $tipHeight,
            'computedAt' => time(),
        ]));
        return $count;
    } finally {
        _releaseSingleFlight($lock);
    }
}

/**
 * Unique nodes visible to at least one seed.
 * Queries getpeerinfo on each of the 4 seeds in parallel, dedupes by addr.
 * TTL 5 min — slow remote seeds can make one call take 10s, and refreshing
 * every 30s under load self-DOSes everything.
 */
function getNodesOnline(int $rpcPort, string $chain): ?array {
    $cacheFile = _explorerCacheDir() . "/nodes_online-{$chain}.json";

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 300) {
        $c = json_decode(@file_get_contents($cacheFile), true);
        if (is_array($c) && isset($c['nodesOnline'])) return $c;
    }

    $lock = _acquireSingleFlight($cacheFile);
    if (!$lock) {
        if (file_exists($cacheFile)) {
            $c = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($c) && isset($c['nodesOnline'])) return $c;
        }
        return null;
    }

    try {
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 300) {
            $c = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($c) && isset($c['nodesOnline'])) return $c;
        }

        $multi = curl_multi_init();
        $handles = [];
        foreach (SEED_NODES as $i => [, $host]) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => "http://{$host}:{$rpcPort}/",
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => json_encode([
                    'jsonrpc' => '2.0', 'id' => 1,
                    'method'  => 'getpeerinfo', 'params' => [],
                ]),
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_HTTPHEADER     => [
                    'Content-Type: application/json',
                    'X-Dilithion-RPC: 1',
                    'Authorization: Basic ' . base64_encode('rpc:rpc'),
                ],
            ]);
            curl_multi_add_handle($multi, $ch);
            $handles[$i] = $ch;
        }
        $running = null;
        do {
            curl_multi_exec($multi, $running);
            curl_multi_select($multi, 0.1);
        } while ($running > 0);

        $peerSet         = [];
        $seedsResponding = 0;
        foreach ($handles as $ch) {
            $resp = curl_multi_getcontent($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);
            if ($code !== 200 || !$resp) continue;
            // The node sometimes emits malformed JSON in getpeerinfo when a peer's
            // subversion string contains unescaped quotes (e.g. "/Dilithion:"v3.8.3"/").
            // So we skip full JSON parsing and just regex-extract the addr fields —
            // that's all we need, and it's robust to the malformed subver case.
            // TODO: fix at the node level so getpeerinfo emits valid JSON.
            if (!preg_match_all('/"addr"\s*:\s*"([^"\s]+?)(?:[:\s].*?)?"/', $resp, $m)) continue;
            $seedsResponding++;
            foreach ($m[1] as $ipPort) {
                $ipOnly = preg_replace('/:\d+$/', '', $ipPort);
                if ($ipOnly !== '') $peerSet[$ipOnly] = true;
            }
        }
        curl_multi_close($multi);

        foreach (SEED_NODES as [$pubIp,]) {
            $peerSet[$pubIp] = true;
        }

        $result = [
            'nodesOnline'     => count($peerSet),
            'seedsResponding' => $seedsResponding,
            'seedsTotal'      => count(SEED_NODES),
            'computedAt'      => time(),
        ];
        @file_put_contents($cacheFile, json_encode($result));
        return $result;
    } finally {
        _releaseSingleFlight($lock);
    }
}

/**
 * Cumulative transaction count (sum of tx_count across all blocks on this chain).
 *
 * Incremental: cache stores {lastHeight, totalTxs}. Each call extends the walk
 * by up to TOTAL_TX_BATCH blocks. First-ever call(s) are slow until the chain
 * is fully walked; after warmedUp=true, subsequent calls only see new tip blocks.
 *
 * TTL 10 min, single-flight: no thundering herd, no redundant walks.
 */
const TOTAL_TX_BATCH = 5000;

function getTotalTransactions(int $tipHeight, string $chain): ?int {
    $cacheFile = _explorerCacheDir() . "/total_tx-{$chain}.json";

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 600) {
        $c = json_decode(@file_get_contents($cacheFile), true);
        if (is_array($c) && isset($c['totalTxs'])) return (int)$c['totalTxs'];
    }

    $lock = _acquireSingleFlight($cacheFile);
    if (!$lock) {
        if (file_exists($cacheFile)) {
            $c = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($c) && isset($c['totalTxs'])) return (int)$c['totalTxs'];
        }
        return null;
    }

    try {
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 600) {
            $c = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($c) && isset($c['totalTxs'])) return (int)$c['totalTxs'];
        }

        // Load existing incremental state (preserve progress across restarts).
        $state = ['lastHeight' => -1, 'totalTxs' => 0];
        if (file_exists($cacheFile)) {
            $loaded = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($loaded) && isset($loaded['lastHeight'], $loaded['totalTxs'])) {
                $state = $loaded;
            }
        }

        $startHeight = (int)$state['lastHeight'] + 1;
        $total       = (int)$state['totalTxs'];
        $endHeight   = min($tipHeight, $startHeight + TOTAL_TX_BATCH - 1);

        for ($h = $startHeight; $h <= $endHeight; $h++) {
            $hashResp = dilithionRPC('getblockhash', ['height' => $h]);
            $hash = is_array($hashResp) ? ($hashResp['blockhash'] ?? null) : $hashResp;
            if (!$hash) continue;
            $block = dilithionRPC('getblock', ['hash' => $hash, 'verbosity' => 0]);
            if (!$block) continue;
            $total += (int)($block['tx_count'] ?? 0);
        }

        @file_put_contents($cacheFile, json_encode([
            'lastHeight' => $endHeight,
            'totalTxs'   => $total,
            'tipHeight'  => $tipHeight,
            'warmedUp'   => ($endHeight >= $tipHeight),
            'updatedAt'  => time(),
        ]));
        return $total;
    } finally {
        _releaseSingleFlight($lock);
    }
}

/**
 * Blocks remaining until next halving. Both chains halve every 210,000 blocks.
 * Pure math — no RPC.
 */
function getNextHalving(int $tipHeight): array {
    $halvingInterval = 210000;
    $blocksRemaining = $halvingInterval - ($tipHeight % $halvingInterval);
    return [
        'blocksRemaining' => $blocksRemaining,
        'halvingInterval' => $halvingInterval,
        'nextHalvingAt'   => $tipHeight + $blocksRemaining,
    ];
}
