<?php
/**
 * Shared helpers for extended /api/stats.php metrics:
 *   - active miners (distinct MIKs in last-N blocks)
 *   - nodes online (unique peers across 4 seeds, deduped by addr)
 *   - total transactions (incremental per-chain cache)
 *
 * Each helper has its own cache TTL tuned to how expensive the computation is
 * and how fast the underlying data actually changes.
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

/**
 * Active miners: distinct MIKs that produced a block in the last N blocks.
 * Cache 2 min — expensive (N getblock calls) but doesn't change materially on
 * that timescale. Label on UI: "Active Miners (last 24h)" etc.
 */
function getActiveMinerCount(int $tipHeight, string $chain): ?int {
    $window   = $chain === 'dilv' ? ACTIVE_WINDOW_DILV : ACTIVE_WINDOW_DIL;
    $cacheKey = "active_miners-{$chain}";
    $cacheFile = __DIR__ . "/../cache/{$cacheKey}.json";

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 60) {
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
}

/**
 * Unique nodes visible to at least one seed.
 * Queries getpeerinfo on each of the 4 seeds in parallel, dedupes by addr.
 * Cache 30 s. Misses nodes that never touch a seed (minority) — phase 2 would
 * add a dedicated P2P crawler.
 */
function getNodesOnline(int $rpcPort, string $chain): ?array {
    $cacheKey = "nodes_online-{$chain}";
    $cacheFile = __DIR__ . "/../cache/{$cacheKey}.json";

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 10) {
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

    $peerSet          = [];
    $seedsResponding  = 0;
    foreach ($handles as $ch) {
        $resp = curl_multi_getcontent($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_multi_remove_handle($multi, $ch);
        curl_close($ch);
        if ($code !== 200 || !$resp) continue;

        $extracted = extractPeerIPsFromGetpeerinfo($resp);
        if (!empty($extracted) || $resp !== '') {
            // Count as responding if HTTP succeeded, even if peer list happens to be empty.
            $seedsResponding++;
        }
        foreach ($extracted as $ip => $_) {
            $peerSet[$ip] = true;
        }
    }
    curl_multi_close($multi);

    // Include the seeds themselves (they're nodes too, don't see themselves as peers).
    foreach (SEED_NODES as [$pubIp,]) {
        $peerSet[$pubIp] = true;
    }

    $result = [
        'nodesOnline'     => count($peerSet),
        'uniquePeers'     => count($peerSet),  // alias — clearer name for v0
        'seedsResponding' => $seedsResponding,
        'seedsTotal'      => count(SEED_NODES),
        'computedAt'      => time(),
    ];
    @file_put_contents($cacheFile, json_encode($result));
    return $result;
}

/**
 * Extract unique peer IPs from a getpeerinfo response body.
 *
 * Strategy:
 *   1. Try a clean JSON parse. If it succeeds, walk the result array — most
 *      reliable, gets every well-formed peer entry.
 *   2. If JSON parse fails (e.g. some peer's subver contains unescaped quotes
 *      and breaks the document), fall back to regex extraction of `"addr": "…"`
 *      pairs from the raw bytes. Less complete but resilient.
 *
 * Returns an associative array keyed by IP (port stripped, IPv6 brackets
 * removed) — so the caller can union it with other seeds' results for free.
 */
function extractPeerIPsFromGetpeerinfo(string $resp): array {
    $ips = [];

    // Path 1: clean JSON parse.
    $data = @json_decode($resp, true);
    if (is_array($data) && isset($data['result']) && is_array($data['result'])) {
        foreach ($data['result'] as $peer) {
            if (!is_array($peer)) continue;
            $addr = $peer['addr'] ?? null;
            if (!is_string($addr) || $addr === '') continue;
            $ip = normalizePeerIP($addr);
            if ($ip !== '') $ips[$ip] = true;
        }
        return $ips;
    }

    // Path 2: regex fallback for malformed-subver case.
    // `addr` values themselves never contain quotes, so this captures cleanly
    // even when other fields in the same peer entry are corrupt.
    if (preg_match_all('/"addr"\s*:\s*"([^"]+)"/', $resp, $m)) {
        foreach ($m[1] as $addr) {
            $ip = normalizePeerIP($addr);
            if ($ip !== '') $ips[$ip] = true;
        }
    }
    return $ips;
}

/**
 * Strip the port suffix from an addr string and return the IP only.
 * Handles both IPv4 (`192.0.2.1:8444`) and IPv6 (`[::1]:8444`) forms.
 */
function normalizePeerIP(string $addr): string {
    $addr = trim($addr);
    if ($addr === '') return '';
    // IPv6 bracketed form: [::1]:8444 → ::1
    if ($addr[0] === '[') {
        $end = strpos($addr, ']');
        if ($end !== false) {
            return substr($addr, 1, $end - 1);
        }
        return '';
    }
    // IPv4 form: strip a trailing `:port` if present.
    return preg_replace('/:\d+$/', '', $addr);
}

/**
 * Cumulative transaction count (sum of tx_count across all blocks on this chain).
 *
 * Incremental: cache stores {last_height, total_txs}. On each call, walks
 * from last_height+1 to current tip. First-ever call is slow (scans all
 * history); after that it's only a handful of new blocks per refresh.
 *
 * Cache TTL: 60 s (not because it's expensive once warmed, but so we don't
 * RPC-spam the node on every request).
 */
function getTotalTransactions(int $tipHeight, string $chain): ?int {
    $cacheFile = __DIR__ . "/../cache/total_tx-{$chain}.json";
    $state = ['lastHeight' => -1, 'totalTxs' => 0];
    if (file_exists($cacheFile)) {
        // Return fresh cache fast — don't re-walk the chain if we just did.
        if ((time() - filemtime($cacheFile)) < 60) {
            $c = json_decode(@file_get_contents($cacheFile), true);
            if (is_array($c) && isset($c['totalTxs'])) return (int)$c['totalTxs'];
        }
        $loaded = json_decode(@file_get_contents($cacheFile), true);
        if (is_array($loaded) && isset($loaded['lastHeight'], $loaded['totalTxs'])) {
            $state = $loaded;
        }
    }

    $startHeight = (int)$state['lastHeight'] + 1;
    $total       = (int)$state['totalTxs'];

    // Safety: cap how many blocks we scan in a single request so a cold cache
    // doesn't block the whole stats endpoint for minutes. 2000 blocks ≈ a few
    // seconds over loopback. Subsequent calls will close the gap.
    $endHeight = min($tipHeight, $startHeight + 2000 - 1);

    for ($h = $startHeight; $h <= $endHeight; $h++) {
        $hashResp = dilithionRPC('getblockhash', ['height' => $h]);
        $hash = is_array($hashResp) ? ($hashResp['blockhash'] ?? null) : $hashResp;
        if (!$hash) continue;
        $block = dilithionRPC('getblock', ['hash' => $hash, 'verbosity' => 0]);
        if (!$block) continue;
        $total += (int)($block['tx_count'] ?? 0);
    }

    $state = [
        'lastHeight' => $endHeight,
        'totalTxs'   => $total,
        'tipHeight'  => $tipHeight,
        'warmedUp'   => ($endHeight >= $tipHeight),
        'updatedAt'  => time(),
    ];
    @file_put_contents($cacheFile, json_encode($state));
    return $total;
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
