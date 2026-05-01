<?php
/**
 * Block Explorer API - Server-Sent Events Stream
 *
 * Streams `block` and `tx` events to the client as new blocks arrive and as
 * new mempool transactions appear. Polls the local RPC every 1.5s and emits
 * events when state changes; heartbeats every 15s to keep the connection alive
 * across nginx/proxy timeouts.
 *
 *   GET /api/stream.php?chain=dil
 *   GET /api/stream.php?chain=dil&notxs   (block events only, no mempool tx events)
 *
 * Events emitted:
 *   event: ready    - sent once at connection time, payload: { chain, tipHeight, mempoolSize }
 *   event: block    - new block detected, payload matches blocks.php?shape=v0 row shape
 *   event: tx       - new mempool tx, payload matches transactions.php?shape=v0 row shape
 *   : heartbeat ... - SSE comment lines (every 15s); ignored by EventSource
 *
 * Session cap: 60s. The server closes the stream cleanly; EventSource will
 * auto-reconnect. This keeps PHP-FPM worker turnover sane.
 *
 * Subunit terminology: DIL has ions, DilV has volts; transform layer divides
 * by 1e8 so emitted amounts are in whole DIL/DilV.
 */

require_once __DIR__ . '/rpc.php';
require_once __DIR__ . '/_v0_shapes.php';

// Read params (rpc.php's getChainConfig already handles case-insensitivity).
$chain   = getChainConfig()['chain'];
$emitTxs = !array_key_exists('notxs', $_GET);

// SSE headers
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Connection: keep-alive');
header('X-Accel-Buffering: no');           // disable nginx response buffering
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Long-running setup
@set_time_limit(0);
@ignore_user_abort(false);                 // exit when client disconnects → frees PHP-FPM worker
while (ob_get_level() > 0) ob_end_flush();
@ob_implicit_flush(true);

/**
 * Send a named SSE event.
 */
function sse_event(string $event, $data): void {
    echo "event: {$event}\n";
    echo 'data: ' . json_encode($data) . "\n\n";
    @flush();
}

/**
 * Send an SSE comment line (used as a heartbeat — EventSource ignores comments).
 */
function sse_comment(string $msg): void {
    echo ": {$msg}\n\n";
    @flush();
}

// Initial state: send current tip block
$tipHeight = dilithionRPC('getblockcount');
if ($tipHeight === null) {
    sse_event('error', ['message' => 'node unreachable']);
    exit;
}
$tipHeight = (int)$tipHeight;
$lastBlockHeight = $tipHeight;

$tipHashRes = dilithionRPC('getblockhash', ['height' => $tipHeight]);
$tipHash = is_array($tipHashRes) ? ($tipHashRes['blockhash'] ?? null) : $tipHashRes;

// Track mempool ids to detect new transactions
$seenMempoolIds = [];
if ($emitTxs) {
    $raw = dilithionRPC('getrawmempool');
    if (is_array($raw)) {
        foreach ($raw as $txid) $seenMempoolIds[$txid] = true;
    }
}

// Tell client we're ready (and what chain state they joined at)
sse_event('ready', [
    'chain'       => $chain,
    'tipHeight'   => $tipHeight,
    'mempoolSize' => count($seenMempoolIds),
    'serverTime'  => time(),
]);

// Send the current tip block as the first 'block' event so clients have an
// immediate render anchor (mirrors the SWR "previous data" UX).
if ($tipHash !== null) {
    $tipBlock = dilithionRPC('getblock', ['hash' => $tipHash, 'verbosity' => 2]);
    if (is_array($tipBlock)) {
        sse_event('block', transformBlockV0($tipBlock));
    }
}

// Main loop
$startTime     = time();
$lastHeartbeat = time();
$pollInterval  = 1.5;                       // seconds between RPC polls
$sessionCap    = 60;                         // 1 min — keeps fpm worker turnover high under load
$txEmitCap     = 20;                         // max mempool tx events emitted per poll cycle (DoS guard)

while (true) {
    // Session cap reached → close cleanly, client EventSource auto-reconnects.
    if ((time() - $startTime) >= $sessionCap) {
        sse_comment('session ended, please reconnect');
        break;
    }
    if (connection_aborted()) break;

    // ---- New block detection ----
    $newHeight = dilithionRPC('getblockcount');
    if ($newHeight !== null && (int)$newHeight > $lastBlockHeight) {
        $newHeight = (int)$newHeight;
        // Emit each new block in order (handles bursts where >1 block arrived between polls)
        for ($h = $lastBlockHeight + 1; $h <= $newHeight; $h++) {
            $hRes = dilithionRPC('getblockhash', ['height' => $h]);
            $bHash = is_array($hRes) ? ($hRes['blockhash'] ?? null) : $hRes;
            if (!$bHash) continue;
            $b = dilithionRPC('getblock', ['hash' => $bHash, 'verbosity' => 2]);
            if (!is_array($b)) continue;
            sse_event('block', transformBlockV0($b));
            // Drop included txs from mempool tracking so we don't re-emit them
            if (isset($b['tx']) && is_array($b['tx'])) {
                foreach ($b['tx'] as $tx) {
                    $tid = is_string($tx) ? $tx : ($tx['txid'] ?? null);
                    if ($tid) unset($seenMempoolIds[$tid]);
                }
            }
        }
        $lastBlockHeight = $newHeight;
    }

    // ---- New mempool tx detection ----
    if ($emitTxs) {
        $raw = dilithionRPC('getrawmempool');
        if (is_array($raw)) {
            $currentSet = array_flip($raw);
            $newOnes    = array_diff_key($currentSet, $seenMempoolIds);
            $emitted    = 0;
            foreach (array_keys($newOnes) as $newTxid) {
                $seenMempoolIds[$newTxid] = true;
                if ($emitted >= $txEmitCap) continue;        // still record as seen, just don't emit
                $rawTx = dilithionRPC('getrawtransaction', ['txid' => $newTxid, 'verbose' => true]);
                if ($rawTx === null) {
                    $rawTx = dilithionRPC('gettransaction', ['txid' => $newTxid]);
                }
                if (is_array($rawTx)) {
                    sse_event('tx', transformTxV0($rawTx));
                    $emitted++;
                }
            }
            // Forget txids that have left the mempool (mined or evicted)
            $seenMempoolIds = array_intersect_key($seenMempoolIds, $currentSet);
        }
    }

    // ---- Heartbeat ----
    if ((time() - $lastHeartbeat) >= 15) {
        sse_comment('hb ' . time());
        $lastHeartbeat = time();
    }

    // Poll cadence
    usleep((int)($pollInterval * 1000000));
}
