<?php
/**
 * Block Explorer API - Mempool Endpoint
 *
 * No params required.
 *
 * Returns mempool info and list of transaction IDs.
 */

require_once __DIR__ . '/rpc.php';

$mempoolInfo = dilithionRPC('getmempoolinfo');
$rawMempool = dilithionRPC('getrawmempool');

if ($mempoolInfo === null) {
    sendError('Failed to connect to node.', 503);
}

$txids = is_array($rawMempool) ? $rawMempool : [];

sendJSON([
    'size' => $mempoolInfo['size'] ?? count($txids),
    'bytes' => $mempoolInfo['bytes'] ?? 0,
    'usage' => $mempoolInfo['usage'] ?? 0,
    'maxmempool' => $mempoolInfo['maxmempool'] ?? 0,
    'mempoolminfee' => $mempoolInfo['mempoolminfee'] ?? 0,
    'txids' => $txids
]);
