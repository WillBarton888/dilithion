<?php
/**
 * Block Explorer API - Search Endpoint
 *
 * GET params:
 *   q (string) - Search query: block height, block hash, txid, or address
 *
 * Returns: {"type": "block|tx|address|unknown", "result": {...}}
 */

require_once __DIR__ . '/rpc.php';

$query = trim($_GET['q'] ?? '');

if ($query === '') {
    sendError('Missing required parameter: q');
}

// Pure number -> block height
if (ctype_digit($query)) {
    $height = intval($query);
    $hashResult = dilithionRPC('getblockhash', ['height' => $height]);
    $blockHash = is_array($hashResult) ? ($hashResult['blockhash'] ?? null) : $hashResult;
    if ($blockHash !== null) {
        $block = dilithionRPC('getblock', ['hash' => $blockHash, 'verbosity' => 1]);
        if ($block !== null) {
            sendJSON([
                'type' => 'block',
                'result' => $block
            ]);
        }
    }
    sendJSON([
        'type' => 'unknown',
        'query' => $query,
        'message' => 'No block found at height ' . $height
    ]);
}

// 64 hex characters -> try block hash first, then txid
if (preg_match('/^[0-9a-fA-F]{64}$/', $query)) {
    // Try as block hash
    $block = dilithionRPC('getblock', ['hash' => $query, 'verbosity' => 1]);
    if ($block !== null) {
        sendJSON([
            'type' => 'block',
            'result' => $block
        ]);
    }

    // Try as transaction id
    $tx = dilithionRPC('gettransaction', ['txid' => $query]);
    if ($tx !== null) {
        sendJSON([
            'type' => 'tx',
            'result' => $tx
        ]);
    }

    sendJSON([
        'type' => 'unknown',
        'query' => $query,
        'message' => 'No block or transaction found for this hash.'
    ]);
}

// Starts with D -> address
if (str_starts_with($query, 'D')) {
    sendJSON([
        'type' => 'address',
        'result' => ['address' => $query]
    ]);
}

// Nothing matched
sendJSON([
    'type' => 'unknown',
    'query' => $query,
    'message' => 'Could not identify search query. Try a block height, block hash, txid, or address.'
]);
