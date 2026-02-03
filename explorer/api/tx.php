<?php
/**
 * Block Explorer API - Transaction Endpoint
 *
 * GET params:
 *   txid (string) - Transaction ID (64 hex characters)
 */

require_once __DIR__ . '/rpc.php';

$txid = $_GET['txid'] ?? null;

if ($txid === null || $txid === '') {
    sendError('Missing required parameter: txid');
}

if (!preg_match('/^[0-9a-fA-F]{64}$/', $txid)) {
    sendError('Invalid txid. Must be 64 hex characters.');
}

$tx = dilithionRPC('gettransaction', ['txid' => $txid]);
if ($tx === null) {
    // Try getrawtransaction with verbose=true as fallback
    $tx = dilithionRPC('getrawtransaction', ['txid' => $txid, 'verbose' => true]);
}

if ($tx === null) {
    sendError('Transaction not found.', 404);
}

sendJSON(['transaction' => $tx]);
