<?php
/**
 * Block Explorer API - Transaction Endpoint
 *
 * GET params:
 *   txid (string) - Transaction ID (64 hex characters)
 *
 * Without txindex on the node, getrawtransaction does a full chain scan
 * (~7s for old txs) and holds cs_main while it does. Per-txid caching
 * (positive + NEGATIVE) is essential so repeat lookups never hit RPC.
 */

require_once __DIR__ . '/rpc.php';

$txid = $_GET['txid'] ?? null;

if ($txid === null || $txid === '') {
    sendError('Missing required parameter: txid');
}

if (!preg_match('/^[0-9a-fA-F]{64}$/', $txid)) {
    sendError('Invalid txid. Must be 64 hex characters.');
}

$chain     = getChainConfig()['chain'];                // 'dil' or 'dilv'
$cacheDir  = __DIR__ . '/../cache';
$cacheFile = "{$cacheDir}/tx-{$chain}-{$txid}.json";   // txid is 64-hex, safe path
$POS_TTL   = 86400;   // 24h: confirmed txs are immutable
$NEG_TTL   = 300;     // 5min negative cache — kills the 7s/req chain-scan hammer

if (file_exists($cacheFile)) {
    $age = time() - filemtime($cacheFile);
    $entry = json_decode(@file_get_contents($cacheFile), true);
    if (is_array($entry) && isset($entry['found'])) {
        if ($entry['found'] === true && $age < $POS_TTL) {
            sendJSON(['transaction' => $entry['tx'], 'cached' => true, 'cacheAge' => $age]);
        }
        if ($entry['found'] === false && $age < $NEG_TTL) {
            sendError('Transaction not found.', 404);
        }
    }
}

$tx = dilithionRPC('gettransaction', ['txid' => $txid]);
if ($tx === null) {
    // Fallback: getrawtransaction with verbose=true (slow path without txindex)
    $tx = dilithionRPC('getrawtransaction', ['txid' => $txid, 'verbose' => true]);
}

if ($tx === null) {
    @file_put_contents($cacheFile, json_encode(['found' => false, 'at' => time()]));
    sendError('Transaction not found.', 404);
}

@file_put_contents($cacheFile, json_encode(['found' => true, 'tx' => $tx, 'at' => time()]));
sendJSON(['transaction' => $tx]);
