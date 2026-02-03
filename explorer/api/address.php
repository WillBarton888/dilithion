<?php
/**
 * Block Explorer API - Address Endpoint
 *
 * GET params:
 *   addr (string) - Dilithion address (starts with 'D')
 *
 * Fetches balance and UTXOs from the REST API on port 8334.
 */

require_once __DIR__ . '/rpc.php';

$addr = $_GET['addr'] ?? null;

if ($addr === null || $addr === '') {
    sendError('Missing required parameter: addr');
}

// Validate address format: starts with D, reasonable length (26-35 chars typical for base58)
if (!preg_match('/^D[a-km-zA-HJ-NP-Z1-9]{25,34}$/', $addr)) {
    sendError('Invalid address format. Must start with D and be a valid base58 address.');
}

// Fetch balance from REST API
$balance = fetchRestAPI("http://127.0.0.1:8334/api/v1/balance/{$addr}");

// Fetch UTXOs from REST API
$utxos = fetchRestAPI("http://127.0.0.1:8334/api/v1/utxos/{$addr}");

if ($balance === null && $utxos === null) {
    sendError('Failed to fetch address data. Node may be unavailable.', 503);
}

sendJSON([
    'address' => $addr,
    'balance' => $balance,
    'utxos' => $utxos
]);

/**
 * Fetch data from the Dilithion REST API (port 8334)
 */
function fetchRestAPI($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Accept: application/json'
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) {
        return null;
    }

    return json_decode($response, true);
}
