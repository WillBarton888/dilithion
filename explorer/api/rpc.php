<?php
/**
 * Shared RPC helper for Dilithion Block Explorer API
 * Proxies JSON-RPC calls to the local Dilithion node (127.0.0.1:8332)
 */

// Persistent curl handle for connection reuse (keep-alive)
$_rpcCurlHandle = null;

function dilithionRPC($method, $params = []) {
    global $_rpcCurlHandle;

    if ($_rpcCurlHandle === null) {
        $_rpcCurlHandle = curl_init();
        curl_setopt($_rpcCurlHandle, CURLOPT_URL, 'http://127.0.0.1:8332/');
        curl_setopt($_rpcCurlHandle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($_rpcCurlHandle, CURLOPT_TIMEOUT, 5);
        curl_setopt($_rpcCurlHandle, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($_rpcCurlHandle, CURLOPT_POST, true);
        curl_setopt($_rpcCurlHandle, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'X-Dilithion-RPC: 1',
            'Authorization: Basic ' . base64_encode('rpc:rpc'),
            'Connection: keep-alive'
        ]);
    }

    $payload = json_encode([
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => $method,
        'params' => $params
    ]);

    curl_setopt($_rpcCurlHandle, CURLOPT_POSTFIELDS, $payload);
    $response = curl_exec($_rpcCurlHandle);
    $httpCode = curl_getinfo($_rpcCurlHandle, CURLINFO_HTTP_CODE);

    if ($httpCode !== 200 || !$response) {
        return null;
    }

    $data = json_decode($response, true);
    if (isset($data['error']) && $data['error'] !== null) {
        return null;
    }

    return $data['result'] ?? null;
}

function sendJSON($data) {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Content-Type: application/json');
    header('Cache-Control: no-cache, no-store, must-revalidate');

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }

    echo json_encode($data, JSON_PRETTY_PRINT);
    exit;
}

function sendError($message, $code = 400) {
    http_response_code($code);
    sendJSON(['error' => $message]);
}
