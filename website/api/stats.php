<?php
/**
 * API Proxy for Dilithion Network Stats
 * Proxies requests to backend nodes to avoid Mixed Content blocking
 */

// CORS headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store, must-revalidate');

// Handle OPTIONS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Backend nodes to try (in order)
$backends = [
    'http://188.166.255.63:8334/api/stats',
    'http://134.122.4.164:8334/api/stats',
    'http://209.97.177.197:8334/api/stats'
];

$errors = [];

// Try each backend
foreach ($backends as $backend) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $backend);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 2);           // Reduced to 2 seconds
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);    // Reduced to 1 second
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);

    // If successful, return the response
    if ($http_code === 200 && $response) {
        http_response_code(200);
        echo $response;
        exit;
    }

    // Log the error
    $errors[] = [
        'backend' => $backend,
        'http_code' => $http_code,
        'error' => $curl_error ?: 'No response'
    ];
}

// All backends failed - return error details
http_response_code(503);
echo json_encode([
    'error' => 'All backend nodes unavailable',
    'timestamp' => time(),
    'details' => $errors
]);
