<?php
/**
 * API for Dilithion Network Stats
 * Fetches data from all seed nodes and returns aggregated stats
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

// Seed node configuration
// Note: Testnet uses port 18334, mainnet uses 8334
$seedNodes = [
    'nyc' => [
        'name' => 'NYC (Primary)',
        'ip' => '134.122.4.164',
        'api_port' => 18334
    ],
    'sgp' => [
        'name' => 'Singapore',
        'ip' => '188.166.255.63',
        'api_port' => 18334
    ],
    'ldn' => [
        'name' => 'London',
        'ip' => '209.97.177.197',
        'api_port' => 18334
    ]
];

/**
 * Fetch stats from a single node
 */
function fetchNodeStats($ip, $port) {
    $url = "http://{$ip}:{$port}/api/stats";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);

    if ($http_code === 200 && $response) {
        $data = json_decode($response, true);
        if ($data) {
            return [
                'online' => true,
                'blockHeight' => $data['blockHeight'] ?? 0,
                'peerCount' => $data['peerCount'] ?? 0,
                'hashrate' => $data['hashRate'] ?? $data['hashrate'] ?? 0,
                'difficulty' => $data['difficulty'] ?? 0
            ];
        }
    }

    return [
        'online' => false,
        'blockHeight' => 0,
        'peerCount' => 0,
        'error' => $curl_error ?: 'Connection failed'
    ];
}

// Fetch stats from all nodes
$nodes = [];
$maxBlockHeight = 0;
$totalPeers = 0;
$networkOnline = false;

foreach ($seedNodes as $nodeId => $config) {
    $nodeStats = fetchNodeStats($config['ip'], $config['api_port']);
    $nodes[$nodeId] = $nodeStats;

    if ($nodeStats['online']) {
        $networkOnline = true;
        if ($nodeStats['blockHeight'] > $maxBlockHeight) {
            $maxBlockHeight = $nodeStats['blockHeight'];
        }
        $totalPeers += $nodeStats['peerCount'];
    }
}

// Build response
$response = [
    'status' => $networkOnline ? 'live' : 'offline',
    'blockHeight' => $maxBlockHeight,
    'peerCount' => $totalPeers,
    'timestamp' => time(),
    'nodes' => $nodes
];

// Also include hashrate/difficulty from the first online node
foreach ($nodes as $nodeData) {
    if ($nodeData['online']) {
        if (isset($nodeData['hashrate']) && $nodeData['hashrate'] > 0) {
            $response['hashRate'] = $nodeData['hashrate'];
        }
        if (isset($nodeData['difficulty']) && $nodeData['difficulty'] > 0) {
            $response['difficulty'] = $nodeData['difficulty'];
        }
        break;
    }
}

http_response_code(200);
echo json_encode($response, JSON_PRETTY_PRINT);
