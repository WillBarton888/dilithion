<?php
/**
 * Block Explorer API - Seed Node Status (Live)
 *
 * Queries all 4 mainnet seed nodes directly via RPC.
 * NYC is local (127.0.0.1), others via direct HTTP.
 * Cached for 3 seconds to avoid overloading nodes.
 */

require_once __DIR__ . "/rpc.php";

$config = getChainConfig();
$chain = $config['chain'];
$rpcPort = $config['rpc_port'];

// 3-second cache
$cacheFile = __DIR__ . "/../cache/nodes-{$chain}.json";
if (file_exists($cacheFile)) {
    $cacheAge = time() - filemtime($cacheFile);
    if ($cacheAge < 3) {
        $cached = file_get_contents($cacheFile);
        if ($cached !== false) {
            $data = json_decode($cached, true);
            if ($data !== null) {
                $data['cached'] = true;
                $data['cacheAge'] = $cacheAge;
                sendJSON($data);
            }
        }
    }
}

$seedNodes = [
    ['id' => 'nyc', 'ip' => '138.197.68.128', 'host' => '127.0.0.1',      'label' => 'New York',  'flag' => 'US', 'primary' => true],
    ['id' => 'ldn', 'ip' => '167.172.56.119', 'host' => '167.172.56.119', 'label' => 'London',    'flag' => 'GB', 'primary' => false],
    ['id' => 'sgp', 'ip' => '165.22.103.114', 'host' => '165.22.103.114', 'label' => 'Singapore', 'flag' => 'SG', 'primary' => false],
    ['id' => 'syd', 'ip' => '134.199.159.83', 'host' => '134.199.159.83', 'label' => 'Sydney',    'flag' => 'AU', 'primary' => false],
];

// Query all nodes in parallel using curl_multi
$multiHandle = curl_multi_init();
$curlHandles = [];

// For each node, create 3 requests: getblockchaininfo, getconnectioncount, getnetworkinfo
$requests = [];
foreach ($seedNodes as $i => $node) {
    $methods = ['getblockchaininfo', 'getconnectioncount', 'getnetworkinfo'];
    foreach ($methods as $j => $method) {
        $ch = curl_init();
        $url = "http://{$node['host']}:{$rpcPort}/";
        $payload = json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => $method, 'params' => []]);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'X-Dilithion-RPC: 1',
            'Authorization: Basic ' . base64_encode('rpc:rpc'),
        ]);
        curl_multi_add_handle($multiHandle, $ch);
        $key = "{$i}_{$j}";
        $curlHandles[$key] = $ch;
        $requests[$key] = ['node' => $i, 'method' => $method];
    }
}

// Execute all requests in parallel
$running = null;
do {
    curl_multi_exec($multiHandle, $running);
    curl_multi_select($multiHandle, 0.1);
} while ($running > 0);

// Collect results
$nodeData = [];
foreach ($seedNodes as $i => $node) {
    $nodeData[$i] = [
        'id'      => $node['id'],
        'ip'      => $node['ip'],
        'label'   => $node['label'],
        'flag'    => $node['flag'],
        'primary' => $node['primary'],
        'online'  => false,
        'height'  => null,
        'peers'   => null,
        'chain'   => null,
        'version' => null,
        'difficulty' => null,
    ];
}

foreach ($curlHandles as $key => $ch) {
    $response = curl_multi_getcontent($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_multi_remove_handle($multiHandle, $ch);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) continue;
    $data = json_decode($response, true);
    if (!$data || isset($data['error']) && $data['error'] !== null) continue;
    $result = $data['result'] ?? null;
    if ($result === null) continue;

    $nodeIdx = $requests[$key]['node'];
    $method = $requests[$key]['method'];

    if ($method === 'getblockchaininfo') {
        $nodeData[$nodeIdx]['online'] = true;
        $nodeData[$nodeIdx]['height'] = $result['blocks'] ?? 0;
        $nodeData[$nodeIdx]['chain'] = $result['chain'] ?? null;
        $nodeData[$nodeIdx]['difficulty'] = $result['difficulty'] ?? null;
    } elseif ($method === 'getconnectioncount') {
        $nodeData[$nodeIdx]['peers'] = $result;
    } elseif ($method === 'getnetworkinfo') {
        $nodeData[$nodeIdx]['version'] = $result['subversion'] ?? null;
    }
}

curl_multi_close($multiHandle);

$nodes = array_values($nodeData);
$heights = array_filter(array_column($nodes, 'height'), fn($h) => $h !== null);
$consensusHeight = !empty($heights) ? max($heights) : 0;

$response = [
    'nodes' => $nodes,
    'chain' => $chain,
    'consensusHeight' => $consensusHeight,
    'timestamp' => time(),
];

@file_put_contents($cacheFile, json_encode($response));
sendJSON($response);
