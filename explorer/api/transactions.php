<?php
/**
 * Block Explorer API - Recent Transactions Endpoint
 *
 * Returns recent transactions extracted from the latest blocks.
 * Cached for 30 seconds.
 *
 *   /api/transactions.php?chain=dil            → latest 50 transactions
 *   /api/transactions.php?chain=dil&limit=20   → latest 20 transactions
 */

require_once __DIR__ . "/rpc.php";

$config = getChainConfig();
$chainSuffix = $config['chain'] === 'dilv' ? '-dilv' : '';
$limit = min(max((int)($_GET['limit'] ?? 50), 1), 200);

$cacheFile = __DIR__ . "/../cache/transactions{$chainSuffix}.json";

// Check cache (30s TTL)
if (file_exists($cacheFile)) {
    $cacheAge = time() - filemtime($cacheFile);
    if ($cacheAge < 30) {
        $cached = file_get_contents($cacheFile);
        if ($cached !== false) {
            $data = json_decode($cached, true);
            if ($data !== null) {
                // Trim to requested limit
                if (isset($data['transactions'])) {
                    $data['transactions'] = array_slice($data['transactions'], 0, $limit);
                }
                $data['cached'] = true;
                $data['cacheAge'] = $cacheAge;
                sendJSON($data);
            }
        }
    }
}

// Get tip height
$tipHeight = dilithionRPC('getblockcount');
if ($tipHeight === null) {
    sendError("Failed to connect to node.", 503);
}

// Walk backwards through blocks collecting transactions
// Fetch enough blocks to get ~200 transactions (cache the full set)
$transactions = [];
$startHashResult = dilithionRPC('getblockhash', ['height' => $tipHeight]);
$currentHash = is_array($startHashResult) ? ($startHashResult['blockhash'] ?? null) : $startHashResult;
$blocksScanned = 0;
$maxBlocks = 50; // Scan up to 50 blocks

while ($currentHash !== null && count($transactions) < 200 && $blocksScanned < $maxBlocks) {
    usleep(10000); // 10ms delay
    $block = dilithionRPC('getblock', ['hash' => $currentHash, 'verbosity' => 2]);
    if ($block === null) break;

    $blockHeight = $block['height'] ?? -1;
    $blockTime = $block['time'] ?? 0;
    $blockHash = $block['hash'] ?? '';

    // Process transactions in this block
    if (isset($block['tx']) && is_array($block['tx'])) {
        foreach ($block['tx'] as $tx) {
            $txid = $tx['txid'] ?? '';
            $isCoinbase = false;
            $totalIn = 0;
            $totalOut = 0;
            $fromAddresses = [];
            $toAddresses = [];

            // Process inputs
            if (isset($tx['vin'])) {
                foreach ($tx['vin'] as $vin) {
                    if (isset($vin['coinbase']) && $vin['coinbase']) {
                        $isCoinbase = true;
                    }
                }
            }

            // Process outputs
            if (isset($tx['vout'])) {
                foreach ($tx['vout'] as $vout) {
                    $value = $vout['value'] ?? 0;
                    $totalOut += $value;
                    if (isset($vout['address']) && !empty($vout['address'])) {
                        $toAddresses[] = [
                            'address' => $vout['address'],
                            'value' => $value
                        ];
                    }
                }
            }

            $transactions[] = [
                'txid' => $txid,
                'block_height' => $blockHeight,
                'block_hash' => $blockHash,
                'time' => $blockTime,
                'coinbase' => $isCoinbase,
                'outputs' => $toAddresses,
                'total_output' => $totalOut,
                'confirmations' => $tipHeight - $blockHeight + 1,
            ];
        }
    }

    $currentHash = $block['previousblockhash'] ?? null;
    $blocksScanned++;
}

$response = [
    'transactions' => array_slice($transactions, 0, $limit),
    'total_found' => count($transactions),
    'blocks_scanned' => $blocksScanned,
    'tip_height' => $tipHeight,
    'unit' => $config['unit'],
    'chain' => $config['chain'],
    'updated_at' => time(),
];

// Cache full result
@file_put_contents($cacheFile, json_encode([
    'transactions' => $transactions,
    'total_found' => count($transactions),
    'blocks_scanned' => $blocksScanned,
    'tip_height' => $tipHeight,
    'unit' => $config['unit'],
    'chain' => $config['chain'],
    'updated_at' => time(),
]));

sendJSON($response);
