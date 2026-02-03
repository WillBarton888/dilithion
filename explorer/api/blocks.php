<?php
/**
 * Block Explorer API - Blocks Endpoint
 *
 * GET params:
 *   hash      (string)  - Block hash to look up directly
 *   height    (int)     - Block height to look up
 *   page      (int)     - Page number for latest blocks list (default: 1)
 *   limit     (int)     - Blocks per page, max 50 (default: 20)
 *   verbosity (int)     - getblock verbosity level (default: 1)
 *
 * If hash provided: returns single block by hash
 * If height provided: returns single block by height
 * If neither: returns paginated list of latest blocks
 */

require_once __DIR__ . '/rpc.php';

$hash = $_GET['hash'] ?? null;
$height = isset($_GET['height']) ? intval($_GET['height']) : null;
$page = max(1, intval($_GET['page'] ?? 1));
$limit = min(50, max(1, intval($_GET['limit'] ?? 20)));
$verbosity = max(0, min(2, intval($_GET['verbosity'] ?? 1)));

// Single block by hash
if ($hash !== null) {
    if (!preg_match('/^[0-9a-fA-F]{64}$/', $hash)) {
        sendError('Invalid block hash. Must be 64 hex characters.');
    }

    $block = dilithionRPC('getblock', ['hash' => $hash, 'verbosity' => $verbosity]);
    if ($block === null) {
        sendError('Block not found.', 404);
    }

    sendJSON(['block' => $block]);
}

// Single block by height
if ($height !== null) {
    if ($height < 0) {
        sendError('Height must be non-negative.');
    }

    $hashResult = dilithionRPC('getblockhash', ['height' => $height]);
    if ($hashResult === null) {
        sendError('Block not found at height ' . $height . '.', 404);
    }
    $blockHash = is_array($hashResult) ? ($hashResult['blockhash'] ?? null) : $hashResult;
    if ($blockHash === null) {
        sendError('Block not found at height ' . $height . '.', 404);
    }

    $block = dilithionRPC('getblock', ['hash' => $blockHash, 'verbosity' => $verbosity]);
    if ($block === null) {
        sendError('Failed to retrieve block data.', 500);
    }

    sendJSON(['block' => $block]);
}

// Latest blocks list with pagination
// Try cache first
$cacheFile = __DIR__ . '/../cache/latest-blocks.json';
$useCache = false;

if ($page === 1 && file_exists($cacheFile)) {
    $cacheAge = time() - filemtime($cacheFile);
    if ($cacheAge < 30) {
        $cached = json_decode(file_get_contents($cacheFile), true);
        if ($cached !== null && isset($cached['blocks'])) {
            // Slice the cached blocks to match the requested limit
            $cachedBlocks = array_slice($cached['blocks'], 0, $limit);
            sendJSON([
                'blocks' => $cachedBlocks,
                'page' => 1,
                'limit' => $limit,
                'totalHeight' => $cached['totalHeight'] ?? 0,
                'cached' => true,
                'cacheAge' => $cacheAge
            ]);
        }
    }
}

// Live RPC calls - walk chain backwards via previousblockhash to minimize connections
$tipHeight = dilithionRPC('getblockcount');
if ($tipHeight === null) {
    sendError('Failed to connect to node.', 503);
}

$startHeight = $tipHeight - (($page - 1) * $limit);
$blocks = [];

// Get starting block hash
$startHashResult = dilithionRPC('getblockhash', ['height' => $startHeight]);
$currentHash = is_array($startHashResult) ? ($startHashResult['blockhash'] ?? null) : $startHashResult;

if ($currentHash === null) {
    sendError('Failed to get block hash.', 503);
}

// Walk backwards using previousblockhash (1 RPC per block instead of 2)
for ($i = 0; $i < $limit && $currentHash !== null; $i++) {
    usleep(10000); // 10ms delay between calls to avoid socket exhaustion
    $block = dilithionRPC('getblock', ['hash' => $currentHash, 'verbosity' => $verbosity]);
    if ($block === null) {
        break;
    }

    $blocks[] = $block;
    $currentHash = $block['previousblockhash'] ?? null;
}

// Cache page 1 results
if ($page === 1 && !empty($blocks)) {
    $cacheDir = dirname($cacheFile);
    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0755, true);
    }
    @file_put_contents($cacheFile, json_encode([
        'blocks' => $blocks,
        'totalHeight' => $tipHeight,
        'timestamp' => time()
    ]));
}

sendJSON([
    'blocks' => $blocks,
    'page' => $page,
    'limit' => $limit,
    'totalHeight' => $tipHeight,
    'cached' => false
]);
