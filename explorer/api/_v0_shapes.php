<?php
/**
 * Shared v0-shape transformers for blocks and transactions.
 *
 * Used by:
 *   - blocks.php       (?shape=v0 path)
 *   - transactions.php (?shape=v0 path)
 *   - stream.php       (SSE event payloads)
 *
 * Subunit terminology: DIL has ions, DilV has volts. Both 1:1e8 vs whole coins.
 * RPC `getblock` returns vout values in subunits; transformers convert to whole coins.
 */

// Block direct access (file is meant to be require_once'd, not hit as an HTTP endpoint).
if (isset($_SERVER['SCRIPT_NAME']) && basename($_SERVER['SCRIPT_NAME']) === '_v0_shapes.php') {
    http_response_code(404);
    exit;
}

// Require chain config + RPC helper (already loaded by callers, but defensive).
if (!function_exists('getChainConfig')) {
    require_once __DIR__ . '/rpc.php';
}

// Address labels shared with holders.php / blocks.php.
function _v0Labels(): array {
    return [
        'DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq' => 'Dev Fund',
        'DTHGN3XiZ9LRxHVPUWMumX8B9q6B4BuPdp' => 'Bridge',
        'DNaTbwZgm6x23zf4DnJm4vjEG2qGc6cinx' => 'Bridge',
    ];
}

/**
 * Transform a raw getblock response into v0's camelCase shape.
 * Computes reward/fees from coinbase vout sum + Bitcoin-style halving subsidy.
 */
function transformBlockV0(?array $block): ?array {
    if (!is_array($block)) return $block;

    $config = getChainConfig();
    $baseReward = $config['reward'];

    $h = (int)($block['height'] ?? 0);
    $epoch = intdiv($h, 210000);
    $subsidyDIL = ($epoch >= 64) ? 0.0 : ((float)$baseReward / (1 << $epoch));

    $labels = _v0Labels();

    // Sum coinbase vouts in subunits (ions for DIL, volts for DilV), convert to whole-coin units.
    $rewardSubunits = 0.0;
    $minerAddress = '';
    $coinbaseTxid = '';
    $firstNonCoinbaseTxid = null;
    $txCount = 0;

    if (isset($block['tx']) && is_array($block['tx'])) {
        $txCount = count($block['tx']);
        if ($txCount > 0) {
            $cb = $block['tx'][0];
            if (is_string($cb)) {
                $coinbaseTxid = $cb;
            } else {
                $coinbaseTxid = $cb['txid'] ?? '';
                if (isset($cb['vout']) && is_array($cb['vout'])) {
                    foreach ($cb['vout'] as $vout) {
                        $rewardSubunits += (float)($vout['value'] ?? 0);
                        if ($minerAddress === '' && !empty($vout['address'])) {
                            $minerAddress = $vout['address'];
                        }
                    }
                }
            }
            if ($txCount > 1) {
                $first = $block['tx'][1];
                $firstNonCoinbaseTxid = is_string($first) ? $first : ($first['txid'] ?? null);
            }
        }
    }
    if ($txCount === 0 && isset($block['tx_count'])) {
        $txCount = (int)$block['tx_count'];
    }

    $miner = $labels[$minerAddress] ?? ($minerAddress !== '' ? $minerAddress : 'unknown');
    $rewardDIL = $rewardSubunits / 100000000.0;
    $feesDIL   = max(0.0, $rewardDIL - $subsidyDIL);

    // Difficulty: prefer block.difficulty, else compute from bits.
    $difficulty = 0.0;
    if (isset($block['difficulty'])) {
        $difficulty = (float)$block['difficulty'];
    } elseif (isset($block['bits'])) {
        $bitsRaw = $block['bits'];
        $cur = is_string($bitsRaw) ? hexdec($bitsRaw) : (int)$bitsRaw;
        if ($cur > 0) {
            $maxBits = 0x1f060000;
            $maxExp = $maxBits >> 24;
            $maxMantissa = $maxBits & 0x7fffff;
            $curExp = $cur >> 24;
            $curMantissa = $cur & 0x7fffff;
            if ($curMantissa > 0) {
                $difficulty = ($maxMantissa / $curMantissa) * pow(256.0, $maxExp - $curExp);
            }
        }
    }

    return [
        'height'               => $h,
        'hash'                 => $block['hash'] ?? null,
        'timestamp'            => (int)($block['time'] ?? 0),
        'size'                 => (int)($block['size'] ?? 0),
        'txCount'              => $txCount,
        'difficulty'           => round($difficulty, 8),
        'reward'               => round($rewardDIL, 8),
        'fees'                 => round($feesDIL, 8),
        'miner'                => $miner,
        'minerAddress'         => $minerAddress,
        'coinbaseTxid'         => $coinbaseTxid,
        'firstNonCoinbaseTxid' => $firstNonCoinbaseTxid,
        'mik'                  => $block['mik'] ?? null,
        'previousBlockHash'    => $block['previousblockhash'] ?? null,
    ];
}

/**
 * Transform a transactions.php-shape record (or a getrawtransaction-shape record)
 * into v0's camelCase shape. Auto-detects which input shape it received.
 */
function transformTxV0(array $tx): array {
    // Detect shape: existing transactions.php uses 'outputs' + 'total_output' + 'coinbase'.
    // getrawtransaction uses 'vout' + 'vin' + raw fields.
    $hasNormalized = isset($tx['outputs']) || isset($tx['total_output']);
    $hasRaw        = isset($tx['vout']) || isset($tx['vin']);

    $isCoinbase = false;
    $totalOutSubunits = 0.0;
    $to = '';
    $blockHeight = 0;
    $blockTime = 0;
    $confirmations = 0;
    $txid = $tx['txid'] ?? ($tx['id'] ?? '');

    if ($hasNormalized) {
        $isCoinbase = !empty($tx['coinbase']);
        $totalOutSubunits = (float)($tx['total_output'] ?? 0);
        if (isset($tx['outputs']) && is_array($tx['outputs'])) {
            foreach ($tx['outputs'] as $out) {
                if (!empty($out['address'])) { $to = $out['address']; break; }
            }
        }
        $blockHeight   = (int)($tx['block_height'] ?? 0);
        $blockTime     = (int)($tx['time'] ?? 0);
        $confirmations = (int)($tx['confirmations'] ?? 0);
    } elseif ($hasRaw) {
        // Detect coinbase from vin[0].coinbase
        if (isset($tx['vin']) && is_array($tx['vin'])) {
            foreach ($tx['vin'] as $vin) {
                if (!empty($vin['coinbase'])) { $isCoinbase = true; break; }
            }
        }
        if (isset($tx['vout']) && is_array($tx['vout'])) {
            foreach ($tx['vout'] as $vout) {
                $totalOutSubunits += (float)($vout['value'] ?? 0);
                if ($to === '' && !empty($vout['address'])) {
                    $to = $vout['address'];
                }
            }
        }
        $blockHeight   = (int)($tx['blockheight'] ?? ($tx['block_height'] ?? 0));
        $blockTime     = (int)($tx['blocktime']   ?? ($tx['time']         ?? 0));
        $confirmations = (int)($tx['confirmations'] ?? 0);
    }

    return [
        'id'            => $txid,
        'from'          => $isCoinbase ? 'coinbase' : null,
        'to'            => $to,
        'amount'        => round($totalOutSubunits / 100000000.0, 8),
        'fee'           => 0.0,                                          // deferred — UTXO fee requires vin prevout walk
        'timestamp'     => $blockTime,
        'blockHeight'   => $blockHeight,
        'kind'          => $isCoinbase ? 'coinbase' : 'transfer',
        'confirmations' => $confirmations,
    ];
}
