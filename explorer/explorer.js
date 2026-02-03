/* ============================================================
   Dilithion Block Explorer - SPA with Hash-Based Routing
   ============================================================ */

'use strict';

// --- Configuration ---
const API_BASE = '/api';
const REFRESH_INTERVAL = 10000;
const ITEMS_PER_PAGE = 20;
const IONS_PER_DIL = 100000000;

// --- State ---
let refreshTimer = null;
let currentRoute = '';

// --- SVG Icons ---
const ICONS = {
    copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    chevronLeft: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>',
    chevronRight: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>',
    arrow: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>',
    pickaxe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2.5L18 6l-4 4"/><path d="M2 22l10-10"/><path d="M18 6l4-4"/></svg>',
};

// ============================================================
// Router
// ============================================================

class Router {
    constructor() {
        this.routes = [];
        window.addEventListener('hashchange', () => this.route());
    }

    add(pattern, handler) {
        this.routes.push({ pattern, handler });
    }

    route() {
        const hash = window.location.hash || '#/';
        stopAutoRefresh();

        for (const { pattern, handler } of this.routes) {
            const regex = new RegExp('^' + pattern.replace(/:\w+/g, '([^/]+)') + '$');
            const match = hash.match(regex);
            if (match) {
                currentRoute = pattern;
                updateNavLinks(hash);
                handler(...match.slice(1));
                return;
            }
        }

        // Default fallback to home
        currentRoute = '#/';
        updateNavLinks('#/');
        renderHome();
    }
}

const router = new Router();

// --- Routes ---
router.add('#/', renderHome);
router.add('#/home', renderHome);
router.add('#/block/:id', renderBlock);
router.add('#/tx/:txid', renderTransaction);
router.add('#/address/:addr', renderAddress);
router.add('#/blocks', () => renderBlockList(1));
router.add('#/blocks/:page', (page) => renderBlockList(parseInt(page, 10)));
router.add('#/forks', renderForks);
router.add('#/search/:query', handleSearch);

// ============================================================
// Helper Functions
// ============================================================

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function formatHash(hash, chars) {
    if (!hash) return '';
    chars = chars || 8;
    if (hash.length <= chars * 2 + 3) return hash;
    return hash.substring(0, chars) + '...' + hash.substring(hash.length - chars);
}

function formatAmount(ions) {
    if (ions === null || ions === undefined) return '0.00000000';
    const dil = Number(ions) / IONS_PER_DIL;
    return dil.toFixed(8);
}


function formatNumber(n) {
    if (n === null || n === undefined) return '0';
    return Number(n).toLocaleString('en-US');
}

function formatTime(timestamp) {
    if (!timestamp) return '';
    const now = Math.floor(Date.now() / 1000);
    const diff = now - timestamp;

    if (diff < 0) return 'just now';
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + ' min ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return formatAbsoluteTime(timestamp);
}

function formatAbsoluteTime(timestamp) {
    if (!timestamp) return '';
    const d = new Date(timestamp * 1000);
    return d.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
    });
}

function formatHashRate(hps) {
    if (!hps || hps <= 0) return '0 H/s';
    const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s'];
    let idx = 0;
    let val = Number(hps);
    while (val >= 1000 && idx < units.length - 1) {
        val /= 1000;
        idx++;
    }
    return val.toFixed(2) + ' ' + units[idx];
}

function formatSize(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
}

function setTitle(subtitle) {
    document.title = subtitle ? subtitle + ' - Dilithion Explorer' : 'Dilithion Explorer';
}

function getApp() {
    return document.getElementById('app');
}

function showLoading() {
    getApp().innerHTML = '<div class="loading"><div class="spinner"></div><span>Loading...</span></div>';
}

function showError(title, message) {
    getApp().innerHTML = `
        <div class="error-message">
            <h2>${escapeHtml(title)}</h2>
            <p>${escapeHtml(message)}</p>
            <a href="#/">Back to Home</a>
        </div>`;
}

function stopAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

function updateNavLinks(hash) {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
        const route = link.getAttribute('data-route');
        if (route === 'home' && (hash === '#/' || hash === '#/home')) {
            link.classList.add('active');
        } else if (route === 'blocks' && hash.startsWith('#/blocks')) {
            link.classList.add('active');
        } else if (route === 'forks' && hash === '#/forks') {
            link.classList.add('active');
        }
    });
}

async function apiFetch(endpoint) {
    const response = await fetch(API_BASE + endpoint);
    if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.error || 'API error: ' + response.status);
    }
    return response.json();
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).catch(() => {
        // Fallback for non-https
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    });
}

function makeCopyButton(text) {
    return `<button class="copy-btn" onclick="handleCopy(this, '${escapeHtml(text)}')" title="Copy to clipboard">${ICONS.copy}</button>`;
}

function handleCopy(btn, text) {
    copyToClipboard(text);
    btn.innerHTML = ICONS.check;
    btn.classList.add('copied');
    setTimeout(() => {
        btn.innerHTML = ICONS.copy;
        btn.classList.remove('copied');
    }, 2000);
}
// Expose globally for inline onclick
window.handleCopy = handleCopy;

function breadcrumb(items) {
    const parts = items.map((item, i) => {
        if (i === items.length - 1) {
            return `<span class="current">${escapeHtml(item.label)}</span>`;
        }
        return `<a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a><span class="separator">&rsaquo;</span>`;
    });
    return `<div class="breadcrumb">${parts.join('')}</div>`;
}

// ============================================================
// View: Home
// ============================================================

async function renderHome() {
    setTitle(null);
    showLoading();

    try {
        const [statsRes, blocksRes] = await Promise.all([
            apiFetch('/stats.php'),
            apiFetch('/blocks.php?limit=15'),
        ]);

        const stats = statsRes;
        const blocks = blocksRes.blocks || [];

        let html = '';

        // Stats bar
        html += '<div class="stats-bar">';
        html += statCard('Block Height', formatNumber(stats.blocks || blocksRes.totalHeight || 0));
        html += statCard('Hashrate', formatHashRate(stats.networkhashps));
        html += statCard('Difficulty', stats.difficulty ? Number(stats.difficulty).toFixed(4) : 'N/A');
        html += statCard('Supply', stats.supply ? formatNumber(Math.floor(stats.supply)) + ' DIL' : 'N/A');
        html += statCard('Avg Block Time', stats.avgBlockTime ? stats.avgBlockTime.toFixed(0) + 's' : 'N/A');
        html += statCard('Peers', stats.connections != null ? formatNumber(stats.connections) : 'N/A');
        html += '</div>';

        // Latest blocks
        html += '<div class="card">';
        html += '<div class="card-header"><h2>Latest Blocks</h2><a href="#/blocks" class="card-action">View all blocks &rarr;</a></div>';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table">';
        html += '<thead><tr><th>Height</th><th>Hash</th><th>Time</th><th>Miner</th><th class="center">Txs</th><th class="right">Reward</th></tr></thead>';
        html += '<tbody>';

        for (const block of blocks) {
            const height = block.height;
            const hash = block.hash || '';
            const time = block.time || block.mediantime || 0;
            const txCount = block.nTx || block.tx_count || (block.tx ? block.tx.length : 0);
            const miner = extractMiner(block);
            const reward = extractReward(block);

            html += '<tr>';
            html += `<td><a href="#/block/${height}">${formatNumber(height)}</a></td>`;
            html += `<td><a href="#/block/${escapeHtml(hash)}" class="hash">${escapeHtml(formatHash(hash, 10))}</a></td>`;
            html += `<td title="${escapeHtml(formatAbsoluteTime(time))}">${escapeHtml(formatTime(time))}</td>`;
            html += `<td>${miner ? `<a href="#/address/${escapeHtml(miner)}" class="address">${escapeHtml(formatHash(miner, 8))}</a>` : '<span class="text-dim">Unknown</span>'}</td>`;
            html += `<td class="center">${txCount}</td>`;
            html += `<td class="right amount">${escapeHtml(formatAmount(reward))} DIL</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div></div>';

        getApp().innerHTML = html;

        // Auto-refresh
        refreshTimer = setInterval(async () => {
            if (currentRoute !== '#/' && currentRoute !== '#/home') return;
            try {
                const fresh = await apiFetch('/blocks.php?limit=15');
                const freshBlocks = fresh.blocks || [];
                if (freshBlocks.length > 0 && blocks.length > 0 &&
                    freshBlocks[0].height !== blocks[0].height) {
                    renderHome();
                }
            } catch (e) {
                // Silent fail on refresh
            }
        }, REFRESH_INTERVAL);

    } catch (err) {
        showError('Failed to Load', err.message);
    }
}

function statCard(label, value, isMono) {
    return `<div class="stat-card"><div class="stat-label">${escapeHtml(label)}</div><div class="stat-value${isMono ? ' mono' : ''}">${escapeHtml(value)}</div></div>`;
}

function extractMiner(block) {
    // First check top-level miner field (available at all verbosity levels)
    if (block.miner) return block.miner;

    // Fallback: extract from coinbase tx outputs (verbosity=2 only)
    if (block.tx && block.tx.length > 0) {
        const coinbase = block.tx[0];
        if (typeof coinbase === 'object' && coinbase.vout) {
            for (const out of coinbase.vout) {
                const addr = out.scriptPubKey?.address || out.scriptPubKey?.addresses?.[0];
                if (addr && addr.startsWith('D')) return addr;
            }
        }
    }
    return null;
}

function extractReward(block) {
    // First try from coinbase tx outputs (verbosity=2)
    if (block.tx && block.tx.length > 0) {
        const coinbase = block.tx[0];
        if (typeof coinbase === 'object' && coinbase.vout) {
            let total = 0;
            for (const out of coinbase.vout) {
                total += out.value || 0;
            }
            return total;
        }
    }
    // Fallback: 50 DIL block reward (in ions)
    return 50 * IONS_PER_DIL;
}

// ============================================================
// View: Block Detail
// ============================================================

async function renderBlock(id) {
    setTitle('Block ' + id);
    showLoading();

    try {
        let data;
        if (/^\d+$/.test(id)) {
            data = await apiFetch('/blocks.php?height=' + id + '&verbosity=2');
        } else {
            data = await apiFetch('/blocks.php?hash=' + encodeURIComponent(id) + '&verbosity=2');
        }

        const block = data.block;
        if (!block) throw new Error('Block not found');

        const height = block.height;
        setTitle('Block #' + formatNumber(height));

        let html = '';

        // Breadcrumb
        html += breadcrumb([
            { label: 'Home', href: '#/' },
            { label: 'Blocks', href: '#/blocks' },
            { label: 'Block #' + formatNumber(height) },
        ]);

        // Block header with nav
        html += '<div class="card">';
        html += '<div class="card-header">';
        html += '<h2>Block #' + escapeHtml(formatNumber(height)) + '</h2>';
        html += '<div class="block-nav">';
        if (height > 0) {
            html += `<a href="#/block/${height - 1}">${ICONS.chevronLeft} ${formatNumber(height - 1)}</a>`;
        } else {
            html += `<span class="disabled">${ICONS.chevronLeft} Prev</span>`;
        }
        if (block.nextblockhash) {
            html += `<a href="#/block/${height + 1}">${formatNumber(height + 1)} ${ICONS.chevronRight}</a>`;
        } else {
            html += `<span class="disabled">Next ${ICONS.chevronRight}</span>`;
        }
        html += '</div></div>';

        // Detail grid
        html += '<div class="detail-grid">';
        html += detailRow('Hash', `<span class="mono">${escapeHtml(block.hash)}</span>${makeCopyButton(block.hash)}`);
        html += detailRow('Previous Hash', block.previousblockhash ?
            `<a href="#/block/${escapeHtml(block.previousblockhash)}" class="hash mono">${escapeHtml(block.previousblockhash)}</a>${makeCopyButton(block.previousblockhash)}` :
            '<span class="text-dim">Genesis Block</span>');
        html += detailRow('Next Hash', block.nextblockhash ?
            `<a href="#/block/${escapeHtml(block.nextblockhash)}" class="hash mono">${escapeHtml(block.nextblockhash)}</a>${makeCopyButton(block.nextblockhash)}` :
            '<span class="text-dim">N/A (latest block)</span>');
        html += detailRow('Merkle Root', `<span class="mono">${escapeHtml(block.merkleroot)}</span>${makeCopyButton(block.merkleroot)}`);
        html += detailRow('Timestamp', escapeHtml(formatAbsoluteTime(block.time)) + ' <span class="text-muted">(' + escapeHtml(formatTime(block.time)) + ')</span>');
        html += detailRow('Confirmations', `<span class="badge badge-success">${escapeHtml(formatNumber(block.confirmations))}</span>`);
        html += detailRow('Difficulty', escapeHtml(block.difficulty != null ? Number(block.difficulty).toFixed(8) : 'N/A'));

        const miner = extractMiner(block);
        html += detailRow('Miner', miner ?
            `<a href="#/address/${escapeHtml(miner)}" class="address">${escapeHtml(miner)}</a>${makeCopyButton(miner)}` :
            '<span class="text-dim">Unknown</span>');

        html += detailRow('Size', escapeHtml(formatSize(block.size)));
        html += detailRow('Nonce', `<span class="mono">${escapeHtml(String(block.nonce || ''))}</span>`);
        html += detailRow('nBits', `<span class="mono">${escapeHtml(block.bits || '')}</span>`);
        html += detailRow('Version', `<span class="mono">${escapeHtml(String(block.version || ''))}</span>`);
        html += '</div></div>';

        // Transactions
        const txs = block.tx || [];
        html += '<div class="card">';
        html += `<div class="card-header"><h2>Transactions (${txs.length})</h2></div>`;
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table">';
        html += '<thead><tr><th>#</th><th>TxID</th><th>From</th><th>To</th><th class="right">Amount</th></tr></thead>';
        html += '<tbody>';

        txs.forEach((tx, idx) => {
            if (typeof tx === 'string') {
                // verbosity=1 returns just txids
                html += `<tr><td>${idx + 1}</td><td><a href="#/tx/${escapeHtml(tx)}" class="hash">${escapeHtml(formatHash(tx, 12))}</a></td><td colspan="2" class="text-dim">Load transaction for details</td><td></td></tr>`;
                return;
            }

            const txid = tx.txid || tx.hash || '';
            const isCoinbase = tx.vin && tx.vin.length > 0 && tx.vin[0].coinbase;

            // From addresses
            let fromHtml = '';
            if (isCoinbase) {
                fromHtml = '<span class="coinbase-label">' + ICONS.pickaxe + ' Coinbase</span>';
            } else if (tx.vin) {
                const addrs = [];
                for (const vin of tx.vin) {
                    const addr = vin.prevout?.scriptPubKey?.address || vin.address;
                    if (addr && !addrs.includes(addr)) addrs.push(addr);
                }
                if (addrs.length > 0) {
                    fromHtml = addrs.map(a =>
                        `<a href="#/address/${escapeHtml(a)}" class="address">${escapeHtml(formatHash(a, 8))}</a>`
                    ).join(', ');
                } else {
                    fromHtml = '<span class="text-dim">N/A</span>';
                }
            }

            // To addresses and amount
            let toHtml = '';
            let totalOut = 0;
            if (tx.vout) {
                const addrs = [];
                for (const vout of tx.vout) {
                    totalOut += vout.value || 0;
                    const addr = vout.scriptPubKey?.address || vout.scriptPubKey?.addresses?.[0];
                    if (addr && !addrs.includes(addr)) addrs.push(addr);
                }
                toHtml = addrs.slice(0, 3).map(a =>
                    `<a href="#/address/${escapeHtml(a)}" class="address">${escapeHtml(formatHash(a, 8))}</a>`
                ).join(', ');
                if (addrs.length > 3) toHtml += ` <span class="text-dim">+${addrs.length - 3} more</span>`;
            }

            html += `<tr>`;
            html += `<td>${idx + 1}</td>`;
            html += `<td><a href="#/tx/${escapeHtml(txid)}" class="hash">${escapeHtml(formatHash(txid, 12))}</a></td>`;
            html += `<td>${fromHtml}</td>`;
            html += `<td>${toHtml}</td>`;
            html += `<td class="right amount">${escapeHtml(formatAmount(totalOut))} DIL</td>`;
            html += `</tr>`;
        });

        html += '</tbody></table></div></div></div>';

        getApp().innerHTML = html;

    } catch (err) {
        showError('Block Not Found', err.message);
    }
}

function detailRow(label, valueHtml) {
    return `<div class="detail-row"><div class="detail-label">${escapeHtml(label)}</div><div class="detail-value">${valueHtml}</div></div>`;
}

// ============================================================
// View: Transaction Detail
// ============================================================

async function renderTransaction(txid) {
    setTitle('Transaction ' + formatHash(txid, 12));
    showLoading();

    try {
        const data = await apiFetch('/tx.php?txid=' + encodeURIComponent(txid));
        const tx = data.transaction;
        if (!tx) throw new Error('Transaction not found');

        const realTxid = tx.txid || tx.hash || txid;
        setTitle('TX ' + formatHash(realTxid, 10));

        const isCoinbase = tx.vin && tx.vin.length > 0 && (tx.vin[0].coinbase || tx.vin[0].txid === '0000000000000000000000000000000000000000000000000000000000000000');
        const confirmations = tx.confirmations || 0;

        let html = '';

        // Breadcrumb
        html += breadcrumb([
            { label: 'Home', href: '#/' },
            { label: 'Transaction' },
        ]);

        // Main card
        html += '<div class="card">';
        html += '<div class="card-header"><h2>Transaction Details</h2>';
        if (confirmations > 0) {
            html += `<span class="badge badge-success">Confirmed (${formatNumber(confirmations)} confirmations)</span>`;
        } else {
            html += '<span class="badge badge-warning">Pending</span>';
        }
        html += '</div>';

        // Detail grid
        html += '<div class="detail-grid">';
        html += detailRow('TxID', `<span class="mono">${escapeHtml(realTxid)}</span>${makeCopyButton(realTxid)}`);

        if (tx.blockhash) {
            html += detailRow('Block', `<a href="#/block/${escapeHtml(tx.blockhash)}" class="hash mono">${escapeHtml(formatHash(tx.blockhash, 16))}</a>`);
        }
        if (tx.blockheight != null) {
            html += detailRow('Block Height', `<a href="#/block/${tx.blockheight}">${formatNumber(tx.blockheight)}</a>`);
        }
        if (tx.time || tx.blocktime) {
            html += detailRow('Timestamp', escapeHtml(formatAbsoluteTime(tx.time || tx.blocktime)));
        }
        html += detailRow('Confirmations', confirmations > 0 ? formatNumber(confirmations) : '<span class="text-warning">Unconfirmed</span>');
        html += detailRow('Version', `<span class="mono">${escapeHtml(String(tx.version || ''))}</span>`);
        html += detailRow('Lock Time', `<span class="mono">${escapeHtml(String(tx.locktime || 0))}</span>`);
        html += '</div></div>';

        // Inputs / Outputs visualization
        html += '<div class="card">';
        html += '<div class="card-header"><h2>Inputs &amp; Outputs</h2></div>';
        html += '<div class="card-body">';
        html += '<div class="tx-io">';

        // Inputs
        html += '<div class="tx-io-inputs">';
        html += '<div class="tx-io-label">Inputs</div>';
        if (isCoinbase) {
            html += '<div class="tx-io-item"><span class="coinbase-label">' + ICONS.pickaxe + ' Coinbase (Newly Generated Coins)</span></div>';
        } else if (tx.vin) {
            let totalIn = 0;
            for (const vin of tx.vin) {
                const addr = vin.prevout?.scriptPubKey?.address || vin.address || null;
                const val = vin.prevout?.value || vin.value || 0;
                totalIn += val;
                html += '<div class="tx-io-item">';
                if (addr) {
                    html += `<a href="#/address/${escapeHtml(addr)}" class="address">${escapeHtml(formatHash(addr, 10))}</a>`;
                } else {
                    html += '<span class="text-dim">Unknown</span>';
                }
                html += `<span class="amount">${escapeHtml(formatAmount(val))} DIL</span>`;
                html += '</div>';
            }
        }
        html += '</div>';

        // Arrow
        html += `<div class="tx-io-arrow">${ICONS.arrow}</div>`;

        // Outputs
        html += '<div class="tx-io-outputs">';
        html += '<div class="tx-io-label">Outputs</div>';
        let totalOut = 0;
        if (tx.vout) {
            for (const vout of tx.vout) {
                const addr = vout.scriptPubKey?.address || vout.scriptPubKey?.addresses?.[0] || null;
                const val = vout.value || 0;
                totalOut += val;
                html += '<div class="tx-io-item">';
                if (addr) {
                    html += `<a href="#/address/${escapeHtml(addr)}" class="address">${escapeHtml(formatHash(addr, 10))}</a>`;
                } else {
                    html += '<span class="text-dim">OP_RETURN / Unknown</span>';
                }
                html += `<span class="amount">${escapeHtml(formatAmount(val))} DIL</span>`;
                html += '</div>';
            }
        }
        html += '</div>';
        html += '</div>'; // tx-io
        html += '</div>'; // card-body

        // Summary bar
        let totalIn = 0;
        if (!isCoinbase && tx.vin) {
            for (const vin of tx.vin) {
                totalIn += vin.prevout?.value || vin.value || 0;
            }
        }
        const fee = isCoinbase ? 0 : Math.max(0, totalIn - totalOut);

        html += '<div class="summary-bar">';
        if (!isCoinbase) {
            html += `<span><span class="label">Total Input: </span><span class="value">${escapeHtml(formatAmount(totalIn))} DIL</span></span>`;
        }
        html += `<span><span class="label">Total Output: </span><span class="value">${escapeHtml(formatAmount(totalOut))} DIL</span></span>`;
        if (!isCoinbase) {
            html += `<span><span class="label">Fee: </span><span class="value">${escapeHtml(formatAmount(fee))} DIL</span></span>`;
        }
        html += '</div>';
        html += '</div>';

        getApp().innerHTML = html;

    } catch (err) {
        showError('Transaction Not Found', err.message);
    }
}

// ============================================================
// View: Address
// ============================================================

async function renderAddress(addr) {
    setTitle('Address ' + formatHash(addr, 10));
    showLoading();

    try {
        const data = await apiFetch('/address.php?addr=' + encodeURIComponent(addr));

        let html = '';

        // Breadcrumb
        html += breadcrumb([
            { label: 'Home', href: '#/' },
            { label: 'Address' },
        ]);

        // Address overview card
        html += '<div class="card">';
        html += '<div class="card-header"><h2>Address</h2></div>';
        html += '<div class="detail-grid">';
        html += detailRow('Address', `<span class="mono address" style="color:var(--accent)">${escapeHtml(data.address)}</span>${makeCopyButton(data.address)}`);

        const balance = data.balance;
        if (balance !== null && balance !== undefined) {
            // Balance could be in satoshis or DIL depending on the REST API
            const balanceDisplay = typeof balance === 'object' ?
                formatAmount(balance.balance || balance.confirmed || 0) :
                formatAmount(balance);
            html += detailRow('Balance', `<span class="font-bold" style="font-size:18px">${escapeHtml(balanceDisplay)} DIL</span>`);
        } else {
            html += detailRow('Balance', '<span class="text-dim">Unable to fetch balance</span>');
        }

        const utxos = data.utxos;
        const utxoList = Array.isArray(utxos) ? utxos : (utxos?.utxos || []);
        html += detailRow('UTXO Count', String(utxoList.length));
        html += '</div></div>';

        // UTXO table
        if (utxoList.length > 0) {
            html += '<div class="card">';
            html += `<div class="card-header"><h2>UTXOs (${utxoList.length})</h2></div>`;
            html += '<div class="card-body-flush"><div class="table-container">';
            html += '<table class="data-table">';
            html += '<thead><tr><th>TxID</th><th class="center">Output Index</th><th class="right">Amount</th><th class="center">Confirmations</th></tr></thead>';
            html += '<tbody>';

            for (const utxo of utxoList) {
                const utxoTxid = utxo.txid || utxo.tx_hash || '';
                const voutIdx = utxo.vout != null ? utxo.vout : (utxo.tx_pos != null ? utxo.tx_pos : '');
                const amount = utxo.value != null ? utxo.value : (utxo.amount || 0);
                const confs = utxo.confirmations || '';

                html += '<tr>';
                html += `<td><a href="#/tx/${escapeHtml(utxoTxid)}" class="hash">${escapeHtml(formatHash(utxoTxid, 12))}</a></td>`;
                html += `<td class="center">${escapeHtml(String(voutIdx))}</td>`;
                html += `<td class="right amount">${escapeHtml(formatAmount(amount))} DIL</td>`;
                html += `<td class="center">${confs ? escapeHtml(formatNumber(confs)) : '<span class="text-dim">N/A</span>'}</td>`;
                html += '</tr>';
            }

            html += '</tbody></table></div></div></div>';
        } else {
            html += '<div class="card"><div class="card-body"><div class="empty-state">No UTXOs found for this address.</div></div></div>';
        }

        getApp().innerHTML = html;

    } catch (err) {
        showError('Address Error', err.message);
    }
}

// ============================================================
// View: Block List (paginated)
// ============================================================

async function renderBlockList(page) {
    page = page || 1;
    setTitle('Blocks - Page ' + page);
    showLoading();

    try {
        const data = await apiFetch('/blocks.php?page=' + page + '&limit=' + ITEMS_PER_PAGE);
        const blocks = data.blocks || [];
        const totalHeight = data.totalHeight || 0;
        const totalPages = Math.ceil((totalHeight + 1) / ITEMS_PER_PAGE);

        let html = '';

        html += '<div class="page-header"><h1>All Blocks</h1><p>' + formatNumber(totalHeight + 1) + ' blocks on the Dilithion blockchain</p></div>';

        html += '<div class="card">';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table">';
        html += '<thead><tr><th>Height</th><th>Hash</th><th>Time</th><th>Miner</th><th class="center">Txs</th><th class="right">Reward</th><th class="right">Size</th></tr></thead>';
        html += '<tbody>';

        for (const block of blocks) {
            const height = block.height;
            const hash = block.hash || '';
            const time = block.time || 0;
            const txCount = block.nTx || block.tx_count || (block.tx ? block.tx.length : 0);
            const miner = extractMiner(block);
            const reward = extractReward(block);

            html += '<tr>';
            html += `<td><a href="#/block/${height}">${formatNumber(height)}</a></td>`;
            html += `<td><a href="#/block/${escapeHtml(hash)}" class="hash">${escapeHtml(formatHash(hash, 8))}</a></td>`;
            html += `<td title="${escapeHtml(formatAbsoluteTime(time))}">${escapeHtml(formatTime(time))}</td>`;
            html += `<td>${miner ? `<a href="#/address/${escapeHtml(miner)}" class="address">${escapeHtml(formatHash(miner, 6))}</a>` : '<span class="text-dim">Unknown</span>'}</td>`;
            html += `<td class="center">${txCount}</td>`;
            html += `<td class="right amount">${reward != null ? escapeHtml(formatAmount(reward)) + ' DIL' : ''}</td>`;
            html += `<td class="right text-muted">${block.size ? escapeHtml(formatSize(block.size)) : ''}</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div>';

        // Pagination
        html += '<div class="pagination">';

        if (page > 1) {
            html += `<a href="#/blocks/${page - 1}">${ICONS.chevronLeft} Prev</a>`;
        } else {
            html += `<span class="disabled">${ICONS.chevronLeft} Prev</span>`;
        }

        // Page numbers
        const maxVisible = 5;
        let startPage = Math.max(1, page - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        if (endPage - startPage < maxVisible - 1) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }

        if (startPage > 1) {
            html += `<a href="#/blocks/1">1</a>`;
            if (startPage > 2) html += `<span class="disabled">...</span>`;
        }

        for (let i = startPage; i <= endPage; i++) {
            if (i === page) {
                html += `<span class="active">${i}</span>`;
            } else {
                html += `<a href="#/blocks/${i}">${i}</a>`;
            }
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) html += `<span class="disabled">...</span>`;
            html += `<a href="#/blocks/${totalPages}">${totalPages}</a>`;
        }

        if (page < totalPages) {
            html += `<a href="#/blocks/${page + 1}">Next ${ICONS.chevronRight}</a>`;
        } else {
            html += `<span class="disabled">Next ${ICONS.chevronRight}</span>`;
        }

        html += '</div></div>';

        getApp().innerHTML = html;

    } catch (err) {
        showError('Failed to Load Blocks', err.message);
    }
}

// ============================================================
// View: Forks (Chain Tips)
// ============================================================

async function renderForks() {
    setTitle('Chain Tips');
    showLoading();

    try {
        const data = await apiFetch('/stats.php');
        const chainTips = data.chainTips || [];

        let html = '';

        html += '<div class="page-header"><h1>Chain Tips</h1><p>All known chain tips, including forks and the active best chain.</p></div>';

        html += '<div class="card">';
        html += '<div class="card-body-flush"><div class="table-container">';
        html += '<table class="data-table">';
        html += '<thead><tr><th>Status</th><th>Height</th><th>Hash</th><th class="center">Branch Length</th></tr></thead>';
        html += '<tbody>';

        if (chainTips.length === 0) {
            html += '<tr><td colspan="4" class="text-center text-dim" style="padding:30px">No chain tip data available</td></tr>';
        }

        for (const tip of chainTips) {
            const status = tip.status || 'unknown';
            let badgeClass = 'badge-muted';
            if (status === 'active') badgeClass = 'badge-success';
            else if (status === 'valid-fork') badgeClass = 'badge-warning';
            else if (status === 'valid-headers') badgeClass = 'badge-info';
            else if (status === 'headers-only') badgeClass = 'badge-info';
            else if (status === 'invalid') badgeClass = 'badge-danger';

            html += '<tr>';
            html += `<td><span class="badge ${badgeClass}">${escapeHtml(status)}</span></td>`;
            html += `<td><a href="#/block/${tip.height}">${formatNumber(tip.height)}</a></td>`;
            html += `<td><a href="#/block/${escapeHtml(tip.hash)}" class="hash">${escapeHtml(formatHash(tip.hash, 16))}</a></td>`;
            html += `<td class="center">${tip.branchlen != null ? tip.branchlen : 'N/A'}</td>`;
            html += '</tr>';
        }

        html += '</tbody></table></div></div>';

        // Explanation
        html += '<div class="info-text">';
        html += '<strong>What are chain tips?</strong> Chain tips represent the ends of all known blockchain branches. ';
        html += 'The <strong>"active"</strong> tip is the current best chain that nodes follow. ';
        html += '<strong>"valid-fork"</strong> tips are alternative chains with valid blocks that branched off from the main chain. ';
        html += '<strong>"valid-headers"</strong> means headers were received but blocks haven\'t been fully validated yet. ';
        html += 'A <strong>branch length</strong> of 0 means the tip is on the main chain.';
        html += '</div>';

        html += '</div>';

        getApp().innerHTML = html;

    } catch (err) {
        showError('Failed to Load Chain Tips', err.message);
    }
}

// ============================================================
// Search Handler
// ============================================================

async function handleSearch(query) {
    query = decodeURIComponent(query).trim();
    if (!query) {
        window.location.hash = '#/';
        return;
    }

    setTitle('Search: ' + query);
    showLoading();

    try {
        const data = await apiFetch('/search.php?q=' + encodeURIComponent(query));

        if (data.type === 'block') {
            const blockHash = data.result?.hash;
            const blockHeight = data.result?.height;
            window.location.hash = '#/block/' + (blockHeight != null ? blockHeight : blockHash);
            return;
        }

        if (data.type === 'tx') {
            const txid = data.result?.txid || data.result?.hash || query;
            window.location.hash = '#/tx/' + txid;
            return;
        }

        if (data.type === 'address') {
            const addr = data.result?.address || query;
            window.location.hash = '#/address/' + addr;
            return;
        }

        // Unknown
        showError('Not Found', data.message || 'No results found for "' + query + '". Try a block height, block hash, transaction ID, or address.');

    } catch (err) {
        showError('Search Failed', err.message);
    }
}

// ============================================================
// Search Bar Event Listeners
// ============================================================

function initSearchBar() {
    const input = document.getElementById('search-input');
    if (!input) return;

    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const query = input.value.trim();
            if (query) {
                window.location.hash = '#/search/' + encodeURIComponent(query);
                input.value = '';
                input.blur();
            }
        }
    });

    // Global keyboard shortcut: "/" focuses search
    document.addEventListener('keydown', function (e) {
        if (e.key === '/' && document.activeElement !== input && document.activeElement.tagName !== 'INPUT') {
            e.preventDefault();
            input.focus();
        }
    });
}

// ============================================================
// Init
// ============================================================

document.addEventListener('DOMContentLoaded', function () {
    initSearchBar();
    router.route();
});
