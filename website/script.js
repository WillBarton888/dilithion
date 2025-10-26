/**
 * Dilithion Website - JavaScript
 * Countdown timer and live dashboard functionality
 */

// Configuration
const LAUNCH_DATE = new Date('2026-01-01T00:00:00Z').getTime();
const RPC_ENDPOINT = 'http://localhost:8332'; // Dilithion RPC endpoint
const UPDATE_INTERVAL = 5000; // Update dashboard every 5 seconds

// State
let isNetworkLive = false;
let dashboardUpdateInterval = null;

/**
 * Countdown Timer
 */
function updateCountdown() {
    const now = new Date().getTime();
    const distance = LAUNCH_DATE - now;

    // If countdown is finished
    if (distance < 0) {
        document.getElementById('days').textContent = '00';
        document.getElementById('hours').textContent = '00';
        document.getElementById('minutes').textContent = '00';
        document.getElementById('seconds').textContent = '00';

        // Update status to live
        updateNetworkStatus(true);

        // Start dashboard updates
        if (!dashboardUpdateInterval) {
            startDashboardUpdates();
        }
        return;
    }

    // Calculate time units
    const days = Math.floor(distance / (1000 * 60 * 60 * 24));
    const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((distance % (1000 * 60)) / 1000);

    // Update display
    document.getElementById('days').textContent = String(days).padStart(2, '0');
    document.getElementById('hours').textContent = String(hours).padStart(2, '0');
    document.getElementById('minutes').textContent = String(minutes).padStart(2, '0');
    document.getElementById('seconds').textContent = String(seconds).padStart(2, '0');
}

/**
 * Update network status indicator
 */
function updateNetworkStatus(live) {
    isNetworkLive = live;
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    if (live) {
        statusDot.classList.add('live');
        statusText.textContent = 'Network Live';
    } else {
        statusDot.classList.remove('live');
        statusText.textContent = 'Network launching January 1, 2026';
    }
}

/**
 * Fetch data from Dilithion RPC endpoint
 */
async function fetchRPCData(method, params = []) {
    try {
        const response = await fetch(RPC_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 'dilithion-website',
                method: method,
                params: params
            })
        });

        if (!response.ok) {
            throw new Error('RPC request failed');
        }

        const data = await response.json();
        return data.result;
    } catch (error) {
        console.log('RPC not available:', error.message);
        return null;
    }
}

/**
 * Update dashboard with live network data
 */
async function updateDashboard() {
    try {
        // Fetch blockchain info
        const blockchainInfo = await fetchRPCData('getblockchaininfo');

        if (!blockchainInfo) {
            // Network not available yet
            return;
        }

        // Update network status to live
        if (!isNetworkLive) {
            updateNetworkStatus(true);
        }

        // Update block height
        if (blockchainInfo.blocks !== undefined) {
            document.getElementById('block-height').textContent =
                blockchainInfo.blocks.toLocaleString();
        }

        // Update difficulty
        if (blockchainInfo.difficulty !== undefined) {
            document.getElementById('difficulty').textContent =
                formatNumber(blockchainInfo.difficulty);
        }

        // Fetch mining info for hash rate
        const miningInfo = await fetchRPCData('getmininginfo');
        if (miningInfo && miningInfo.networkhashps !== undefined) {
            document.getElementById('hash-rate').textContent =
                formatHashRate(miningInfo.networkhashps);
        }

        // Calculate total supply (blocks * current reward)
        if (blockchainInfo.blocks !== undefined) {
            const totalSupply = calculateTotalSupply(blockchainInfo.blocks);
            document.getElementById('total-supply').textContent =
                totalSupply.toLocaleString() + ' DIL';
        }

        // Calculate current block reward and next halving
        const blockHeight = blockchainInfo.blocks || 0;
        const currentReward = getCurrentBlockReward(blockHeight);
        const blocksUntilHalving = getBlocksUntilHalving(blockHeight);

        document.getElementById('block-reward').textContent = currentReward + ' DIL';
        document.getElementById('next-halving').textContent =
            blocksUntilHalving.toLocaleString() + ' blocks';

        // Fetch latest block for timestamp
        if (blockchainInfo.bestblockhash) {
            const block = await fetchRPCData('getblock', [blockchainInfo.bestblockhash]);
            if (block && block.time) {
                const blockTime = new Date(block.time * 1000);
                const now = new Date();
                const minutesAgo = Math.floor((now - blockTime) / 60000);

                document.getElementById('last-block-time').textContent =
                    minutesAgo === 0 ? 'Just now' : minutesAgo + ' min ago';
            }
        }

    } catch (error) {
        console.error('Dashboard update error:', error);
    }
}

/**
 * Calculate total supply based on block height
 */
function calculateTotalSupply(blockHeight) {
    let totalSupply = 0;
    let currentHeight = 0;
    let reward = 50; // Initial reward
    const halvingInterval = 210000;

    while (currentHeight < blockHeight) {
        const blocksInThisEra = Math.min(
            halvingInterval - (currentHeight % halvingInterval),
            blockHeight - currentHeight
        );
        totalSupply += blocksInThisEra * reward;
        currentHeight += blocksInThisEra;

        if (currentHeight % halvingInterval === 0 && currentHeight < blockHeight) {
            reward /= 2;
        }
    }

    return totalSupply;
}

/**
 * Get current block reward based on height
 */
function getCurrentBlockReward(blockHeight) {
    const halvings = Math.floor(blockHeight / 210000);
    const reward = 50 / Math.pow(2, halvings);
    return reward >= 0.00000001 ? reward : 0;
}

/**
 * Get blocks until next halving
 */
function getBlocksUntilHalving(blockHeight) {
    const halvingInterval = 210000;
    const nextHalvingBlock = Math.ceil((blockHeight + 1) / halvingInterval) * halvingInterval;
    return nextHalvingBlock - blockHeight;
}

/**
 * Format hash rate with appropriate units
 */
function formatHashRate(hashesPerSecond) {
    if (hashesPerSecond < 1000) {
        return hashesPerSecond.toFixed(2) + ' H/s';
    } else if (hashesPerSecond < 1000000) {
        return (hashesPerSecond / 1000).toFixed(2) + ' KH/s';
    } else if (hashesPerSecond < 1000000000) {
        return (hashesPerSecond / 1000000).toFixed(2) + ' MH/s';
    } else if (hashesPerSecond < 1000000000000) {
        return (hashesPerSecond / 1000000000).toFixed(2) + ' GH/s';
    } else {
        return (hashesPerSecond / 1000000000000).toFixed(2) + ' TH/s';
    }
}

/**
 * Format large numbers
 */
function formatNumber(num) {
    if (num < 1000) {
        return num.toFixed(2);
    } else if (num < 1000000) {
        return (num / 1000).toFixed(2) + 'K';
    } else if (num < 1000000000) {
        return (num / 1000000).toFixed(2) + 'M';
    } else {
        return (num / 1000000000).toFixed(2) + 'B';
    }
}

/**
 * Start dashboard updates
 */
function startDashboardUpdates() {
    // Initial update
    updateDashboard();

    // Schedule regular updates
    dashboardUpdateInterval = setInterval(updateDashboard, UPDATE_INTERVAL);
}

/**
 * Stop dashboard updates
 */
function stopDashboardUpdates() {
    if (dashboardUpdateInterval) {
        clearInterval(dashboardUpdateInterval);
        dashboardUpdateInterval = null;
    }
}

/**
 * Smooth scroll for navigation links
 */
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const href = this.getAttribute('href');

            // Skip if href is just "#"
            if (href === '#') {
                e.preventDefault();
                return;
            }

            const target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Start countdown timer
    updateCountdown();
    setInterval(updateCountdown, 1000);

    // Initialize smooth scrolling
    initSmoothScroll();

    // Check if network is already live
    const now = new Date().getTime();
    if (now >= LAUNCH_DATE) {
        updateNetworkStatus(true);
        startDashboardUpdates();
    } else {
        // Schedule dashboard start for launch time
        const timeUntilLaunch = LAUNCH_DATE - now;
        setTimeout(() => {
            updateNetworkStatus(true);
            startDashboardUpdates();
        }, timeUntilLaunch);
    }
});

/**
 * Cleanup on page unload
 */
window.addEventListener('beforeunload', function() {
    stopDashboardUpdates();
});
