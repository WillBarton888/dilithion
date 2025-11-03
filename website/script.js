/**
 * Dilithion Website - JavaScript
 * Countdown timer and live dashboard functionality
 */

// Configuration
const TESTNET_LAUNCH_DATE = 1762041600000; // Nov 2, 2025 00:00:00 UTC
const MAINNET_LAUNCH_DATE = 1767225600000; // Jan 1, 2026 00:00:00 UTC
const RPC_ENDPOINT = 'http://localhost:8332';
const STATS_JSON_URL = 'https://dilithion.org/network-stats.json';
const UPDATE_INTERVAL = 30000;

// State
let isNetworkLive = false;
let dashboardUpdateInterval = null;

/**
 * Countdown Timer
 */
function updateCountdown() {
    const now = new Date().getTime();
    const distance = MAINNET_LAUNCH_DATE - now; // Count down to mainnet launch

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
        statusText.textContent = 'Testnet: LIVE NOW | Mainnet: January 1, 2026';
    } else {
        statusDot.classList.remove('live');
        statusText.textContent = 'Testnet: LIVE NOW | Mainnet: January 1, 2026';
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
 * Fetch network stats from static JSON file
 */
async function fetchNetworkStats() {
    try {
        const response = await fetch(STATS_JSON_URL + '?t=' + Date.now(), {
            cache: 'no-store'
        });

        if (!response.ok) {
            throw new Error('Stats file not available');
        }

        const stats = await response.json();
        return stats;
    } catch (error) {
        console.log('Static stats not available, trying RPC:', error.message);
        return null;
    }
}

/**
 * Update dashboard with live network data
 */
async function updateDashboard() {
    try {
        // Try fetching from static JSON first (for public website)
        let stats = await fetchNetworkStats();

        if (stats) {
            // Use static JSON data
            updateDashboardFromStats(stats);
            return;
        }

        // Fallback to direct RPC (for local node users)
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
 * Update dashboard from static stats JSON
 */
function updateDashboardFromStats(stats) {
    // Update network status to live
    if (!isNetworkLive && stats.status === 'live') {
        updateNetworkStatus(true);
    }

    // Update block height
    if (stats.blockHeight !== undefined) {
        document.getElementById('block-height').textContent =
            stats.blockHeight.toLocaleString();
    }

    // Update difficulty
    if (stats.difficulty !== undefined) {
        document.getElementById('difficulty').textContent =
            formatNumber(stats.difficulty);
    }

    // Update hash rate
    if (stats.networkHashRate !== undefined) {
        document.getElementById('hash-rate').textContent =
            formatHashRate(stats.networkHashRate);
    }

    // Update total supply
    if (stats.totalSupply !== undefined) {
        document.getElementById('total-supply').textContent =
            stats.totalSupply.toLocaleString() + ' DIL';
    }

    // Update block reward
    if (stats.blockReward !== undefined) {
        document.getElementById('block-reward').textContent =
            stats.blockReward + ' DIL';
    }

    // Update next halving
    if (stats.blocksUntilHalving !== undefined) {
        document.getElementById('next-halving').textContent =
            stats.blocksUntilHalving.toLocaleString() + ' blocks';
    }

    // Update last update time
    if (stats.timestamp) {
        const statsTime = new Date(stats.timestamp);
        const now = new Date();
        const secondsAgo = Math.floor((now - statsTime) / 1000);

        let timeAgo = 'Just now';
        if (secondsAgo > 60) {
            const minutesAgo = Math.floor(secondsAgo / 60);
            timeAgo = minutesAgo + ' min ago';
        } else if (secondsAgo > 5) {
            timeAgo = secondsAgo + ' sec ago';
        }

        document.getElementById('last-block-time').textContent = timeAgo;
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

    // Check if testnet is already live (separate from mainnet countdown)
    const now = new Date().getTime();
    if (now >= TESTNET_LAUNCH_DATE) {
        // Testnet is live - start showing stats immediately
        updateNetworkStatus(true);
        startDashboardUpdates();
    } else {
        // Schedule dashboard start for testnet launch time
        const timeUntilLaunch = TESTNET_LAUNCH_DATE - now;
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

/**
 * Mobile Menu Functionality
 */
function initMobileMenu() {
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const navLinks = document.getElementById('navLinks');
    const menuIcon = document.getElementById('menuIcon');
    const closeIcon = document.getElementById('closeIcon');

    if (!mobileMenuBtn || !navLinks) return;

    // Toggle mobile menu
    mobileMenuBtn.addEventListener('click', function() {
        const isExpanded = this.getAttribute('aria-expanded') === 'true';

        // Toggle menu state
        this.setAttribute('aria-expanded', !isExpanded);
        navLinks.classList.toggle('active');
        document.body.classList.toggle('menu-open');

        // Toggle icons
        if (menuIcon && closeIcon) {
            menuIcon.style.display = isExpanded ? 'block' : 'none';
            closeIcon.style.display = isExpanded ? 'none' : 'block';
        }
    });

    // Close mobile menu when clicking on a link
    const navLinksAll = navLinks.querySelectorAll('a');
    navLinksAll.forEach(link => {
        link.addEventListener('click', function() {
            navLinks.classList.remove('active');
            document.body.classList.remove('menu-open');
            mobileMenuBtn.setAttribute('aria-expanded', 'false');

            if (menuIcon && closeIcon) {
                menuIcon.style.display = 'block';
                closeIcon.style.display = 'none';
            }
        });
    });

    // Close mobile menu when clicking outside
    document.addEventListener('click', function(event) {
        if (!navLinks.contains(event.target) && !mobileMenuBtn.contains(event.target)) {
            if (navLinks.classList.contains('active')) {
                navLinks.classList.remove('active');
                document.body.classList.remove('menu-open');
                mobileMenuBtn.setAttribute('aria-expanded', 'false');

                if (menuIcon && closeIcon) {
                    menuIcon.style.display = 'block';
                    closeIcon.style.display = 'none';
                }
            }
        }
    });

    // Close mobile menu on escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && navLinks.classList.contains('active')) {
            navLinks.classList.remove('active');
            document.body.classList.remove('menu-open');
            mobileMenuBtn.setAttribute('aria-expanded', 'false');

            if (menuIcon && closeIcon) {
                menuIcon.style.display = 'block';
                closeIcon.style.display = 'none';
            }
        }
    });
}

// Initialize mobile menu when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initMobileMenu();
    initFAQ();
    initNewsletter();
});

/**
 * FAQ Accordion Functionality
 */
function initFAQ() {
    const faqItems = document.querySelectorAll('.faq-item');

    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');

        question.addEventListener('click', () => {
            // Toggle active class
            const isActive = item.classList.contains('active');

            // Close all other FAQ items (optional - remove to allow multiple open)
            faqItems.forEach(otherItem => {
                if (otherItem !== item) {
                    otherItem.classList.remove('active');
                }
            });

            // Toggle current item
            if (isActive) {
                item.classList.remove('active');
            } else {
                item.classList.add('active');
            }
        });
    });
}

/**
 * Newsletter Form Handler
 */
function initNewsletter() {
    const form = document.getElementById('newsletterForm');
    if (!form) return;

    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const emailInput = this.querySelector('.newsletter-input');
        const email = emailInput.value.trim();

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showNewsletterMessage('Please enter a valid email address.', 'error');
            return;
        }

        // In production, this would send to a backend API or email service
        // For now, just show a success message
        console.log('Newsletter signup:', email);

        // Store in localStorage as placeholder (production would use real backend)
        const subscribers = JSON.parse(localStorage.getItem('dilithion_subscribers') || '[]');
        if (!subscribers.includes(email)) {
            subscribers.push(email);
            localStorage.setItem('dilithion_subscribers', JSON.stringify(subscribers));
        }

        // Show success message
        showNewsletterMessage('Success! You\'re subscribed to mainnet launch updates.', 'success');

        // Clear form
        emailInput.value = '';
    });
}

/**
 * Show newsletter feedback message
 */
function showNewsletterMessage(message, type) {
    const form = document.getElementById('newsletterForm');
    if (!form) return;

    // Remove existing message
    const existingMessage = form.parentElement.querySelector('.newsletter-message');
    if (existingMessage) {
        existingMessage.remove();
    }

    // Create message element
    const messageEl = document.createElement('div');
    messageEl.className = `newsletter-message newsletter-message-${type}`;
    messageEl.textContent = message;

    // Insert after form
    form.parentElement.insertBefore(messageEl, form.nextSibling);

    // Remove after 5 seconds
    setTimeout(() => {
        messageEl.remove();
    }, 5000);
}
