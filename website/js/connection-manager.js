/**
 * Connection Manager for Dilithion Light Wallet
 *
 * Handles switching between:
 * - Full Node mode: JSON-RPC to local node (uses node's wallet)
 * - Light Wallet mode: REST API to seed nodes (uses browser keys)
 *
 * Copyright (c) 2025 The Dilithion Core developers
 * Distributed under the MIT software license
 */

// Connection modes
const CONNECTION_MODE = {
    FULL: 'full',
    LIGHT: 'light'
};

// Default seed nodes (mainnet)
const DEFAULT_SEED_NODES = [
    { host: 'seed1.dilithion.org', port: 8332, region: 'US' },
    { host: 'seed2.dilithion.org', port: 8332, region: 'EU' },
    { host: 'seed3.dilithion.org', port: 8332, region: 'APAC' }
];

// Testnet seed nodes
const TESTNET_SEED_NODES = [
    { host: '134.122.4.164', port: 18332, region: 'US' },
    { host: '188.166.255.63', port: 18332, region: 'APAC' },
    { host: '209.97.177.197', port: 18332, region: 'EU' }
];

/**
 * Connection Manager class
 */
class ConnectionManager {
    constructor() {
        // Current mode
        this.mode = CONNECTION_MODE.FULL;

        // Full node settings
        this.rpcConfig = {
            host: '127.0.0.1',
            port: 8332,
            user: '',
            pass: ''
        };

        // Light wallet settings
        this.lightConfig = {
            seedNodes: DEFAULT_SEED_NODES,
            currentNode: null,
            testnet: false
        };

        // Connection state
        this.connected = false;
        this.chainInfo = null;
        this.lastError = null;

        // Event listeners
        this.listeners = {
            'connectionChange': [],
            'modeChange': [],
            'error': []
        };

        // Request timeout (ms)
        this.timeout = 10000;
    }

    /**
     * Initialize connection manager
     * Loads saved settings from localStorage
     */
    init() {
        this.loadSettings();
        console.log('[ConnectionManager] Initialized. Mode:', this.mode);
    }

    /**
     * Get current connection mode
     * @returns {string} 'full' or 'light'
     */
    getMode() {
        return this.mode;
    }

    /**
     * Check if connected
     * @returns {boolean}
     */
    isConnected() {
        return this.connected;
    }

    /**
     * Get chain info (from last successful connection)
     * @returns {Object|null}
     */
    getChainInfo() {
        return this.chainInfo;
    }

    /**
     * Set connection mode
     * @param {string} mode - 'full' or 'light'
     */
    async setMode(mode) {
        if (mode !== CONNECTION_MODE.FULL && mode !== CONNECTION_MODE.LIGHT) {
            throw new Error('Invalid mode: ' + mode);
        }

        const oldMode = this.mode;
        this.mode = mode;

        // Save setting
        this.saveSettings();

        // Find best seed node if switching to light mode
        if (mode === CONNECTION_MODE.LIGHT && !this.lightConfig.currentNode) {
            await this.findBestSeedNode();
        }

        // Emit event
        this.emit('modeChange', { oldMode, newMode: mode });

        console.log('[ConnectionManager] Mode changed from', oldMode, 'to', mode);
    }

    /**
     * Set RPC configuration for full node mode
     * @param {Object} config - {host, port, user, pass}
     */
    setRPCConfig(config) {
        this.rpcConfig = { ...this.rpcConfig, ...config };
        this.saveSettings();
    }

    /**
     * Set testnet mode
     * @param {boolean} testnet
     */
    setTestnet(testnet) {
        this.lightConfig.testnet = testnet;
        this.lightConfig.seedNodes = testnet ? TESTNET_SEED_NODES : DEFAULT_SEED_NODES;
        this.lightConfig.currentNode = null;  // Reset current node
        this.saveSettings();
    }

    /**
     * Find the best (fastest responding) seed node
     * @returns {Promise<Object>} Selected node
     */
    async findBestSeedNode() {
        const nodes = this.lightConfig.seedNodes;
        let bestNode = null;
        let bestLatency = Infinity;

        console.log('[ConnectionManager] Finding best seed node...');

        // Test each node in parallel
        const tests = nodes.map(async (node) => {
            const start = Date.now();
            try {
                const response = await this.fetchWithTimeout(
                    `http://${node.host}:${node.port}/api/v1/info`,
                    { method: 'GET' },
                    5000  // 5 second timeout for probe
                );

                if (response.ok) {
                    const latency = Date.now() - start;
                    console.log(`[ConnectionManager] ${node.host}: ${latency}ms`);
                    return { node, latency };
                }
            } catch (e) {
                console.log(`[ConnectionManager] ${node.host}: failed (${e.message})`);
            }
            return null;
        });

        const results = await Promise.all(tests);

        // Find best
        for (const result of results) {
            if (result && result.latency < bestLatency) {
                bestLatency = result.latency;
                bestNode = result.node;
            }
        }

        if (bestNode) {
            this.lightConfig.currentNode = bestNode;
            console.log('[ConnectionManager] Selected node:', bestNode.host, '(' + bestLatency + 'ms)');
        } else {
            console.error('[ConnectionManager] No seed nodes available');
            this.emit('error', new Error('No seed nodes available'));
        }

        return bestNode;
    }

    /**
     * Connect to node (test connection)
     * @returns {Promise<Object>} Chain info
     */
    async connect() {
        this.connected = false;
        this.lastError = null;

        try {
            if (this.mode === CONNECTION_MODE.FULL) {
                // Full node: use JSON-RPC
                this.chainInfo = await this.rpcCall('getblockchaininfo');
            } else {
                // Light wallet: use REST API
                if (!this.lightConfig.currentNode) {
                    await this.findBestSeedNode();
                }
                if (!this.lightConfig.currentNode) {
                    throw new Error('No seed node available');
                }
                this.chainInfo = await this.restCall('/api/v1/info');
            }

            this.connected = true;
            this.emit('connectionChange', { connected: true, chainInfo: this.chainInfo });

            console.log('[ConnectionManager] Connected. Chain:', this.chainInfo.chain);
            return this.chainInfo;

        } catch (e) {
            this.lastError = e;
            this.connected = false;
            this.emit('connectionChange', { connected: false, error: e });
            throw e;
        }
    }

    /**
     * Disconnect
     */
    disconnect() {
        this.connected = false;
        this.emit('connectionChange', { connected: false });
    }

    // ========================================================================
    // API Methods (unified interface)
    // ========================================================================

    /**
     * Get balance for address
     * @param {string} address - Dilithion address (for light mode)
     * @returns {Promise<Object>} Balance info
     */
    async getBalance(address) {
        if (this.mode === CONNECTION_MODE.FULL) {
            // Full node: use RPC (gets wallet total balance)
            return await this.rpcCall('getbalance');
        } else {
            // Light wallet: use REST API
            return await this.restCall(`/api/v1/balance/${address}`);
        }
    }

    /**
     * Get UTXOs for address
     * @param {string} address - Dilithion address
     * @returns {Promise<Object>} UTXOs
     */
    async getUTXOs(address) {
        if (this.mode === CONNECTION_MODE.FULL) {
            // Full node: use RPC
            return await this.rpcCall('listunspent', [0, 9999999, [address]]);
        } else {
            // Light wallet: use REST API
            return await this.restCall(`/api/v1/utxos/${address}`);
        }
    }

    /**
     * Get transaction details
     * @param {string} txid - Transaction ID
     * @returns {Promise<Object>} Transaction details
     */
    async getTransaction(txid) {
        if (this.mode === CONNECTION_MODE.FULL) {
            return await this.rpcCall('gettransaction', [txid]);
        } else {
            return await this.restCall(`/api/v1/tx/${txid}`);
        }
    }

    /**
     * Get blockchain info
     * @returns {Promise<Object>} Blockchain info
     */
    async getBlockchainInfo() {
        if (this.mode === CONNECTION_MODE.FULL) {
            return await this.rpcCall('getblockchaininfo');
        } else {
            return await this.restCall('/api/v1/info');
        }
    }

    /**
     * Get recommended fee rate
     * @returns {Promise<Object>} Fee rate info
     */
    async getFeeRate() {
        if (this.mode === CONNECTION_MODE.FULL) {
            // Full node: estimate fee
            try {
                const result = await this.rpcCall('estimatefee', [6]);
                return { recommended: result, minimum: result * 0.5 };
            } catch (e) {
                // Default fee if estimation fails
                return { recommended: 1000, minimum: 500 };
            }
        } else {
            return await this.restCall('/api/v1/fee');
        }
    }

    /**
     * Broadcast signed transaction
     * @param {string} rawTx - Hex-encoded signed transaction
     * @returns {Promise<Object>} {txid, accepted}
     */
    async broadcast(rawTx) {
        if (this.mode === CONNECTION_MODE.FULL) {
            const txid = await this.rpcCall('sendrawtransaction', [rawTx]);
            return { txid, accepted: true };
        } else {
            return await this.restCall('/api/v1/broadcast', 'POST', { rawtx: rawTx });
        }
    }

    /**
     * Get new address (full node only)
     * @returns {Promise<string>} New address
     */
    async getNewAddress() {
        if (this.mode === CONNECTION_MODE.LIGHT) {
            throw new Error('getNewAddress not available in light wallet mode. Use local key generation.');
        }
        return await this.rpcCall('getnewaddress');
    }

    /**
     * Send to address (full node only)
     * In light mode, use TransactionBuilder instead
     */
    async sendToAddress(address, amount) {
        if (this.mode === CONNECTION_MODE.LIGHT) {
            throw new Error('sendToAddress not available in light wallet mode. Use TransactionBuilder.');
        }
        return await this.rpcCall('sendtoaddress', [address, amount]);
    }

    // ========================================================================
    // Low-level call methods
    // ========================================================================

    /**
     * Make JSON-RPC call to full node
     * @param {string} method - RPC method
     * @param {Array} params - Parameters
     * @returns {Promise<any>} Result
     */
    async rpcCall(method, params = []) {
        const url = `http://${this.rpcConfig.host}:${this.rpcConfig.port}/`;
        const headers = {
            'Content-Type': 'application/json',
            'X-Dilithion-RPC': '1'  // CSRF protection
        };

        if (this.rpcConfig.user && this.rpcConfig.pass) {
            headers['Authorization'] = 'Basic ' + btoa(this.rpcConfig.user + ':' + this.rpcConfig.pass);
        }

        const response = await this.fetchWithTimeout(url, {
            method: 'POST',
            headers,
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: Date.now(),
                method,
                params
            })
        }, this.timeout);

        const data = await response.json();

        if (data.error) {
            const err = new Error(data.error.message || 'RPC Error');
            err.code = data.error.code;
            throw err;
        }

        return data.result;
    }

    /**
     * Make REST API call to seed node
     * @param {string} path - API path (e.g., '/api/v1/info')
     * @param {string} method - HTTP method
     * @param {Object} body - Request body (for POST)
     * @returns {Promise<Object>} Response data
     */
    async restCall(path, method = 'GET', body = null) {
        if (!this.lightConfig.currentNode) {
            throw new Error('No seed node selected');
        }

        const node = this.lightConfig.currentNode;
        const url = `http://${node.host}:${node.port}${path}`;

        const options = {
            method,
            headers: {
                'Accept': 'application/json'
            }
        };

        if (body) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }

        const response = await this.fetchWithTimeout(url, options, this.timeout);

        if (!response.ok) {
            // Handle error responses
            let errorMessage = `HTTP ${response.status}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorData.message || errorMessage;
            } catch (e) {}

            const err = new Error(errorMessage);
            err.status = response.status;
            throw err;
        }

        return await response.json();
    }

    /**
     * Fetch with timeout
     * @param {string} url - URL to fetch
     * @param {Object} options - Fetch options
     * @param {number} timeout - Timeout in ms
     * @returns {Promise<Response>}
     */
    async fetchWithTimeout(url, options, timeout) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return response;
        } catch (e) {
            clearTimeout(timeoutId);
            if (e.name === 'AbortError') {
                throw new Error('Request timed out');
            }
            throw e;
        }
    }

    // ========================================================================
    // Settings persistence
    // ========================================================================

    /**
     * Load settings from localStorage
     */
    loadSettings() {
        try {
            // Load mode
            const savedMode = localStorage.getItem('dilithionWalletMode');
            if (savedMode === CONNECTION_MODE.LIGHT) {
                this.mode = CONNECTION_MODE.LIGHT;
            }

            // Load RPC config
            const savedRpc = localStorage.getItem('dilithionWalletConfig');
            if (savedRpc) {
                this.rpcConfig = JSON.parse(savedRpc);
            }

            // Load light config
            const savedLight = localStorage.getItem('dilithionLightConfig');
            if (savedLight) {
                const config = JSON.parse(savedLight);
                this.lightConfig.testnet = config.testnet || false;
                if (config.testnet) {
                    this.lightConfig.seedNodes = TESTNET_SEED_NODES;
                }
            }
        } catch (e) {
            console.error('[ConnectionManager] Failed to load settings:', e);
        }
    }

    /**
     * Save settings to localStorage
     */
    saveSettings() {
        try {
            localStorage.setItem('dilithionWalletMode', this.mode);
            localStorage.setItem('dilithionWalletConfig', JSON.stringify(this.rpcConfig));
            localStorage.setItem('dilithionLightConfig', JSON.stringify({
                testnet: this.lightConfig.testnet
            }));
        } catch (e) {
            console.error('[ConnectionManager] Failed to save settings:', e);
        }
    }

    // ========================================================================
    // Event handling
    // ========================================================================

    /**
     * Add event listener
     * @param {string} event - Event name
     * @param {Function} callback - Callback function
     */
    on(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event].push(callback);
        }
    }

    /**
     * Remove event listener
     * @param {string} event - Event name
     * @param {Function} callback - Callback to remove
     */
    off(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
        }
    }

    /**
     * Emit event
     * @param {string} event - Event name
     * @param {any} data - Event data
     */
    emit(event, data) {
        if (this.listeners[event]) {
            for (const callback of this.listeners[event]) {
                try {
                    callback(data);
                } catch (e) {
                    console.error('[ConnectionManager] Event handler error:', e);
                }
            }
        }
    }
}

// Export for both module and browser use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ConnectionManager, CONNECTION_MODE };
} else if (typeof window !== 'undefined') {
    window.ConnectionManager = ConnectionManager;
    window.CONNECTION_MODE = CONNECTION_MODE;
}
