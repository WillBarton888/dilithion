/**
 * Transaction Builder for Dilithion Light Wallet
 *
 * Builds and signs transactions locally without exposing private keys to any server.
 * Uses the REST API to fetch UTXOs and broadcast signed transactions.
 *
 * Copyright (c) 2025 The Dilithion Core developers
 * Distributed under the MIT software license
 */

// Transaction constants
const TX_VERSION = 1;
const SEQUENCE_FINAL = 0xFFFFFFFF;

// Dilithium3 sizes
const DILITHIUM3_SIG_SIZE = 3309;
const DILITHIUM3_PK_SIZE = 1952;
const SCRIPTSIG_SIZE = 2 + DILITHIUM3_SIG_SIZE + 2 + DILITHIUM3_PK_SIZE;  // 5265 bytes

// Script opcodes
const OP_DUP = 0x76;
const OP_HASH160 = 0xA9;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xAC;

// Fee calculation constants
const MIN_FEE_RATE = 500;       // ions per KB
const DEFAULT_FEE_RATE = 1000;  // ions per KB
const DUST_THRESHOLD = 546;     // Minimum output value (ions)

/**
 * Transaction Builder class
 */
class TransactionBuilder {
    constructor(connectionManager, cryptoModule, localWallet) {
        this.conn = connectionManager || window.ConnectionManager && new window.ConnectionManager();
        this.crypto = cryptoModule || window.DilithiumCrypto;
        this.wallet = localWallet || window.LocalWallet && new window.LocalWallet();

        // Default fee rate (can be updated from network)
        this.feeRate = DEFAULT_FEE_RATE;
    }

    /**
     * Update fee rate from network
     */
    async updateFeeRate() {
        try {
            const feeInfo = await this.conn.getFeeRate();
            this.feeRate = feeInfo.recommended || DEFAULT_FEE_RATE;
            console.log('[TxBuilder] Fee rate updated:', this.feeRate, 'ions/KB');
        } catch (e) {
            console.warn('[TxBuilder] Failed to fetch fee rate, using default:', this.feeRate);
        }
    }

    /**
     * Estimate transaction size
     * @param {number} numInputs - Number of inputs
     * @param {number} numOutputs - Number of outputs
     * @returns {number} Estimated size in bytes
     */
    estimateSize(numInputs, numOutputs) {
        // Base transaction overhead
        // Version (4) + input count varint (1-3) + output count varint (1-3) + locktime (4)
        let size = 4 + 1 + 1 + 4;  // ~10 bytes

        // Each input: prevout (36) + scriptSig size varint (3) + scriptSig (5265) + sequence (4)
        size += numInputs * (36 + 3 + SCRIPTSIG_SIZE + 4);  // ~5308 bytes per input

        // Each output: value (8) + scriptPubKey size varint (1) + scriptPubKey (25)
        size += numOutputs * (8 + 1 + 25);  // 34 bytes per output

        return size;
    }

    /**
     * Calculate fee for transaction
     * @param {number} numInputs - Number of inputs
     * @param {number} numOutputs - Number of outputs
     * @returns {number} Fee in ions
     */
    calculateFee(numInputs, numOutputs) {
        const size = this.estimateSize(numInputs, numOutputs);
        // Fee rate is per KB (1000 bytes)
        return Math.ceil(size * this.feeRate / 1000);
    }

    /**
     * Select UTXOs for transaction (simple greedy algorithm)
     * @param {Array} utxos - Available UTXOs
     * @param {number} targetAmount - Amount to send (ions)
     * @param {number} estimatedFee - Estimated fee (ions)
     * @returns {Object} {selected: [], total: number, fee: number}
     */
    selectUTXOs(utxos, targetAmount, estimatedFee) {
        // Sort by amount descending (prefer larger UTXOs to minimize inputs)
        const sorted = [...utxos].sort((a, b) => b.amount - a.amount);

        const selected = [];
        let total = 0;

        for (const utxo of sorted) {
            // Skip dust outputs
            if (utxo.amount < DUST_THRESHOLD) {
                continue;
            }

            selected.push(utxo);
            total += utxo.amount;

            // Recalculate fee with current input count
            const fee = this.calculateFee(selected.length, 2);  // 2 outputs (recipient + change)

            if (total >= targetAmount + fee) {
                return { selected, total, fee };
            }
        }

        // Not enough funds
        const needed = targetAmount + this.calculateFee(selected.length || 1, 2);
        throw new Error(`Insufficient funds. Available: ${total} ions, needed: ${needed} ions`);
    }

    /**
     * Build a transaction
     * @param {Array} inputs - Selected UTXOs
     * @param {string} toAddress - Recipient address
     * @param {number} amount - Amount to send (ions)
     * @param {string} changeAddress - Change address
     * @param {number} changeAmount - Change amount (ions)
     * @returns {Object} Unsigned transaction object
     */
    buildTransaction(inputs, toAddress, amount, changeAddress, changeAmount) {
        // Validate addresses
        if (!this.crypto.validateAddress(toAddress)) {
            throw new Error('Invalid recipient address');
        }
        if (changeAmount > DUST_THRESHOLD && !this.crypto.validateAddress(changeAddress)) {
            throw new Error('Invalid change address');
        }

        // Build transaction object
        const tx = {
            version: TX_VERSION,
            inputs: [],
            outputs: [],
            lockTime: 0
        };

        // Add inputs
        for (const utxo of inputs) {
            tx.inputs.push({
                txid: utxo.txid,
                vout: utxo.vout,
                scriptSig: [],  // Empty, will be filled after signing
                sequence: SEQUENCE_FINAL
            });
        }

        // Add recipient output
        tx.outputs.push({
            value: amount,
            scriptPubKey: this.createScriptPubKey(toAddress)
        });

        // Add change output (if above dust threshold)
        if (changeAmount > DUST_THRESHOLD) {
            tx.outputs.push({
                value: changeAmount,
                scriptPubKey: this.createScriptPubKey(changeAddress)
            });
        }

        return tx;
    }

    /**
     * Create P2PKH scriptPubKey from address
     * @param {string} address - Dilithion address
     * @returns {Uint8Array} scriptPubKey
     */
    createScriptPubKey(address) {
        // Decode address to get pubkey hash
        const decoded = this.crypto.base58check_decode(address);
        const pubkeyHash = decoded.payload;

        // P2PKH: OP_DUP OP_HASH160 <hash_size> <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        const script = new Uint8Array(25);
        script[0] = OP_DUP;
        script[1] = OP_HASH160;
        script[2] = 20;  // 0x14 = 20 bytes
        script.set(pubkeyHash, 3);
        script[23] = OP_EQUALVERIFY;
        script[24] = OP_CHECKSIG;

        return script;
    }

    /**
     * Serialize transaction for signing (empty scriptSig)
     * @param {Object} tx - Transaction object
     * @returns {Uint8Array} Serialized transaction
     */
    serializeForSigning(tx) {
        const data = [];

        // Version (4 bytes, little-endian)
        this.pushUint32LE(data, tx.version);

        // Input count (varint)
        this.pushVarint(data, tx.inputs.length);

        // Inputs (with empty scriptSig)
        for (const input of tx.inputs) {
            // Prevout txid (32 bytes, reversed)
            const txidBytes = this.hexToBytes(input.txid);
            for (let i = 31; i >= 0; i--) {
                data.push(txidBytes[i]);
            }

            // Prevout vout (4 bytes, little-endian)
            this.pushUint32LE(data, input.vout);

            // Empty scriptSig
            this.pushVarint(data, 0);

            // Sequence (4 bytes, little-endian)
            this.pushUint32LE(data, input.sequence);
        }

        // Output count (varint)
        this.pushVarint(data, tx.outputs.length);

        // Outputs
        for (const output of tx.outputs) {
            // Value (8 bytes, little-endian)
            this.pushUint64LE(data, output.value);

            // scriptPubKey
            this.pushVarint(data, output.scriptPubKey.length);
            for (const b of output.scriptPubKey) {
                data.push(b);
            }
        }

        // Locktime (4 bytes, little-endian)
        this.pushUint32LE(data, tx.lockTime);

        return new Uint8Array(data);
    }

    /**
     * Sign transaction
     * @param {Object} tx - Transaction object
     * @param {Uint8Array} privateKey - Private key for signing
     * @param {Uint8Array} publicKey - Public key for scriptSig
     * @returns {Promise<Object>} Signed transaction
     */
    async signTransaction(tx, privateKey, publicKey) {
        // Compute signing hash
        const serialized = this.serializeForSigning(tx);
        const signingHash = this.crypto.sha3_256(serialized);

        // Sign with Dilithium
        const signature = await this.crypto.sign(signingHash, privateKey);

        if (signature.length !== DILITHIUM3_SIG_SIZE) {
            throw new Error(`Invalid signature size: ${signature.length}`);
        }
        if (publicKey.length !== DILITHIUM3_PK_SIZE) {
            throw new Error(`Invalid public key size: ${publicKey.length}`);
        }

        // Build scriptSig for all inputs (same signature for all in single-key spend)
        const scriptSig = this.buildScriptSig(signature, publicKey);

        // Clone transaction and add scriptSig to all inputs
        const signedTx = JSON.parse(JSON.stringify(tx));
        for (let i = 0; i < signedTx.inputs.length; i++) {
            signedTx.inputs[i].scriptSig = Array.from(scriptSig);
        }

        return signedTx;
    }

    /**
     * Build scriptSig from signature and public key
     * Format: [sig_size(2)] [signature] [pubkey_size(2)] [pubkey]
     * @param {Uint8Array} signature - Dilithium signature
     * @param {Uint8Array} publicKey - Public key
     * @returns {Uint8Array} scriptSig
     */
    buildScriptSig(signature, publicKey) {
        const scriptSig = new Uint8Array(2 + signature.length + 2 + publicKey.length);
        let pos = 0;

        // Signature size (2 bytes, little-endian)
        scriptSig[pos++] = signature.length & 0xFF;
        scriptSig[pos++] = (signature.length >> 8) & 0xFF;

        // Signature
        scriptSig.set(signature, pos);
        pos += signature.length;

        // Public key size (2 bytes, little-endian)
        scriptSig[pos++] = publicKey.length & 0xFF;
        scriptSig[pos++] = (publicKey.length >> 8) & 0xFF;

        // Public key
        scriptSig.set(publicKey, pos);

        return scriptSig;
    }

    /**
     * Serialize signed transaction to hex
     * @param {Object} tx - Signed transaction object
     * @returns {string} Hex-encoded transaction
     */
    serializeTransaction(tx) {
        const data = [];

        // Version (4 bytes, little-endian)
        this.pushUint32LE(data, tx.version);

        // Input count (varint)
        this.pushVarint(data, tx.inputs.length);

        // Inputs
        for (const input of tx.inputs) {
            // Prevout txid (32 bytes, reversed)
            const txidBytes = this.hexToBytes(input.txid);
            for (let i = 31; i >= 0; i--) {
                data.push(txidBytes[i]);
            }

            // Prevout vout (4 bytes, little-endian)
            this.pushUint32LE(data, input.vout);

            // scriptSig
            this.pushVarint(data, input.scriptSig.length);
            for (const b of input.scriptSig) {
                data.push(b);
            }

            // Sequence (4 bytes, little-endian)
            this.pushUint32LE(data, input.sequence);
        }

        // Output count (varint)
        this.pushVarint(data, tx.outputs.length);

        // Outputs
        for (const output of tx.outputs) {
            // Value (8 bytes, little-endian)
            this.pushUint64LE(data, output.value);

            // scriptPubKey
            this.pushVarint(data, output.scriptPubKey.length);
            for (const b of output.scriptPubKey) {
                data.push(b);
            }
        }

        // Locktime (4 bytes, little-endian)
        this.pushUint32LE(data, tx.lockTime);

        return this.bytesToHex(new Uint8Array(data));
    }

    /**
     * Send transaction (high-level API)
     * @param {string} fromAddress - Sender address (must be in wallet)
     * @param {string} toAddress - Recipient address
     * @param {number} amount - Amount to send (in DIL, not ions)
     * @returns {Promise<Object>} {txid, hex, fee}
     */
    async send(fromAddress, toAddress, amount) {
        // Convert to ions (1 DIL = 100,000,000 ions)
        const amountIons = Math.round(amount * 100000000);

        if (amountIons <= 0) {
            throw new Error('Amount must be greater than 0');
        }

        // Update fee rate
        await this.updateFeeRate();

        // Get UTXOs for address
        console.log('[TxBuilder] Fetching UTXOs for', fromAddress);
        const utxoResponse = await this.conn.getUTXOs(fromAddress);
        const utxos = utxoResponse.utxos || utxoResponse;

        if (!utxos || utxos.length === 0) {
            throw new Error('No UTXOs available for address');
        }

        // Select UTXOs
        const { selected, total, fee } = this.selectUTXOs(utxos, amountIons, 0);
        console.log('[TxBuilder] Selected', selected.length, 'UTXOs, total:', total, 'fee:', fee);

        // Calculate change
        const changeAmount = total - amountIons - fee;

        // Build transaction
        const tx = this.buildTransaction(selected, toAddress, amountIons, fromAddress, changeAmount);

        // Get private key and public key from wallet
        if (!this.wallet.isWalletUnlocked()) {
            throw new Error('Wallet is locked. Please unlock first.');
        }

        const privateKey = await this.wallet.getPrivateKey(fromAddress);

        // Derive public key from private key path
        const addresses = await this.wallet.getAddresses();
        const addrRecord = addresses.find(a => a.address === fromAddress);
        if (!addrRecord) {
            throw new Error('Address not found in wallet');
        }

        // Re-derive keys to get public key
        const keyData = await this.crypto.deriveChildKey(
            this.wallet.decryptedSeed,
            addrRecord.path
        );

        // Sign transaction
        console.log('[TxBuilder] Signing transaction...');
        const signedTx = await this.signTransaction(tx, privateKey, keyData.publicKey);

        // Serialize to hex
        const rawTx = this.serializeTransaction(signedTx);
        console.log('[TxBuilder] Transaction size:', rawTx.length / 2, 'bytes');

        // Broadcast
        console.log('[TxBuilder] Broadcasting transaction...');
        const result = await this.conn.broadcast(rawTx);

        console.log('[TxBuilder] Transaction broadcast:', result.txid);

        return {
            txid: result.txid,
            hex: rawTx,
            fee: fee / 100000000,  // Convert back to DIL
            feeIons: fee
        };
    }

    // ========================================================================
    // Helper functions
    // ========================================================================

    pushUint32LE(arr, value) {
        arr.push(value & 0xFF);
        arr.push((value >> 8) & 0xFF);
        arr.push((value >> 16) & 0xFF);
        arr.push((value >> 24) & 0xFF);
    }

    pushUint64LE(arr, value) {
        // JavaScript safe integer limit means we need to handle this carefully
        const low = value >>> 0;
        const high = Math.floor(value / 0x100000000) >>> 0;

        arr.push(low & 0xFF);
        arr.push((low >> 8) & 0xFF);
        arr.push((low >> 16) & 0xFF);
        arr.push((low >> 24) & 0xFF);
        arr.push(high & 0xFF);
        arr.push((high >> 8) & 0xFF);
        arr.push((high >> 16) & 0xFF);
        arr.push((high >> 24) & 0xFF);
    }

    pushVarint(arr, value) {
        if (value < 253) {
            arr.push(value);
        } else if (value <= 0xFFFF) {
            arr.push(253);
            arr.push(value & 0xFF);
            arr.push((value >> 8) & 0xFF);
        } else if (value <= 0xFFFFFFFF) {
            arr.push(254);
            this.pushUint32LE(arr, value);
        } else {
            arr.push(255);
            this.pushUint64LE(arr, value);
        }
    }

    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}

// Export for both module and browser use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = TransactionBuilder;
} else if (typeof window !== 'undefined') {
    window.TransactionBuilder = TransactionBuilder;
}
