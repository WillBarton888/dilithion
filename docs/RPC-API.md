# Dilithion RPC API Documentation

**Version:** 1.0.0  
**Protocol:** JSON-RPC 2.0 over HTTP  
**Default Port:** 8332 (mainnet), 18332 (testnet)

## Table of Contents

- [Overview](#overview)
- [Connection & Authentication](#connection--authentication)
- [Wallet Information RPCs](#wallet-information-rpcs)
- [Transaction Creation RPCs](#transaction-creation-rpcs)
- [Transaction Query RPCs](#transaction-query-rpcs)
- [Blockchain Query RPCs](#blockchain-query-rpcs)
- [Wallet Encryption RPCs](#wallet-encryption-rpcs)
- [Mining RPCs](#mining-rpcs)
- [Network RPCs](#network-rpcs)
- [General RPCs](#general-rpcs)
- [Error Codes](#error-codes)

---

## Overview

The Dilithion RPC server provides a JSON-RPC 2.0 interface for interacting with the Dilithion node.

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "methodname",
  "params": {"param1": "value1"},
  "id": 1
}
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "result": {...},
  "id": 1
}
```

---

## Wallet Information RPCs

### getnewaddress

Get a new receiving address.

**Parameters:** None  
**Returns:** String (address)

**Example:**
```json
{"jsonrpc": "2.0", "method": "getnewaddress", "params": {}, "id": 1}
```

**Response:**
```json
{"jsonrpc": "2.0", "result": "DLT1abc123...", "id": 1}
```

---

### getbalance

Get wallet balance information.

**Parameters:** None  
**Returns:** Object with balance details

**Response:**
```json
{
  "balance": 12.34567890,
  "unconfirmed_balance": 0.50000000,
  "immature_balance": 50.00000000
}
```

---

### listunspent

List unspent transaction outputs.

**Parameters:** None  
**Returns:** Array of UTXOs

**Response:**
```json
[
  {
    "txid": "abc123...",
    "vout": 0,
    "address": "DLT1...",
    "amount": 1.50000000,
    "confirmations": 10
  }
]
```

---

## Transaction Creation RPCs

### sendtoaddress

Send coins to an address.

**Parameters:**
- `address` (string): Recipient address
- `amount` (number): Amount in DIL

**Returns:** `{"txid": "abc123..."}`

**Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "sendtoaddress",
  "params": {"address": "DLT1recipient...", "amount": 1.5},
  "id": 1
}
```

---

## Blockchain Query RPCs

### getblockchaininfo

Get blockchain information.

**Returns:**
```json
{
  "chain": "main",
  "blocks": 12345,
  "bestblockhash": "abc123...",
  "chainwork": "0000..."
}
```

---

### getblock

Get block by hash.

**Parameters:**
- `hash` (string): Block hash

**Returns:** Block object with details

---

### getblockhash

Get block hash by height.

**Parameters:**
- `height` (number): Block height

**Returns:** `{"blockhash": "abc123..."}`

---

### gettxout

Get UTXO information.

**Parameters:**
- `txid` (string): Transaction ID
- `n` (number): Output index

**Returns:** UTXO details or null if spent

---

## Complete API Reference

See full examples and all 20+ RPC methods in the implementation.

**Key Methods:**
- Wallet: getnewaddress, getbalance, listunspent, sendtoaddress
- Blockchain: getblockchaininfo, getblock, getblockhash, gettxout
- Transactions: gettransaction, listtransactions, getmempoolinfo
- Encryption: encryptwallet, walletpassphrase, walletlock
- Mining: getmininginfo, stopmining
- General: help, stop

---

**Currency:** 1 DIL = 100,000,000 ions  
**Last Updated:** 2025-10-27
