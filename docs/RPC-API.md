# Dilithion RPC API Documentation

**Version:** 1.0.0
**Protocol:** JSON-RPC 2.0
**Transport:** HTTP
**Last Updated:** October 25, 2025

---

## Table of Contents

1. [Overview](#overview)
2. [Connection](#connection)
3. [Request Format](#request-format)
4. [Response Format](#response-format)
5. [Error Codes](#error-codes)
6. [Wallet Methods](#wallet-methods)
7. [Mining Methods](#mining-methods)
8. [Network Methods](#network-methods)
9. [General Methods](#general-methods)
10. [Code Examples](#code-examples)

---

## Overview

Dilithion provides a JSON-RPC 2.0 interface over HTTP for interacting with the node programmatically.

### Key Features

- **Standard Protocol:** JSON-RPC 2.0 compliant
- **HTTP Transport:** Easy integration with any language
- **Exchange-Ready:** Compatible with standard cryptocurrency exchange APIs
- **Secure:** Localhost-only by default

---

## Connection

### Endpoint

```
http://localhost:8332
```

### Authentication

**Current Version:** No authentication (localhost-only)

**Future:** HTTP Basic Auth or API keys (production deployments)

### Changing the Port

```bash
./dilithion-node --rpcport=9332
```

---

## Request Format

All requests must use **HTTP POST** with **JSON-RPC 2.0** format:

```json
{
  "jsonrpc": "2.0",
  "method": "<method_name>",
  "params": [<parameters>],
  "id": <request_id>
}
```

### Fields

- `jsonrpc`: Must be `"2.0"`
- `method`: RPC method name (string)
- `params`: Array of parameters (can be empty `[]`)
- `id`: Request identifier (number or string)

---

## Response Format

### Success Response

```json
{
  "jsonrpc": "2.0",
  "result": <result_value>,
  "id": <request_id>
}
```

### Error Response

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": <error_code>,
    "message": "<error_message>"
  },
  "id": <request_id>
}
```

---

## Error Codes

| Code | Message | Description |
|------|---------|-------------|
| `-32700` | Parse error | Invalid JSON |
| `-32600` | Invalid request | Invalid JSON-RPC format |
| `-32601` | Method not found | Unknown method |
| `-32602` | Invalid params | Invalid parameters |
| `-32603` | Internal error | Server error |

---

## Wallet Methods

### getnewaddress

Generate a new Dilithion address.

**Parameters:** None

**Returns:** String (Base58Check address)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "getnewaddress",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV",
  "id": 1
}
```

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnewaddress","params":[],"id":1}'
```

---

### getbalance

Get the wallet's total balance.

**Parameters:** None

**Returns:** Integer (balance in satoshis)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "getbalance",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": 1000000,
  "id": 1
}
```

**Note:** Balance is in satoshis (1 DIL = 100,000,000 satoshis)

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

---

### getaddresses

List all addresses in the wallet.

**Parameters:** None

**Returns:** Array of strings (addresses)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "getaddresses",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    "D7JS1ujrYsqZrb8p6H5TuSKKbqYPMbwjfV",
    "DNovzHR7UmF2Ysj9Euowjrycd4iEcF2UUg",
    "DE46WED8pXLpDaShPbDTTvjdJL5qRsnp33"
  ],
  "id": 1
}
```

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getaddresses","params":[],"id":1}'
```

---

### sendtoaddress

Send coins to an address (NOT YET IMPLEMENTED).

**Parameters:**
1. `address` (string): Destination address
2. `amount` (integer): Amount in satoshis

**Returns:** Transaction hash (string)

**Status:** Coming in future update

---

## Mining Methods

### getmininginfo

Get current mining status and statistics.

**Parameters:** None

**Returns:** Object with mining information

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "getmininginfo",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "mining": true,
    "hashrate": 520,
    "threads": 8
  },
  "id": 1
}
```

**Fields:**
- `mining`: Boolean - whether mining is active
- `hashrate`: Integer - current hash rate (H/s)
- `threads`: Integer - number of mining threads

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getmininginfo","params":[],"id":1}'
```

---

### startmining

Start mining (NOT FULLY IMPLEMENTED).

**Parameters:** None

**Returns:** Boolean

**Note:** Currently returns mining status. Full implementation requires block template from blockchain.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "startmining",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": true,
  "id": 1
}
```

**Recommendation:** Use `--mine` command-line flag instead.

---

### stopmining

Stop mining.

**Parameters:** None

**Returns:** Boolean (true on success)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "stopmining",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": true,
  "id": 1
}
```

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"stopmining","params":[],"id":1}'
```

---

## Network Methods

### getnetworkinfo

Get information about the network and node version.

**Parameters:** None

**Returns:** Object with network information

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "getnetworkinfo",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "version": "1.0.0",
    "subversion": "/Dilithion:1.0.0/",
    "protocolversion": 1
  },
  "id": 1
}
```

**Fields:**
- `version`: Node software version
- `subversion`: User agent string
- `protocolversion`: P2P protocol version

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":1}'
```

---

### getpeerinfo

Get information about connected peers (NOT YET IMPLEMENTED).

**Parameters:** None

**Returns:** Array of peer objects

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "getpeerinfo",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [],
  "id": 1
}
```

**Status:** Returns empty array. Full implementation coming soon.

---

## General Methods

### help

List all available RPC methods.

**Parameters:** None

**Returns:** Array of method names

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "help",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    "getnewaddress",
    "getbalance",
    "getaddresses",
    "getmininginfo",
    "stopmining",
    "getnetworkinfo",
    "help",
    "stop"
  ],
  "id": 1
}
```

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"help","params":[],"id":1}'
```

---

### stop

Gracefully stop the Dilithion node.

**Parameters:** None

**Returns:** String (confirmation message)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "stop",
  "params": [],
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "Dilithion server stopping",
  "id": 1
}
```

**Note:** Node will stop after a short delay (100ms).

**cURL Example:**
```bash
curl http://localhost:8332 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"stop","params":[],"id":1}'
```

---

## Code Examples

### Python

```python
import requests
import json

def call_rpc(method, params=[]):
    url = "http://localhost:8332"
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    return response.json()

# Get new address
result = call_rpc("getnewaddress")
print(f"New address: {result['result']}")

# Check balance
result = call_rpc("getbalance")
print(f"Balance: {result['result']} satoshis")

# Get mining info
result = call_rpc("getmininginfo")
print(f"Mining: {result['result']}")
```

---

### JavaScript (Node.js)

```javascript
const axios = require('axios');

async function callRPC(method, params = []) {
  const response = await axios.post('http://localhost:8332', {
    jsonrpc: '2.0',
    method: method,
    params: params,
    id: 1
  });

  return response.data;
}

// Get new address
callRPC('getnewaddress').then(result => {
  console.log('New address:', result.result);
});

// Check balance
callRPC('getbalance').then(result => {
  console.log('Balance:', result.result, 'satoshis');
});

// Get mining info
callRPC('getmininginfo').then(result => {
  console.log('Mining info:', result.result);
});
```

---

### Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
)

type RPCRequest struct {
    JSONRPC string        `json:"jsonrpc"`
    Method  string        `json:"method"`
    Params  []interface{} `json:"params"`
    ID      int           `json:"id"`
}

type RPCResponse struct {
    JSONRPC string      `json:"jsonrpc"`
    Result  interface{} `json:"result"`
    ID      int         `json:"id"`
}

func callRPC(method string, params []interface{}) (*RPCResponse, error) {
    request := RPCRequest{
        JSONRPC: "2.0",
        Method:  method,
        Params:  params,
        ID:      1,
    }

    data, _ := json.Marshal(request)
    resp, err := http.Post("http://localhost:8332", "application/json", bytes.NewBuffer(data))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    var response RPCResponse
    json.Unmarshal(body, &response)

    return &response, nil
}

func main() {
    // Get new address
    result, _ := callRPC("getnewaddress", []interface{}{})
    fmt.Println("New address:", result.Result)

    // Check balance
    result, _ = callRPC("getbalance", []interface{}{})
    fmt.Println("Balance:", result.Result, "satoshis")
}
```

---

### Rust

```rust
use reqwest;
use serde_json::{json, Value};

async fn call_rpc(method: &str, params: Vec<Value>) -> Result<Value, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let request = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let response = client
        .post("http://localhost:8332")
        .json(&request)
        .send()
        .await?
        .json::<Value>()
        .await?;

    Ok(response["result"].clone())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get new address
    let address = call_rpc("getnewaddress", vec![]).await?;
    println!("New address: {}", address);

    // Check balance
    let balance = call_rpc("getbalance", vec![]).await?;
    println!("Balance: {} satoshis", balance);

    Ok(())
}
```

---

## Best Practices

### Error Handling

Always check for errors in responses:

```python
result = call_rpc("getbalance")
if "error" in result:
    print(f"Error: {result['error']['message']}")
else:
    print(f"Balance: {result['result']}")
```

### Request IDs

Use unique request IDs to match responses with requests:

```python
request_id = str(uuid.uuid4())
result = call_rpc("getbalance", id=request_id)
```

### Timeouts

Set appropriate timeouts for RPC calls:

```python
response = requests.post(url, json=payload, timeout=30)
```

### Connection Pooling

For high-frequency calls, use connection pooling:

```python
session = requests.Session()
session.post(url, json=payload)
```

---

## Security Considerations

### Localhost Only

**Current:** RPC server only listens on `127.0.0.1` (localhost)

**Production:** Never expose RPC to the internet without authentication

### Future Authentication

Planned authentication methods:
- HTTP Basic Auth
- API key authentication
- TLS/SSL encryption

### Firewall

Always use a firewall to block port 8332 from external access:

```bash
sudo ufw deny 8332
sudo ufw allow from 127.0.0.1 to any port 8332
```

---

## Changelog

### v1.0.0 (2026-01-01)
- Initial release
- Wallet methods: getnewaddress, getbalance, getaddresses
- Mining methods: getmininginfo, stopmining
- Network methods: getnetworkinfo
- General methods: help, stop

### Future Versions
- Authentication
- sendtoaddress implementation
- getpeerinfo implementation
- Batch requests
- WebSocket support

---

## Support

- **Documentation:** See `docs/` directory
- **User Guide:** See [USER-GUIDE.md](USER-GUIDE.md)
- **GitHub Issues:** https://github.com/dilithion/dilithion/issues

---

**Dilithion RPC API** - Post-Quantum Cryptocurrency Interface
