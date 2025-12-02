# Dilithion RPC API Documentation

## Overview

Dilithion provides a JSON-RPC API for interacting with the node. The RPC server listens on a configurable port (default: 8332) and accepts JSON-RPC 2.0 requests.

## Configuration

The RPC server can be configured via:
- Command-line arguments: `--rpcport <port>`
- Configuration file (`dilithion.conf`): `rpcport=<port>`
- Environment variables: `DILITHION_RPCPORT=<port>`

## Authentication

Currently, the RPC server does not require authentication. **This should be enabled for production use.**

## Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "method_name",
  "params": [...],
  "id": 1
}
```

## Response Format

### Success Response

```json
{
  "jsonrpc": "2.0",
  "result": {...},
  "id": 1
}
```

### Error Response (Standard)

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32600,
    "message": "Invalid Request"
  },
  "id": 1
}
```

### Error Response (Enhanced/Structured)

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32600,
    "message": "Invalid Request",
    "data": {
      "title": "Invalid Request",
      "description": "The JSON sent is not a valid Request object.",
      "severity": "ERROR",
      "error_code": "RPC_INVALID_REQUEST",
      "recovery_steps": [
        "Ensure the request follows JSON-RPC 2.0 specification",
        "Check that 'jsonrpc' field is set to '2.0'",
        "Verify 'method' field is a string",
        "Confirm 'params' is an array or object"
      ]
    }
  },
  "id": 1
}
```

## Standard JSON-RPC Error Codes

- `-32700`: Parse error
- `-32600`: Invalid Request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error
- `-32000` to `-32099`: Server error (reserved for implementation-defined server errors)

## RPC Methods

### `getinfo`

Returns general information about the node.

**Parameters:** None

**Returns:**
```json
{
  "version": "0.1.0",
  "blocks": 12345,
  "connections": 8,
  "testnet": false
}
```

### `getblockcount`

Returns the current block height.

**Parameters:** None

**Returns:**
```json
12345
```

### `getblockhash`

Returns the block hash for a given block height.

**Parameters:**
- `height` (number): Block height

**Returns:**
```json
"0000000000000000000000000000000000000000000000000000000000000000"
```

### `getblock`

Returns block information for a given block hash.

**Parameters:**
- `hash` (string): Block hash (hex)

**Returns:**
```json
{
  "hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "height": 12345,
  "version": 1,
  "previousblockhash": "...",
  "merkleroot": "...",
  "time": 1234567890,
  "bits": "1d00ffff",
  "nonce": 0,
  "transactions": [...]
}
```

### `getrawtransaction`

Returns raw transaction data.

**Parameters:**
- `txid` (string): Transaction ID (hex)
- `verbose` (boolean, optional): If true, returns decoded transaction

**Returns:**
```json
{
  "txid": "...",
  "version": 1,
  "vin": [...],
  "vout": [...],
  "locktime": 0
}
```

### `sendrawtransaction`

Broadcasts a raw transaction to the network.

**Parameters:**
- `hexstring` (string): Raw transaction (hex)

**Returns:**
```json
"transaction_hash"
```

### `getmempoolinfo`

Returns information about the mempool.

**Parameters:** None

**Returns:**
```json
{
  "size": 100,
  "bytes": 50000,
  "usage": 100000
}
```

### `getpeerinfo`

Returns information about connected peers.

**Parameters:** None

**Returns:**
```json
[
  {
    "id": 1,
    "addr": "192.168.1.1:8333",
    "version": 70001,
    "subver": "/Dilithion:0.1.0/",
    "connected": true,
    "lastsend": 1234567890,
    "lastrecv": 1234567890
  }
]
```

### `getnetworkinfo`

Returns network information.

**Parameters:** None

**Returns:**
```json
{
  "version": 70001,
  "subversion": "/Dilithion:0.1.0/",
  "protocolversion": 70001,
  "connections": 8,
  "networkactive": true
}
```

### `stop`

Stops the Dilithion node.

**Parameters:** None

**Returns:**
```json
"Dilithion stopping"
```

## Error Handling

All RPC methods use enhanced error responses that include:
- **Error Code**: Standard JSON-RPC error code or custom error code
- **Title**: Human-readable error title
- **Description**: Detailed error description
- **Severity**: ERROR, WARNING, CRITICAL
- **Recovery Steps**: Actionable steps to resolve the issue

## Rate Limiting

The RPC server implements rate limiting to prevent abuse:
- Maximum requests per second: Configurable (default: 100)
- Rate limit violations result in `-32000` error with appropriate message

## Best Practices

1. **Always check error responses**: Use the structured error format to provide better user experience
2. **Handle timeouts**: Network operations may timeout; implement retry logic
3. **Validate parameters**: The server validates parameters, but client-side validation is recommended
4. **Use appropriate HTTP methods**: POST for JSON-RPC requests
5. **Monitor rate limits**: Be aware of rate limiting when making frequent requests

## Security Considerations

1. **Authentication**: Currently disabled; should be enabled for production
2. **TLS/SSL**: Not currently implemented; should be added for secure connections
3. **IP Whitelisting**: Consider restricting RPC access to localhost or trusted IPs
4. **Rate Limiting**: Already implemented; adjust limits based on use case

## Example Usage

### Using curl

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "getinfo",
    "params": [],
    "id": 1
  }'
```

### Using Python

```python
import requests
import json

url = "http://localhost:8332"
payload = {
    "jsonrpc": "2.0",
    "method": "getinfo",
    "params": [],
    "id": 1
}
response = requests.post(url, json=payload)
result = response.json()
print(result)
```

## Future Enhancements

- Authentication (username/password, API keys)
- TLS/SSL support
- WebSocket support for real-time updates
- Batch requests
- Method filtering/whitelisting
- Request logging and auditing

