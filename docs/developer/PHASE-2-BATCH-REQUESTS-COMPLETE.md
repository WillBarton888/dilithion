# Phase 2: Batch Requests - Complete

## Overview

Phase 2 implements JSON-RPC 2.0 batch request support, allowing clients to send multiple RPC calls in a single HTTP request. This improves efficiency by reducing network round-trips and HTTP overhead.

## Implementation Details

### Features

1. **Batch Request Detection**: Automatically detects if the JSON payload is an array (batch) or object (single request)
2. **Batch Parsing**: Parses array of JSON-RPC 2.0 requests
3. **Batch Execution**: Executes all requests in the batch sequentially
4. **Batch Response**: Returns array of responses matching the order of requests
5. **Error Handling**: Invalid requests in batch result in error responses (per JSON-RPC 2.0 spec)
6. **Security**: Rate limiting, permission checking, and logging for batch requests

### JSON-RPC 2.0 Compliance

- **Batch Request Format**: Array of request objects
  ```json
  [
    {"jsonrpc": "2.0", "method": "getbalance", "params": [], "id": 1},
    {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 2}
  ]
  ```

- **Batch Response Format**: Array of response objects (same order as requests)
  ```json
  [
    {"jsonrpc": "2.0", "result": "100.5", "id": 1},
    {"jsonrpc": "2.0", "result": "12345", "id": 2}
  ]
  ```

- **Invalid Requests**: Invalid requests in batch result in error responses (not dropped)
- **Empty Batch**: Empty batch array is rejected with error

### Security Features

1. **Batch Size Limit**: Maximum 100 requests per batch (prevents DoS)
2. **Rate Limiting**: Batch counts as single request for rate limiting
3. **Permission Checking**: All methods in batch are checked for permissions before execution
4. **Logging**: Each request in batch is logged individually

### Performance

- **Sequential Execution**: Requests in batch are executed sequentially (maintains order)
- **Single HTTP Request**: Reduces network overhead
- **Efficient Parsing**: Uses nlohmann/json for fast JSON parsing

## Code Changes

### New Functions

**`ParseBatchRPCRequest()`**
- Parses JSON array of request objects
- Validates each request
- Handles invalid requests gracefully (creates error request)

**`ExecuteBatchRPC()`**
- Executes all requests in batch
- Checks permissions for each request
- Returns vector of responses

**`SerializeBatchResponse()`**
- Serializes array of responses to JSON array string
- Maintains order of responses

### Modified Functions

**`HandleClient()`**
- Detects batch vs single request
- Routes to appropriate handler
- Handles batch-specific rate limiting and permission checking

## Usage Examples

### Single Request (Existing)
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ=" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

### Batch Request (New)
```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ=" \
  -d '[
    {"jsonrpc":"2.0","method":"getbalance","params":[],"id":1},
    {"jsonrpc":"2.0","method":"getblockcount","params":[],"id":2},
    {"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":3}
  ]'
```

### Response Example
```json
[
  {"jsonrpc":"2.0","result":"100.5","id":"1"},
  {"jsonrpc":"2.0","result":"12345","id":"2"},
  {"jsonrpc":"2.0","result":"{\"connections\":5}","id":"3"}
]
```

### Error Handling

**Invalid Request in Batch:**
```json
[
  {"jsonrpc":"2.0","method":"getbalance","params":[],"id":1},
  {"invalid":"request","id":2},
  {"jsonrpc":"2.0","method":"getblockcount","params":[],"id":3}
]
```

**Response:**
```json
[
  {"jsonrpc":"2.0","result":"100.5","id":"1"},
  {"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":"2"},
  {"jsonrpc":"2.0","result":"12345","id":"3"}
]
```

## Files Modified

- `src/rpc/server.h` - Added batch request function declarations
- `src/rpc/server.cpp` - Implemented batch request parsing, execution, and serialization

## Testing

**Manual Testing:**
1. Send single request (should work as before)
2. Send batch request with multiple methods
3. Send batch request with invalid request (should return error for that request)
4. Send empty batch (should return error)
5. Send batch exceeding size limit (should return error)
6. Test rate limiting with batch (should count as single request)
7. Test permissions with batch (should check all methods)

**Example Test Script:**
```bash
#!/bin/bash

# Test batch request
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ=" \
  -d '[
    {"jsonrpc":"2.0","method":"getbalance","params":[],"id":1},
    {"jsonrpc":"2.0","method":"getblockcount","params":[],"id":2}
  ]'
```

## Performance Impact

- **Network Efficiency**: Reduces HTTP overhead (single connection, single request)
- **Server Load**: Sequential execution maintains order but may be slower than parallel
- **Memory**: Batch requests use more memory (all requests/responses in memory)

## Future Enhancements

1. **Parallel Execution**: Execute independent requests in parallel (requires dependency analysis)
2. **Batch Size Configuration**: Make batch size limit configurable
3. **Partial Success**: Allow some requests to succeed even if others fail (current: all or nothing for permissions)

## Documentation

- See `docs/developer/API-DOCUMENTATION.md` for RPC API reference
- JSON-RPC 2.0 Specification: https://www.jsonrpc.org/specification

