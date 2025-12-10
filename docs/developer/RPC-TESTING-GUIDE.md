# RPC Testing Guide

## Overview

This guide provides instructions for testing the RPC enhancements:
- Phase 1: Authentication, Method Filtering, Request Logging
- Phase 2: Batch Requests
- Phase 3: TLS/SSL Support
- Phase 4: WebSocket Support

## Test Scripts

### 1. SSL/TLS Testing (`scripts/test_ssl.sh`)

Generates test certificates and verifies SSL configuration.

**Usage:**
```bash
./scripts/test_ssl.sh
```

**What it does:**
- Generates self-signed certificate and private key
- Verifies certificate validity
- Verifies key matches certificate
- Provides instructions for node configuration

**Output:**
- `test_cert.pem` - Test certificate
- `test_key.pem` - Test private key

### 2. WebSocket Testing (`scripts/test_websocket.sh`)

Provides instructions and examples for testing WebSocket connections.

**Usage:**
```bash
./scripts/test_websocket.sh
```

**What it does:**
- Checks if node is running
- Provides JavaScript, Python, and wscat examples
- Instructions for WSS (secure WebSocket) testing

### 3. Integration Testing (`scripts/test_rpc_integration.sh`)

Comprehensive integration tests for all RPC features.

**Usage:**
```bash
# Set environment variables (optional)
export RPC_PORT=8332
export WS_PORT=8333
export RPC_USER=admin
export RPC_PASS=password

# Run tests
./scripts/test_rpc_integration.sh
```

**What it tests:**
- Basic RPC calls (HTTP)
- Authentication
- Batch requests
- HTTPS (SSL/TLS)
- WebSocket connections

## Unit Tests

### Running Unit Tests

```bash
make test_dilithion
./test_dilithion
```

**Test Suites:**
- `rpc_ssl_tests` - SSL wrapper functionality
- `rpc_websocket_tests` - WebSocket server functionality

## Manual Testing

### 1. Test Authentication

```bash
# Without authentication (should fail if auth enabled)
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'

# With authentication
AUTH=$(echo -n "admin:password" | base64)
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -H "Authorization: Basic $AUTH" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'
```

### 2. Test Batch Requests

```bash
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -H "Authorization: Basic $AUTH" \
  -d '[
    {"jsonrpc":"2.0","method":"getbalance","params":[],"id":1},
    {"jsonrpc":"2.0","method":"getblockcount","params":[],"id":2},
    {"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":3}
  ]'
```

### 3. Test SSL/TLS

```bash
# Generate test certificate
openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem \
    -days 365 -nodes -subj "/CN=localhost"

# Configure node (add to dilithion.conf)
# rpcsslcertificatechainfile=/path/to/test_cert.pem
# rpcsslprivatekeyfile=/path/to/test_key.pem

# Test HTTPS connection
curl -k https://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -H "Authorization: Basic $AUTH" \
  -d '{"jsonrpc":"2.0","method":"help","params":[],"id":1}'
```

### 4. Test WebSocket

**JavaScript (Browser Console):**
```javascript
const ws = new WebSocket('ws://localhost:8333');
ws.onopen = () => {
    ws.send(JSON.stringify({
        jsonrpc: "2.0",
        method: "getbalance",
        params: [],
        id: 1
    }));
};
ws.onmessage = (e) => console.log(JSON.parse(e.data));
```

**Python:**
```python
import websocket
import json

def on_message(ws, message):
    print(json.loads(message))

ws = websocket.WebSocketApp("ws://localhost:8333",
                            on_message=on_message)
ws.run_forever()
```

**wscat (Node.js):**
```bash
npm install -g wscat
wscat -c ws://localhost:8333
> {"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}
```

### 5. Test Request Logging

```bash
# Make some RPC calls
curl -X POST http://localhost:8332 \
  -H "Content-Type: application/json" \
  -H "X-Dilithion-RPC: 1" \
  -H "Authorization: Basic $AUTH" \
  -d '{"jsonrpc":"2.0","method":"getbalance","params":[],"id":1}'

# Check log files
cat ~/.dilithion/rpc.log
cat ~/.dilithion/rpc_audit.log
```

## Expected Results

### Authentication
- ✅ Without auth: 401 Unauthorized (if auth enabled)
- ✅ With valid auth: 200 OK with JSON-RPC response
- ✅ With invalid auth: 401 Unauthorized

### Batch Requests
- ✅ Single request: Single JSON object response
- ✅ Batch request: Array of JSON objects (same order as requests)
- ✅ Invalid request in batch: Error response for that request only

### SSL/TLS
- ✅ HTTP (no SSL): Works normally
- ✅ HTTPS (with SSL): Encrypted connection, may show certificate warning for self-signed

### WebSocket
- ✅ Connection: Handshake successful (101 Switching Protocols)
- ✅ Message: JSON-RPC request sent, response received
- ✅ Ping/Pong: Automatic keepalive
- ✅ Close: Graceful disconnection

## Troubleshooting

### SSL/TLS Issues
- **Certificate not found**: Check file paths in `dilithion.conf`
- **Certificate invalid**: Regenerate with `openssl`
- **Key mismatch**: Ensure certificate and key match

### WebSocket Issues
- **Connection refused**: Check WebSocket port in config
- **Handshake failed**: Verify WebSocket protocol implementation
- **No response**: Check message callback is set

### Authentication Issues
- **Always unauthorized**: Check `rpcuser`/`rpcpassword` in config
- **Permission denied**: Check `rpc_permissions.json` file

## Test Coverage

### Unit Tests
- ✅ SSL wrapper initialization
- ✅ SSL error handling
- ✅ WebSocket server creation
- ✅ WebSocket accept key generation
- ✅ WebSocket message callbacks
- ✅ WebSocket broadcast

### Integration Tests
- ✅ HTTP RPC calls
- ✅ HTTPS RPC calls
- ✅ Batch requests
- ✅ Authentication
- ✅ WebSocket connections

### Manual Tests
- ✅ Certificate generation
- ✅ SSL handshake
- ✅ WebSocket handshake
- ✅ Real-time messaging
- ✅ Log file verification

## Continuous Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run RPC Tests
  run: |
    make test_dilithion
    ./test_dilithion --log_level=test_suite
```

## Next Steps

1. **Automated Testing**: Set up CI/CD to run tests automatically
2. **Performance Testing**: Benchmark SSL and WebSocket overhead
3. **Security Testing**: Penetration testing for SSL/TLS and WebSocket
4. **Load Testing**: Test with multiple concurrent WebSocket connections

