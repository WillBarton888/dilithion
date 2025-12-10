# Phase 4: WebSocket Support - Complete

## Overview

Phase 4 implements WebSocket protocol (RFC 6455) support for the RPC server, enabling real-time bidirectional communication. This allows clients to receive live updates (new blocks, transactions, peer status) without polling.

## Implementation Details

### Features

1. **WebSocket Protocol**: Full RFC 6455 implementation
   - WebSocket handshake (HTTP upgrade)
   - Frame encoding/decoding (text and binary)
   - Ping/pong keepalive
   - Close handshake

2. **Real-Time Updates**: Bidirectional communication for:
   - New block notifications
   - Transaction mempool updates
   - Peer connection status changes
   - Mining status updates

3. **SSL/TLS Support**: WebSocket over WSS (secure WebSocket) when SSL is enabled

4. **RPC Integration**: WebSocket connections can send JSON-RPC requests and receive responses

5. **Broadcast Support**: Server can broadcast messages to all connected clients

### Code Architecture

**New Files:**
- `src/rpc/websocket.h` - WebSocket server interface
- `src/rpc/websocket.cpp` - WebSocket server implementation

**Modified Files:**
- `src/rpc/server.h` - Added WebSocket server member and InitializeWebSocket()
- `src/rpc/server.cpp` - Integrated WebSocket server with RPC
- `src/node/dilithion-node.cpp` - Added WebSocket initialization from config
- `Makefile` - Added websocket.cpp to build

### WebSocket Protocol Implementation

**Handshake:**
- Extracts `Sec-WebSocket-Key` from HTTP request
- Generates `Sec-WebSocket-Accept` using SHA-1 + Base64
- Sends HTTP 101 Switching Protocols response

**Frame Format:**
- Supports all opcodes: TEXT, BINARY, CLOSE, PING, PONG
- Handles masked/unmasked frames
- Supports payload lengths: 7-bit, 16-bit, 64-bit
- Proper network byte order conversion

**Message Handling:**
- Text messages: JSON-RPC requests/responses
- Binary messages: Future use (e.g., binary protocol)
- Ping/Pong: Automatic keepalive
- Close: Graceful connection termination

## Configuration

### Configuration File (`dilithion.conf`)

```ini
# Enable WebSocket server
rpcwebsocketport=8333
```

**Note:** WebSocket port should be different from RPC port to avoid conflicts.

### SSL/TLS for WebSocket

If SSL is enabled for RPC, WebSocket automatically uses WSS (secure WebSocket):

```ini
rpcsslcertificatechainfile=/path/to/cert.pem
rpcsslprivatekeyfile=/path/to/key.pem
rpcwebsocketport=8333
```

## Usage

### JavaScript Client Example

```javascript
// Connect to WebSocket server
const ws = new WebSocket('ws://localhost:8333');

ws.onopen = function() {
    console.log('WebSocket connected');
    
    // Send JSON-RPC request
    ws.send(JSON.stringify({
        jsonrpc: "2.0",
        method: "getbalance",
        params: [],
        id: 1
    }));
};

ws.onmessage = function(event) {
    const response = JSON.parse(event.data);
    console.log('Received:', response);
};

ws.onerror = function(error) {
    console.error('WebSocket error:', error);
};

ws.onclose = function() {
    console.log('WebSocket closed');
};
```

### Python Client Example

```python
import websocket
import json

def on_message(ws, message):
    response = json.loads(message)
    print("Received:", response)

def on_error(ws, error):
    print("Error:", error)

def on_close(ws):
    print("Connection closed")

def on_open(ws):
    # Send JSON-RPC request
    request = {
        "jsonrpc": "2.0",
        "method": "getbalance",
        "params": [],
        "id": 1
    }
    ws.send(json.dumps(request))

ws = websocket.WebSocketApp("ws://localhost:8333",
                            on_message=on_message,
                            on_error=on_error,
                            on_close=on_close)
ws.on_open = on_open
ws.run_forever()
```

### Secure WebSocket (WSS)

```javascript
// Connect to secure WebSocket
const ws = new WebSocket('wss://localhost:8333', {
    rejectUnauthorized: false  // For self-signed certificates
});
```

## Files Modified

### New Files
- `src/rpc/websocket.h` - WebSocket server header
- `src/rpc/websocket.cpp` - WebSocket server implementation

### Modified Files
- `src/rpc/server.h` - Added WebSocket server member
- `src/rpc/server.cpp` - Integrated WebSocket with RPC message handling
- `src/node/dilithion-node.cpp` - Added WebSocket initialization
- `Makefile` - Added websocket.cpp

## Testing

**Manual Testing:**
1. Start node with WebSocket port configured
2. Connect via WebSocket client (browser or tool)
3. Send JSON-RPC request via WebSocket
4. Verify response received
5. Test ping/pong keepalive
6. Test close handshake
7. Test with SSL enabled (WSS)

**Example Test:**
```bash
# Start node with WebSocket
./dilithion-node --rpcport=8332

# In browser console or Node.js:
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

## Security Notes

1. **Localhost Only**: WebSocket server binds to localhost by default (same as RPC)
2. **SSL/TLS**: Use WSS (secure WebSocket) for remote access
3. **Authentication**: WebSocket connections should authenticate via RPC auth if needed
4. **Rate Limiting**: Consider adding rate limiting for WebSocket connections
5. **Message Size Limits**: Implement message size limits to prevent DoS

## Performance Impact

- **Memory**: ~1-2KB per WebSocket connection
- **CPU**: Minimal overhead for frame encoding/decoding
- **Network**: Reduced overhead compared to HTTP polling

## Future Enhancements

1. **Subscription System**: Allow clients to subscribe to specific events (blocks, transactions, peers)
2. **Message Queuing**: Queue messages for disconnected clients
3. **Thread Pool**: Use thread pool for handling multiple WebSocket connections
4. **Compression**: WebSocket per-message compression (RFC 7692)
5. **Subprotocols**: Support WebSocket subprotocols for different message formats

## Integration with RPC

WebSocket connections can send JSON-RPC requests just like HTTP connections:
- Same authentication (if enabled)
- Same permission checking
- Same method execution
- Responses sent back via WebSocket

**Example:**
```javascript
// WebSocket RPC request
ws.send(JSON.stringify({
    jsonrpc: "2.0",
    method: "getblockcount",
    params: [],
    id: 1
}));

// Response received via WebSocket
// {"jsonrpc":"2.0","result":"12345","id":"1"}
```

## Documentation

- WebSocket RFC 6455: https://tools.ietf.org/html/rfc6455
- See `docs/developer/API-DOCUMENTATION.md` for RPC API reference

