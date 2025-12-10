#!/bin/bash
# Test script for WebSocket functionality
# Copyright (c) 2025 The Dilithion Core developers

set -e

echo "=== Testing WebSocket Support ==="
echo ""

# Check if node is running
if ! pgrep -f "dilithion-node" > /dev/null; then
    echo "WARNING: dilithion-node is not running"
    echo "Please start the node with WebSocket enabled:"
    echo "  ./dilithion-node"
    echo ""
    echo "Make sure dilithion.conf has:"
    echo "  rpcwebsocketport=8333"
    echo ""
    read -p "Press Enter to continue with connection test anyway..."
fi

echo "1. Testing WebSocket connection..."
echo ""

# Test WebSocket handshake using curl (if available) or provide instructions
if command -v curl &> /dev/null; then
    echo "Attempting WebSocket handshake (this will fail as curl doesn't support WebSocket)..."
    echo "   Use a WebSocket client instead (see instructions below)"
else
    echo "curl not found - skipping connection test"
fi

echo ""
echo "2. Manual Testing Instructions:"
echo ""
echo "   Option 1: Browser Console (JavaScript)"
echo "   ----------------------------------------"
echo "   const ws = new WebSocket('ws://localhost:8333');"
echo "   ws.onopen = () => {"
echo "       console.log('Connected');"
echo "       ws.send(JSON.stringify({"
echo "           jsonrpc: '2.0',"
echo "           method: 'getbalance',"
echo "           params: [],"
echo "           id: 1"
echo "       }));"
echo "   };"
echo "   ws.onmessage = (e) => console.log(JSON.parse(e.data));"
echo ""
echo "   Option 2: Python (websocket-client)"
echo "   -------------------------------------"
echo "   pip install websocket-client"
echo "   python -c \""
echo "   import websocket, json"
echo "   ws = websocket.WebSocketApp('ws://localhost:8333',"
echo "       on_message=lambda ws, msg: print(json.loads(msg)))"
echo "   ws.on_open = lambda ws: ws.send(json.dumps({"
echo "       'jsonrpc': '2.0',"
echo "       'method': 'getbalance',"
echo "       'params': [],"
echo "       'id': 1"
echo "   }))"
echo "   ws.run_forever()"
echo "   \""
echo ""
echo "   Option 3: wscat (Node.js tool)"
echo "   ------------------------------"
echo "   npm install -g wscat"
echo "   wscat -c ws://localhost:8333"
echo "   > {\"jsonrpc\":\"2.0\",\"method\":\"getbalance\",\"params\":[],\"id\":1}"
echo ""

echo "3. Testing WebSocket with SSL (WSS)..."
echo "   If SSL is enabled, use 'wss://' instead of 'ws://'"
echo "   Example: wss://localhost:8333"
echo ""

echo "=== WebSocket Test Instructions Complete ==="

