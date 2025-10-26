# Node Communication Debugging Guide
**Date**: October 27, 2025 (Morning Session)
**Issue**: Nodes connecting but not communicating
**Status**: Debug logging added, ready for testing
**Quality Standard**: A++ Professional Debugging

---

## Current Status Summary

### What's Working ✅
- P2P server listening and accepting connections
- Outbound connections establishing successfully
- Socket layer functional
- Build compiles cleanly (604K binary)

### What's Not Working ❌
- Message exchange between nodes
- Version/verack handshake not completing
- No ping/pong messages

### Changes Made This Session
1. **Added comprehensive debug logging** to `src/net/net.cpp`:
   - SendMessage now logs every send attempt with bytes sent
   - ReceiveMessages logs header reception, validation, payload reads
   - Detailed error messages for all failure cases
   - Magic number validation logging

2. **Build Status**: ✅ CLEAN (604K binary)

---

## Testing Instructions

### Test 1: Two-Node Message Exchange

**Purpose**: Verify messages are sent and received between two nodes

#### Terminal 1: Start Listening Node
```bash
cd /mnt/c/Users/will/dilithion
./dilithion-node --testnet --port=18444 --rpcport=18332
```

**Expected Initial Output**:
```
======================================
Dilithion Node v1.0.0
Post-Quantum Cryptocurrency
======================================

Network: TESTNET (256x easier difficulty)
Data directory: .dilithion-testnet
P2P port: 18444
RPC port: 18332

...
✓ P2P server listening on port 18444
✓ P2P accept thread started
✓ P2P receive thread started
✓ P2P maintenance thread started
...
Node Status: RUNNING
```

#### Terminal 2: Start Connecting Node
```bash
cd /mnt/c/Users/will/dilithion

# Create separate data directory first
mkdir -p .dilithion-testnet-2/blocks

# Start node that connects to Node 1
./dilithion-node --testnet --port=18445 --rpcport=18333 \
  --connect=127.0.0.1:18444 --datadir=.dilithion-testnet-2
```

**Expected Connection Output**:
```
Initiating outbound connections...
  Connecting to 127.0.0.1:18444...
    ✓ Connected to 127.0.0.1:18444 (peer_id=1)
    ✓ Sent version message to peer 1
```

---

## What to Look For in Logs

### 1. Connection Establishment (Should See This)
**Terminal 1** should show:
```
[P2P] New peer connected: 127.0.0.1:XXXXX
[P2P] Peer accepted and added to connection pool (peer_id=1)
[P2P] Sent version message to peer 1
```

**Terminal 2** should show:
```
[P2P] Connected to 127.0.0.1:18444 (peer_id=1)
[P2P] Sent version message to peer 1
```

### 2. Message Send Logs (Debug - Should See This)
```
[P2P] Sent 'version' to peer 1 (XXX bytes)
```

### 3. Message Receive Logs (CRITICAL - Currently Missing?)
```
[P2P] Received header from peer 1: command='version', payload_size=XXX, magic=0xdab5bffa
[P2P] Received complete payload from peer 1 (XXX bytes)
[P2P] Processing 'version' message from peer 1
[P2P] Received version from peer 1 (version=70001, agent=Dilithion:1.0.0)
[P2P] Sent verack to peer 1
```

### 4. Handshake Complete (Goal State)
```
[P2P] Handshake complete with peer 1
```

### 5. Ping/Pong (After 30 seconds)
```
[P2P] Sent 'ping' to peer 1 (XXX bytes)
[P2P] Received pong from peer 1 (nonce=XXXXX)
```

---

## Expected Issues to Diagnose

### Issue 1: No "Received header" Messages
**Symptom**: You see "Sent 'version'" but never see "Received header"

**Likely Causes**:
1. **Non-blocking socket returning 0 bytes** - Normal, messages might arrive later
2. **Network magic mismatch** - Would show "Invalid header" error
3. **Socket not readable** - Data queued but not being read

**Debug Steps**:
- Check both terminals - messages should appear on BOTH sides
- Wait 5-10 seconds - non-blocking I/O might have delay
- Look for "Invalid header" or "magic mismatch" errors

### Issue 2: "Incomplete header" or "Incomplete payload"
**Symptom**: Logs show partial message reception

**Likely Causes**:
1. **Message split across multiple Recv() calls** - Need buffering
2. **Socket buffer timing** - Data arrives in chunks

**Fix Required**: Implement message buffering (current code expects full message in one Recv)

### Issue 3: Magic Number Mismatch
**Symptom**: Log shows:
```
[P2P] Invalid header from peer 1 (magic mismatch: got 0xXXXXXXXX, expected 0xdab5bffa)
```

**Fix**: Check that both nodes are using testnet (should both show `Network: TESTNET`)

### Issue 4: "No valid socket for peer"
**Symptom**: SendMessage fails with "No valid socket"

**Likely Cause**: Socket not stored correctly in peer_sockets map

**Fix**: Check AcceptConnection and ConnectToPeer implementations

---

## Diagnostic Commands

### Check if Nodes are Connected
```bash
# In Terminal 3
netstat -an | grep 18444
```
Should show ESTABLISHED connections

### Check RPC Server (Optional)
```bash
curl -X POST http://localhost:18332 -d '{"method":"help"}'
```

---

## Quick Reference: Network Parameters

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| Network Magic | 0xD1711710 | 0xDAB5BFFA |
| P2P Port | 8444 | 18444 |
| RPC Port | 8332 | 18332 |
| Data Dir | .dilithion | .dilithion-testnet |
| Difficulty | 0x1d00ffff | 0x1e00ffff (256x easier) |

---

## Common Problems & Solutions

### Problem: "Failed to bind P2P socket"
**Solution**: Port already in use
```bash
# Kill existing process
pkill dilithion-node

# Or use different port
./dilithion-node --testnet --port=18447
```

### Problem: "Failed to connect"
**Solution**: Node 1 not running or wrong port
- Verify Node 1 is running in Terminal 1
- Check port matches (`--port=18444` in Node 1, `--connect=127.0.0.1:18444` in Node 2)

### Problem: Nodes crash or hang
**Solution**: Clean shutdown with Ctrl+C, check for database locks
```bash
# Clean shutdown
Ctrl+C in each terminal

# Remove lock files if needed
rm .dilithion-testnet/blocks/LOCK
rm .dilithion-testnet-2/blocks/LOCK
```

---

## Success Criteria

After running 2-node test, you should see:

- ✅ Both nodes start successfully
- ✅ Connection established (Terminal 1 shows "New peer connected")
- ✅ Version messages sent (both terminals show "Sent 'version'")
- ✅ Version messages received (both terminals show "Received header")
- ✅ Verack messages exchanged
- ✅ Handshake complete messages
- ✅ Ping/pong exchange after 30 seconds

---

## Capture Logs for Analysis

If issues persist, capture full logs:

```bash
# Terminal 1
./dilithion-node --testnet --port=18444 --rpcport=18332 2>&1 | tee node1.log

# Terminal 2
./dilithion-node --testnet --port=18445 --rpcport=18333 \
  --connect=127.0.0.1:18444 --datadir=.dilithion-testnet-2 2>&1 | tee node2.log
```

Then review `node1.log` and `node2.log` for diagnostic messages.

---

## Next Steps After Diagnosis

### If Messages ARE Being Received
- ✅ Message exchange working!
- Move to 3-node testing
- Test block propagation

### If Messages NOT Being Received
Common fixes needed:
1. **Message buffering**: Implement partial message storage
2. **Socket state**: Check if sockets are in correct blocking/non-blocking mode
3. **Serialization**: Verify message format matches protocol

---

## Code Locations for Reference

### Message Send
- **File**: `src/net/net.cpp`
- **Function**: `CConnectionManager::SendMessage()` (line ~512)
- **Logs**: "Sent 'command' to peer X"

### Message Receive
- **File**: `src/net/net.cpp`
- **Function**: `CConnectionManager::ReceiveMessages()` (line ~552)
- **Logs**: "Received header from peer X"

### Message Processing
- **File**: `src/net/net.cpp`
- **Function**: `CNetMessageProcessor::ProcessMessage()` (line ~37)
- **Logs**: "Processing 'command' message from peer X"

### Version Handler
- **File**: `src/node/dilithion-node.cpp`
- **Lines**: ~232-241 (version handler registration)
- **Logs**: "Received version from peer X"

---

**Project Coordinator**: Claude Code
**Session**: Morning debugging continuation
**Build Status**: ✅ CLEAN (604K)
**Ready for**: Manual 2-node testing

**Professional Standard**: A++ debugging methodology with comprehensive logging
