# Manual Peer Connection Setup

**Version**: 1.0
**Date**: October 28, 2025
**Status**: Required for Testnet Launch

---

## Overview

Dilithion currently requires **manual peer configuration** for network connectivity. Automatic peer discovery via DNS seed nodes will be implemented in a future release.

**Why Manual Setup?**
- DNS seed node infrastructure not yet deployed
- Allows testnet launch while DNS seeds are being set up
- Provides direct control over peer connections
- Simple and reliable for initial testing

---

## Quick Start

### Option 1: Command Line (Recommended)

Connect to peers when starting the node:

```bash
./dilithion-node --addnode=<peer_ip>:<port>
```

**Example:**
```bash
# Connect to a single peer
./dilithion-node --addnode=192.168.1.100:8333

# Connect to multiple peers
./dilithion-node --addnode=192.168.1.100:8333 --addnode=192.168.1.101:8333
```

### Option 2: RPC After Startup

Add peers dynamically using RPC:

```bash
# Using curl
curl --user dilithion:your_rpc_password \
     --data-binary '{"jsonrpc":"2.0","id":"1","method":"addnode","params":["192.168.1.100:8333","add"]}' \
     http://localhost:18332

# The node will attempt to connect to this peer
```

---

## Testnet Deployment Guide

### Step 1: Identify Your Peers

For testnet launch, you need to know the IP addresses of other testnet participants.

**Coordinator Node** (if you're running the first node):
1. Share your public IP address with testnet participants
2. Ensure port 8333 is open in your firewall
3. Start your node first

**Participant Nodes**:
1. Get the coordinator's IP address
2. Use `--addnode` to connect to coordinator

### Step 2: Start Your Node

**Coordinator:**
```bash
./dilithion-node --rpcport=18332 --p2pport=8333
```

**Participants:**
```bash
./dilithion-node --rpcport=18332 --p2pport=8333 --addnode=<coordinator_ip>:8333
```

### Step 3: Verify Connections

Check peer connections via RPC:

```bash
curl --user dilithion:your_password \
     --data-binary '{"jsonrpc":"2.0","id":"1","method":"getconnectioncount","params":[]}' \
     http://localhost:18332
```

**Expected Response:**
```json
{"result": 1, "error": null, "id": "1"}
```

If result is 0, check:
- Firewall settings (port 8333 must be open)
- Correct IP address
- Peer node is running

---

## Configuration File Setup

Create `dilithion.conf` in your data directory:

```conf
# Network Configuration
p2pport=8333
rpcport=18332

# Manual Peer Connections
addnode=192.168.1.100:8333
addnode=192.168.1.101:8333
addnode=192.168.1.102:8333

# RPC Configuration
rpcuser=dilithion
rpcpassword=your_secure_password_here

# Optional: Mining
mining=1
miningthreads=2
```

**Location:**
- Linux: `~/.dilithion/dilithion.conf`
- Windows: `%APPDATA%\Dilithion\dilithion.conf`

---

## Network Topology Recommendations

### Small Testnet (3-5 nodes)

**Star Topology** (Recommended):
```
     Node 2 ──┐
              │
     Node 3 ──┤── Coordinator (Node 1)
              │
     Node 4 ──┘
```

Each participant connects to coordinator:
```bash
# All participants use:
./dilithion-node --addnode=<coordinator_ip>:8333
```

### Medium Testnet (6-20 nodes)

**Mesh Topology** (Better redundancy):
```
Node 1 ←→ Node 2 ←→ Node 3
   ↕         ↕         ↕
Node 4 ←→ Node 5 ←→ Node 6
```

Each node connects to 2-3 peers:
```bash
./dilithion-node \
  --addnode=<peer1_ip>:8333 \
  --addnode=<peer2_ip>:8333 \
  --addnode=<peer3_ip>:8333
```

---

## Troubleshooting

### Problem: "Connection refused"

**Causes:**
- Peer node not running
- Firewall blocking port 8333
- Incorrect IP address

**Solutions:**
```bash
# 1. Verify peer node is running
ssh user@peer_ip "ps aux | grep dilithion-node"

# 2. Test port connectivity
telnet <peer_ip> 8333

# 3. Check firewall (Linux)
sudo ufw allow 8333/tcp

# 4. Check firewall (Windows)
netsh advfirewall firewall add rule name="Dilithion P2P" dir=in action=allow protocol=TCP localport=8333
```

### Problem: "No block updates"

**Cause:** Not connected to any peers with blockchain data

**Solution:**
1. Verify at least one peer is mining blocks
2. Check peer connections: `getconnectioncount`
3. Manually trigger block request (coordinator should mine first block)

### Problem: "Peers disconnect after connecting"

**Causes:**
- Version mismatch
- Network timeout
- Invalid handshake

**Solutions:**
1. Ensure all nodes running same version
2. Check network stability
3. Review node logs for error messages

---

## Security Considerations

### Trusted Peers Only

**⚠️ IMPORTANT:** Only connect to peers you trust!

- Malicious peers can provide fake blockchain data
- For testnet, coordinate with known participants
- For mainnet, DNS seeds will provide trusted peer discovery

### Firewall Configuration

**Recommended Settings:**
- Allow inbound connections on P2P port (8333)
- Restrict RPC port (18332) to localhost only
- Use strong RPC passwords

```bash
# Linux firewall rules
sudo ufw allow 8333/tcp          # P2P port - public
sudo ufw deny 18332/tcp           # RPC port - localhost only (default)

# Then explicitly allow localhost
# (RPC binds to localhost by default, so this is handled automatically)
```

### IP Whitelisting (Optional)

For production testnet, you can whitelist specific peer IPs:

```conf
# dilithion.conf
whitelist=192.168.1.100
whitelist=192.168.1.101
onlynet=ipv4
```

---

## Future: DNS Seed Nodes

**Planned for v1.1:**
- Automatic peer discovery via DNS
- Multiple seed node domains
- Fallback to hardcoded seeds

**What will change:**
- `--addnode` will become optional
- Nodes will auto-discover peers on startup
- Manual peer addition still supported for advanced users

**Timeline:** 2-4 weeks after testnet launch

---

## Command Reference

### Starting Node with Peers

```bash
# Single peer
./dilithion-node --addnode=<ip>:<port>

# Multiple peers
./dilithion-node \
  --addnode=peer1.example.com:8333 \
  --addnode=peer2.example.com:8333 \
  --addnode=192.168.1.100:8333

# With custom ports
./dilithion-node \
  --p2pport=9333 \
  --rpcport=19332 \
  --addnode=<peer_ip>:9333
```

### RPC Commands

```bash
# Add node dynamically
curl --user dilithion:password \
     --data-binary '{"jsonrpc":"2.0","method":"addnode","params":["<ip>:<port>","add"]}' \
     http://localhost:18332

# Remove node
curl --user dilithion:password \
     --data-binary '{"jsonrpc":"2.0","method":"addnode","params":["<ip>:<port>","remove"]}' \
     http://localhost:18332

# Get connection count
curl --user dilithion:password \
     --data-binary '{"jsonrpc":"2.0","method":"getconnectioncount","params":[]}' \
     http://localhost:18332

# Get peer info (when implemented)
curl --user dilithion:password \
     --data-binary '{"jsonrpc":"2.0","method":"getpeerinfo","params":[]}' \
     http://localhost:18332
```

---

## Support

**Questions?** Join the Dilithion community:
- GitHub Issues: https://github.com/dilithion/dilithion/issues
- Discord: (to be announced)
- Forum: (to be announced)

**Reporting Problems:**
- Include node version
- Include connection logs
- Include `getconnectioncount` output
- Include firewall configuration

---

## Appendix: Example Testnet Setup

### 3-Node Testnet Example

**Node 1 (Coordinator):**
```bash
# Start first, begin mining
./dilithion-node --rpcport=18332 --p2pport=8333
# (Share your IP: 192.168.1.10)
```

**Node 2:**
```bash
./dilithion-node --rpcport=18332 --p2pport=8333 --addnode=192.168.1.10:8333
```

**Node 3:**
```bash
./dilithion-node --rpcport=18332 --p2pport=8333 --addnode=192.168.1.10:8333
```

**Result:**
- All nodes connect to coordinator
- Blocks propagate from Node 1 → Node 2 & Node 3
- Transactions relay between all nodes

---

**Document Version**: 1.0
**Last Updated**: October 28, 2025
**Next Update**: When DNS seeds implemented
