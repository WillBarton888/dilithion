# BUG #74: RPC sendtoaddress Hangs Indefinitely

## Problem
Calling `sendtoaddress` RPC causes all RPC threads to hang, making the entire RPC interface unresponsive.

## Symptoms
1. Simple RPC methods (getblockcount, getbalance) work initially
2. Calling sendtoaddress blocks and never returns (60s+ timeout)
3. After sendtoaddress timeout, ALL RPC methods become unresponsive
4. TCP connections stuck in CLOSE_WAIT / FIN_WAIT_2 states
5. Requires node restart to recover

## Environment
- Windows 10 x64
- Node version: v1.0.16
- Both with mining (8/20 threads) and without mining

## Steps to Reproduce
```bash
# Start node without mining
dilithion-node.exe --testnet

# Simple RPC works
curl -X POST -H "Content-Type: application/json" -H "X-Dilithion-RPC: 1" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
  http://127.0.0.1:18332/
# Returns: {"jsonrpc":"2.0","result":105,"id":1}

# This hangs forever:
curl -X POST -H "Content-Type: application/json" -H "X-Dilithion-RPC: 1" \
  -d '{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":{"address":"DMGhMdoZsK2aaB7ysW6EH5SxrSQLTYaQDi","amount":10}}' \
  http://127.0.0.1:18332/
# Never returns, RPC is now dead
```

## Analysis
The issue is likely in `RPC_SendToAddress` at [src/rpc/server.cpp:1261](src/rpc/server.cpp#L1261).

Possible causes:
1. Deadlock in wallet mutex during UTXO selection
2. Deadlock in UTXO set lock
3. Dilithium signature generation blocking forever
4. Missing timeout on signing operation

## Note
This is first-time wallet transaction testing. Remote Linux nodes have working RPC, suggesting this may be Windows-specific or related to the local test environment.

## Related Files
- src/rpc/server.cpp - RPC_SendToAddress implementation
- src/wallet/wallet.cpp - CreateTransaction, SignTransaction
- src/wallet/wallet.h - Wallet locks and mutexes
