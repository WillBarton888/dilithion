@echo off
echo ========================================
echo IBD Test - Second Node (Fresh Sync)
echo ========================================
echo.
echo This node starts with NO blocks
echo It should sync blocks 1-2 from first node via IBD
echo.
echo Data directory: C:\Users\will\.dilithion-testnet-node2
echo.
echo Make sure first node is running with 2 blocks!
echo.
echo Press Ctrl+C after you see block height reach 2
echo.
dilithion-node.exe --testnet --datadir="C:\Users\will\.dilithion-testnet-node2" --port=18445 --rpcport=18333
