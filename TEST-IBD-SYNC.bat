@echo off
echo ========================================
echo IBD Test - Sync 2 blocks from NYC
echo ========================================
echo.
echo Starting node WITHOUT mining...
echo Should sync blocks 1-2 from NYC via IBD
echo Watch for [IBD] and [HEADERS] messages
echo.
echo Press Ctrl+C after you see block height reach 2
echo.
dilithion-node.exe --testnet
