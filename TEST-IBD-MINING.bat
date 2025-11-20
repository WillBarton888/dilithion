@echo off
echo ========================================
echo IBD Test - Mine 2 blocks locally
echo ========================================
echo.
echo Starting node with mining...
echo Press Ctrl+C when you see "Block count: 2" or higher
echo.
dilithion-node.exe --testnet --mine --threads=auto
