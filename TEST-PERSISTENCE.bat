@echo off
echo ========================================
echo Persistence Test
echo ========================================
echo.
echo Step 1: Mine exactly 1 block
echo Step 2: Will auto-stop after block found
echo.
timeout /t 3
dilithion-node.exe --testnet --mine --threads=auto
