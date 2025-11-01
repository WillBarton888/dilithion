@echo off
REM =======================================================
REM  DILITHION TESTNET - ONE-CLICK MINING
REM =======================================================
REM  This script starts mining Dilithion testnet instantly
REM  No configuration needed - just double-click!
REM =======================================================

cls
color 0A
echo.
echo  ================================================
echo    DILITHION TESTNET - QUICK START MINER
echo  ================================================
echo.
echo  Starting Dilithion testnet mining...
echo  - Network: TESTNET (coins have NO value)
echo  - Seed Node: 170.64.203.134:18444
echo  - Mining: ENABLED (auto-detecting CPU threads)
echo.
echo  Mining will start in 3 seconds...
echo  Press Ctrl+C to stop mining anytime.
echo.
timeout /t 3 /nobreak >nul

echo  Starting node...
echo.

dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=auto

REM If node exits, show error
echo.
echo  ================================================
echo    Mining stopped
echo  ================================================
echo.
pause
