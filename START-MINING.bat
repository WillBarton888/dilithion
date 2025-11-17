@echo off
REM =======================================================
REM  DILITHION TESTNET - ONE-CLICK MINING
REM =======================================================
REM  Based on v1.0.6 - SIMPLIFIED VERSION THAT WORKED
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
echo  - Seed Nodes: NYC, Singapore, London (auto-connect)
echo  - Mining: ENABLED (auto-detecting CPU threads)
echo.
echo  Mining will start in 3 seconds...
echo  Press Ctrl+C to stop mining anytime.
echo.
timeout /t 3 /nobreak >nul

echo  Starting node...
echo.

REM File check removed (causes false positives on some Windows systems)
dilithion-node.exe --testnet --mine --threads=auto

REM If node exits, show message
echo.
echo  ================================================
echo    Mining stopped
echo  ================================================
echo.
pause
