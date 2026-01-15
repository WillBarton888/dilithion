@echo off
REM =======================================================
REM  DILITHION MAINNET - ONE-CLICK MINING
REM =======================================================
REM  v1.4.0 - MAINNET LAUNCH
REM =======================================================

cls
color 0A
echo.
echo  ================================================
echo    DILITHION MAINNET - QUICK START MINER
echo  ================================================
echo.
echo  Starting Dilithion mainnet mining...
echo  - Network: MAINNET (real DIL!)
echo  - Seed Nodes: NYC, London, Singapore, Sydney (auto-connect)
echo  - Mining: ENABLED (auto-detecting CPU threads)
echo.
echo  Mining will start in 3 seconds...
echo  Press Ctrl+C to stop mining anytime.
echo.
timeout /t 3 /nobreak >nul

echo  Starting node...
echo.

REM File check removed (causes false positives on some Windows systems)
dilithion-node.exe --mine --threads=auto

REM If node exits, show message
echo.
echo  ================================================
echo    Mining stopped
echo  ================================================
echo.
pause
