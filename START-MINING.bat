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

REM =======================================================
REM SECURITY: Check if binary exists before execution
REM =======================================================
if not exist "dilithion-node.exe" (
    color 0C
    echo.
    echo  ================================================
    echo    ERROR: dilithion-node.exe not found
    echo  ================================================
    echo.
    echo  The dilithion-node.exe binary is missing!
    echo.
    echo  Please ensure you:
    echo    1. Extracted the COMPLETE zip file
    echo    2. Are running this script from the dilithion folder
    echo    3. Downloaded the Windows release package
    echo.
    echo  Current directory: %CD%
    echo.
    echo  For support: https://discord.gg/dilithion
    echo  ================================================
    echo.
    pause
    exit /b 1
)

dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=auto

REM If node exits, show error
echo.
echo  ================================================
echo    Mining stopped
echo  ================================================
echo.
pause
