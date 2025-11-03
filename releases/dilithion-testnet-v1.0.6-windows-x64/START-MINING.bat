@echo off
REM =======================================================
REM  DILITHION TESTNET - QUICK START MINING v1.0.6
REM =======================================================

color 0B
cls
echo.
echo  ========================================================
echo    DILITHION TESTNET - QUICK START MINING
echo  ========================================================
echo.
echo  Starting Dilithion node with auto-detected CPU cores...
echo.
echo  EXPECT 2 WINDOWS FIREWALL PROMPTS:
echo    1. Port 18444 (P2P networking) - Click "Allow access"
echo    2. Port 18332 (RPC server) - Click "Allow access"
echo.
echo  Press Ctrl+C anytime to stop mining.
echo.
echo  ========================================================
echo.

REM Create data directory if needed
if not exist ".dilithion-testnet" mkdir ".dilithion-testnet"
if not exist ".dilithion-testnet\blocks" mkdir ".dilithion-testnet\blocks"

timeout /t 2 /nobreak >nul

REM Launch node with auto-detected threads
dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=auto

set NODE_EXIT_CODE=%errorlevel%

echo.
echo  ========================================================
echo    Mining Stopped
echo  ========================================================
echo.

if %NODE_EXIT_CODE% neq 0 (
    echo  Node exited with error code: %NODE_EXIT_CODE%
    echo.
) else (
    echo  Mining session ended normally.
    echo.
)

echo  To start mining again, run this script or SETUP-AND-START.bat
echo.
pause
