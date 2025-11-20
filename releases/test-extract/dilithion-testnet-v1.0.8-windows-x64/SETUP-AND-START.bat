@echo off
REM =======================================================
REM  DILITHION TESTNET - SETUP WIZARD v1.0.6
REM =======================================================

color 0B
cls
echo.
echo  ========================================================
echo    DILITHION TESTNET - FIRST TIME SETUP WIZARD
echo  ========================================================
echo.
echo  Welcome to Dilithion - Post-Quantum Cryptocurrency!
echo.
echo  This wizard will help you get started mining testnet DIL.
echo  Testnet coins have NO monetary value (for testing only).
echo.
echo  ========================================================
echo.
pause

cls
echo.
echo  ========================================================
echo    STEP 1: CONFIGURE MINING
echo  ========================================================
echo.
echo  How many CPU cores would you like to use for mining?
echo.
echo  Recommendations:
echo    - Leave BLANK for AUTO (recommended for beginners)
echo    - Enter 1-2 for light mining (laptop/low power)
echo    - Enter 4+ for dedicated mining (desktop)
echo.
set /p threads="Enter number of CPU cores (or press ENTER for auto): "

if "%threads%"=="" (
    set threads=auto
    set threads_display=Auto-Detect
) else (
    set threads_display=%threads% cores
)

cls
echo.
echo  ========================================================
echo    CONFIGURATION SUMMARY
echo  ========================================================
echo.
echo    - CPU Threads: %threads_display%
echo    - Network: Testnet
echo    - Seed Node: 170.64.203.134:18444
echo.
echo  ========================================================
echo.
echo  Ready to start mining!
echo.
pause

cls
echo.
echo  ========================================================
echo    DILITHION TESTNET MINER - STARTING
echo  ========================================================
echo.
echo  Initializing...
echo.

REM Create data directory
if not exist ".dilithion-testnet" mkdir ".dilithion-testnet"
if not exist ".dilithion-testnet\blocks" mkdir ".dilithion-testnet\blocks"

timeout /t 2 /nobreak >nul

echo  ========================================================
echo    Launching Dilithion Node
echo  ========================================================
echo.
echo  EXPECT 2 WINDOWS FIREWALL PROMPTS:
echo    1. Port 18444 (P2P networking) - Click "Allow access"
echo    2. Port 18332 (RPC server) - Click "Allow access"
echo.
echo  Press Ctrl+C anytime to stop mining.
echo.
echo  ========================================================
echo.

REM Launch the node
if "%threads%"=="auto" (
    dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=auto
) else (
    dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=%threads%
)

set NODE_EXIT_CODE=%errorlevel%

echo.
echo  ========================================================
echo    Mining Stopped
echo  ========================================================
echo.

if %NODE_EXIT_CODE% neq 0 (
    echo  Node exited with error code: %NODE_EXIT_CODE%
    echo.
    echo  To start mining again, run this wizard or START-MINING.bat
) else (
    echo  To start mining again:
    echo    - Double-click START-MINING.bat for quick start
    echo    - Or run this wizard again
)

echo.
pause
