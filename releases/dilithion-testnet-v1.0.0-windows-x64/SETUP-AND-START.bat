@echo off
REM =======================================================
REM  DILITHION TESTNET - INTERACTIVE SETUP WIZARD
REM =======================================================
REM  First-time setup guide for crypto beginners
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
echo    - Enter 4-8 for medium mining (desktop)
echo    - Enter 8+ for maximum mining (powerful PC)
echo.
echo  Your CPU will be auto-detected if you leave this blank.
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
echo    STEP 2: REVIEW CONFIGURATION
echo  ========================================================
echo.
echo  Your Settings:
echo    - Network:     TESTNET
echo    - Seed Node:   170.64.203.134:18444 (official)
echo    - Mining:      ENABLED
echo    - CPU Threads: %threads_display%
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
echo  Connecting to seed node...
echo  Initializing mining with %threads_display%...
echo.
echo  The node will start shortly.
echo  Press Ctrl+C anytime to stop mining.
echo.
echo  ========================================================
echo.
timeout /t 2 /nobreak >nul

dilithion-node.exe --testnet --addnode=170.64.203.134:18444 --mine --threads=%threads%

echo.
echo  ========================================================
echo    Mining Stopped
echo  ========================================================
echo.
echo  To start mining again:
echo    - Double-click START-MINING.bat for quick start
echo    - Or run this wizard again
echo.
pause
