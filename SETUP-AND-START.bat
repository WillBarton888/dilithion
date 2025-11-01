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

REM ========================================
REM SECURITY: Validate input to prevent command injection
REM ========================================
if "%threads%"=="" (
    set threads=auto
    set threads_display=Auto-Detect
    goto input_valid
)

REM Check if input is "auto" (case-insensitive)
echo %threads% | findstr /i /x "auto" >nul
if %errorlevel% equ 0 (
    set threads=auto
    set threads_display=Auto-Detect
    goto input_valid
)

REM Validate numeric input (1-128 cores)
set "valid=0"
for /L %%i in (1,1,128) do (
    if "%threads%"=="%%i" set "valid=1"
)

if "%valid%"=="0" (
    cls
    echo.
    echo  ========================================================
    echo    ERROR: Invalid Input
    echo  ========================================================
    echo.
    echo  Please enter either:
    echo    - A number between 1 and 128
    echo    - "auto" for automatic detection
    echo    - Press ENTER for automatic detection
    echo.
    echo  Your input "%threads%" is not valid.
    echo.
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

set threads_display=%threads% cores

:input_valid

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

REM =======================================================
REM SECURITY: Check if binary exists before execution
REM =======================================================
if not exist "dilithion-node.exe" (
    cls
    color 0C
    echo.
    echo  ========================================================
    echo    ERROR: dilithion-node.exe not found
    echo  ========================================================
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
    echo  ========================================================
    echo.
    pause
    exit /b 1
)

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
